use std::collections::BTreeSet;

use url::Url;

const BUNDLED: &str = include_str!("../../../../data/sites/psl/public_suffix_list.dat");

#[derive(Debug)]
pub struct PublicSuffixList {
    exact: BTreeSet<String>,
    wildcard: BTreeSet<String>,
    exception: BTreeSet<String>,
}

impl PublicSuffixList {
    pub fn bundled() -> Self {
        Self::parse(BUNDLED)
    }

    pub fn parse(text: &str) -> Self {
        let mut list = Self {
            exact: BTreeSet::new(),
            wildcard: BTreeSet::new(),
            exception: BTreeSet::new(),
        };
        for line in text.lines() {
            let rule = line.split_whitespace().next().unwrap_or("");
            if rule.is_empty() || rule.starts_with("//") {
                continue;
            }
            if let Some(rest) = rule.strip_prefix('!') {
                list.exception.extend(ascii_rule(rest));
            } else if let Some(rest) = rule.strip_prefix("*.") {
                list.wildcard.extend(ascii_rule(rest));
            } else {
                list.exact.extend(ascii_rule(rule));
            }
        }
        list
    }

    pub fn public_suffix<'a>(&self, host: &'a str) -> Option<&'a str> {
        let labels = labels(host)?;
        let count = self.suffix_label_count(&labels);
        let skip = labels.len().checked_sub(count)?;
        let start: usize = labels.iter().take(skip).map(|l| l.len() + 1).sum();
        host.get(start..)
    }

    pub fn registrable_domain<'a>(&self, host: &'a str) -> Option<&'a str> {
        let labels = labels(host)?;
        let count = self.suffix_label_count(&labels);
        let skip = labels.len().checked_sub(count.checked_add(1)?)?;
        let start: usize = labels.iter().take(skip).map(|l| l.len() + 1).sum();
        host.get(start..)
    }

    fn suffix_label_count(&self, labels: &[&str]) -> usize {
        let total = labels.len();
        let mut best = 1;
        for start in 0..total {
            let candidate = labels.get(start..).map(|l| l.join(".")).unwrap_or_default();
            if self.exception.contains(&candidate) {
                return total - start - 1;
            }
            let parent_is_wildcard = labels
                .get(start + 1..)
                .filter(|rest| !rest.is_empty())
                .is_some_and(|rest| self.wildcard.contains(&rest.join(".")));
            if self.exact.contains(&candidate) || parent_is_wildcard {
                best = best.max(total - start);
            }
        }
        best
    }
}

fn labels(host: &str) -> Option<Vec<&str>> {
    if host.is_empty() || host.starts_with('.') || host.ends_with('.') {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    labels.iter().all(|l| !l.is_empty()).then_some(labels)
}

fn ascii_rule(rule: &str) -> Option<String> {
    let lowered = rule.to_lowercase();
    if lowered.is_ascii() {
        return Some(lowered);
    }
    let url = Url::parse(&format!("https://{lowered}/")).ok()?;
    url.host_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list() -> PublicSuffixList {
        PublicSuffixList::bundled()
    }

    #[test]
    fn registrable_domain_table() {
        let cases = [
            ("example.com", Some("example.com")),
            ("www.example.com", Some("example.com")),
            ("a.b.c.example.com", Some("example.com")),
            ("www.naver.co.kr", Some("naver.co.kr")),
            ("naver.co.kr", Some("naver.co.kr")),
            ("co.kr", None),
            ("kr", None),
            ("com", None),
            ("www.bbc.co.uk", Some("bbc.co.uk")),
            ("user.github.io", Some("user.github.io")),
            ("a.user.github.io", Some("user.github.io")),
            ("github.io", None),
            ("www.ck", Some("www.ck")),
            ("foo.ck", None),
            ("bar.foo.ck", Some("bar.foo.ck")),
            ("www.city.kawasaki.jp", Some("city.kawasaki.jp")),
            ("localhost", None),
            ("foo.unknowntld", Some("foo.unknowntld")),
            ("xn--fiqs8s", None),
            ("shop.xn--fiqs8s", Some("shop.xn--fiqs8s")),
            ("", None),
            ("a..b", None),
            (".com", None),
        ];
        for (host, expected) in cases {
            assert_eq!(list().registrable_domain(host), expected, "{host}");
        }
    }

    #[test]
    fn public_suffix_table() {
        let cases = [
            ("www.naver.co.kr", Some("co.kr")),
            ("example.com", Some("com")),
            ("user.github.io", Some("github.io")),
            ("foo.unknowntld", Some("unknowntld")),
            ("co.kr", Some("co.kr")),
        ];
        for (host, expected) in cases {
            assert_eq!(list().public_suffix(host), expected, "{host}");
        }
    }

    #[test]
    fn parses_rule_kinds_from_text() {
        let psl = PublicSuffixList::parse("// c\ncom\n*.ck\n!www.ck\nco.uk\n");
        assert_eq!(psl.registrable_domain("x.y.ck"), Some("x.y.ck"));
        assert_eq!(psl.registrable_domain("a.www.ck"), Some("www.ck"));
        assert_eq!(psl.registrable_domain("a.b.co.uk"), Some("b.co.uk"));
    }
}
