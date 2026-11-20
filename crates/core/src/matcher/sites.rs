use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::matcher::MatchError;

const APPLE_PASSWORD_RULES: &str = include_str!("../../../../data/sites/apple/password-rules.json");
const APPLE_SHARED_CREDENTIALS: &str =
    include_str!("../../../../data/sites/apple/shared-credentials.json");
const APPLE_CHANGE_PASSWORD_URLS: &str =
    include_str!("../../../../data/sites/apple/change-password-URLs.json");
const APPLE_APPENDS_2FA: &str =
    include_str!("../../../../data/sites/apple/websites-that-append-2fa-to-password.json");

const HASP_SITE_FILES: [&str; 6] = [
    include_str!("../../../../data/sites/hasp/naver.json"),
    include_str!("../../../../data/sites/hasp/kakao.json"),
    include_str!("../../../../data/sites/hasp/coupang.json"),
    include_str!("../../../../data/sites/hasp/kr-banks.json"),
    include_str!("../../../../data/sites/hasp/kr-brokers.json"),
    include_str!("../../../../data/sites/hasp/kr-public.json"),
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteFile {
    pub version: u32,
    pub entries: Vec<SiteEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteEntry {
    #[serde(rename = "match")]
    pub matcher: SiteMatch,
    #[serde(default)]
    pub flow: Option<Flow>,
    #[serde(default)]
    pub password_rules: Option<String>,
    #[serde(default)]
    pub change_password_url: Option<String>,
    #[serde(default)]
    pub quirks: Quirks,
    #[serde(default)]
    pub related: Vec<String>,
    #[serde(default)]
    pub sources: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteMatch {
    pub domain: String,
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flow {
    pub pages: Vec<FlowPage>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowPage {
    pub path: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub otp: Option<String>,
    #[serde(default)]
    pub advance: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "quirk flags are the sites dataset format"
)]
pub struct Quirks {
    #[serde(default)]
    pub append_2fa: bool,
    #[serde(default)]
    pub no_autosubmit: bool,
    #[serde(default)]
    pub per_char_events: bool,
    #[serde(default)]
    pub skip_save: bool,
    #[serde(default)]
    pub iframe_login: bool,
    #[serde(default)]
    pub blocks_autofill: bool,
}

#[derive(Debug, Deserialize)]
struct AppleRule {
    #[serde(rename = "password-rules")]
    password_rules: String,
}

#[derive(Debug, Deserialize)]
struct AppleShared {
    #[serde(default)]
    shared: Vec<String>,
    #[serde(default)]
    from: Vec<String>,
    #[serde(default)]
    to: Vec<String>,
}

#[derive(Debug)]
struct RelatedGroup {
    from: BTreeSet<String>,
    to: BTreeSet<String>,
}

#[derive(Debug)]
pub struct SiteRules {
    entries: Vec<SiteEntry>,
    apple_rules: BTreeMap<String, String>,
    apple_change_urls: BTreeMap<String, String>,
    apple_append_2fa: BTreeSet<String>,
    groups: Vec<RelatedGroup>,
    from_index: BTreeMap<String, Vec<usize>>,
}

impl SiteRules {
    pub fn bundled() -> Result<Self, MatchError> {
        let files = HASP_SITE_FILES
            .iter()
            .map(|text| serde_json::from_str(text))
            .collect::<Result<Vec<SiteFile>, _>>()
            .map_err(|_| MatchError::Dataset("hasp site file"))?;
        Self::from_sources(
            files,
            APPLE_PASSWORD_RULES,
            APPLE_SHARED_CREDENTIALS,
            APPLE_CHANGE_PASSWORD_URLS,
            APPLE_APPENDS_2FA,
        )
    }

    pub fn from_sources(
        files: Vec<SiteFile>,
        apple_rules: &str,
        apple_shared: &str,
        apple_change_urls: &str,
        apple_append_2fa: &str,
    ) -> Result<Self, MatchError> {
        let rules: BTreeMap<String, AppleRule> = serde_json::from_str(apple_rules)
            .map_err(|_| MatchError::Dataset("apple password-rules"))?;
        let shared: Vec<AppleShared> = serde_json::from_str(apple_shared)
            .map_err(|_| MatchError::Dataset("apple shared-credentials"))?;
        let change_urls: BTreeMap<String, String> = serde_json::from_str(apple_change_urls)
            .map_err(|_| MatchError::Dataset("apple change-password-URLs"))?;
        let append: Vec<String> = serde_json::from_str(apple_append_2fa)
            .map_err(|_| MatchError::Dataset("apple append-2fa"))?;
        let mut groups = Vec::new();
        for group in shared {
            let members: BTreeSet<String> = group.shared.into_iter().collect();
            if !members.is_empty() {
                groups.push(RelatedGroup {
                    from: members.clone(),
                    to: members,
                });
            }
            if !group.from.is_empty() && !group.to.is_empty() {
                groups.push(RelatedGroup {
                    from: group.from.into_iter().collect(),
                    to: group.to.into_iter().collect(),
                });
            }
        }
        let mut entries = Vec::new();
        for file in files {
            if file.version != 1 {
                return Err(MatchError::Dataset("unsupported sites version"));
            }
            for entry in file.entries {
                if !entry.related.is_empty() {
                    let mut members: BTreeSet<String> = entry.related.iter().cloned().collect();
                    members.insert(entry.matcher.domain.clone());
                    groups.push(RelatedGroup {
                        from: members.clone(),
                        to: members,
                    });
                }
                entries.push(entry);
            }
        }
        let mut from_index: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, group) in groups.iter().enumerate() {
            for member in &group.from {
                from_index.entry(member.clone()).or_default().push(index);
            }
        }
        Ok(Self {
            entries,
            apple_rules: rules
                .into_iter()
                .map(|(k, v)| (k, v.password_rules))
                .collect(),
            apple_change_urls: change_urls,
            apple_append_2fa: append.into_iter().collect(),
            groups,
            from_index,
        })
    }

    pub fn entries(&self) -> &[SiteEntry] {
        &self.entries
    }

    pub fn is_related(&self, item_host: &str, page_host: &str) -> bool {
        parents(item_host).any(|candidate| {
            self.from_index.get(candidate).is_some_and(|ids| {
                ids.iter().any(|&id| {
                    self.groups
                        .get(id)
                        .is_some_and(|g| parents(page_host).any(|p| g.to.contains(p)))
                })
            })
        })
    }

    pub fn password_rules(&self, host: &str) -> Option<&str> {
        self.entry_for(host, "", |e| e.password_rules.as_deref())
            .or_else(|| {
                parents(host)
                    .find_map(|candidate| self.apple_rules.get(candidate).map(String::as_str))
            })
    }

    pub fn change_password_url(&self, host: &str) -> Option<&str> {
        self.entry_for(host, "", |e| e.change_password_url.as_deref())
            .or_else(|| {
                parents(host)
                    .find_map(|candidate| self.apple_change_urls.get(candidate).map(String::as_str))
            })
    }

    pub fn quirks(&self, host: &str, path: &str) -> Quirks {
        let mut quirks = self
            .best_entry(host, path)
            .map(|e| Quirks { ..e.quirks })
            .unwrap_or_default();
        if parents(host).any(|candidate| self.apple_append_2fa.contains(candidate)) {
            quirks.append_2fa = true;
        }
        quirks
    }

    pub fn flow(&self, host: &str, path: &str) -> Option<&Flow> {
        self.best_entry(host, path).and_then(|e| e.flow.as_ref())
    }

    fn entry_for<'a, T>(
        &'a self,
        host: &str,
        path: &str,
        pick: impl Fn(&'a SiteEntry) -> Option<T>,
    ) -> Option<T> {
        self.best_entry(host, path).and_then(pick)
    }

    fn best_entry(&self, host: &str, path: &str) -> Option<&SiteEntry> {
        self.entries
            .iter()
            .filter(|e| {
                parents(host).any(|p| p == e.matcher.domain)
                    && (e.matcher.paths.is_empty()
                        || e.matcher
                            .paths
                            .iter()
                            .any(|prefix| path.starts_with(prefix.as_str())))
            })
            .max_by_key(|e| (e.matcher.domain.len(), e.matcher.paths.len()))
    }
}

fn parents(host: &str) -> impl Iterator<Item = &str> {
    let mut rest = Some(host);
    std::iter::from_fn(move || {
        let current = rest?;
        rest = current.split_once('.').map(|(_, tail)| tail);
        Some(current)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> SiteRules {
        SiteRules::bundled().unwrap()
    }

    #[test]
    fn parents_walk_to_the_last_label() {
        let chain: Vec<&str> = parents("a.b.example.com").collect();
        assert_eq!(
            chain,
            ["a.b.example.com", "b.example.com", "example.com", "com"]
        );
    }

    #[test]
    fn apple_shared_groups_are_symmetric() {
        let rules = rules();
        assert!(rules.is_related("envato.com", "themeforest.net"));
        assert!(rules.is_related("themeforest.net", "market.envato.com"));
        assert!(!rules.is_related("envato.com", "example.com"));
    }

    #[test]
    fn apple_directed_groups_are_one_way() {
        let rules = rules();
        assert!(rules.is_related("a2hosting.com", "hosting.com"));
        assert!(!rules.is_related("hosting.com", "a2hosting.com"));
    }

    #[test]
    fn korean_related_groups_come_from_sites_files() {
        let rules = rules();
        assert!(rules.is_related("kakao.com", "daum.net"));
        assert!(rules.is_related("daum.net", "accounts.kakao.com"));
    }

    #[test]
    fn password_rules_prefer_our_entries_then_apple() {
        let rules = rules();
        assert_eq!(
            rules.password_rules("login.coupang.com"),
            rules.password_rules("coupang.com")
        );
        assert!(rules.password_rules("www.1800flowers.com").is_some());
        assert!(rules.password_rules("example.invalid").is_none());
    }

    #[test]
    fn change_password_url_resolves_by_parent_domain() {
        let rules = rules();
        assert_eq!(
            rules.change_password_url("nid.naver.com"),
            Some("https://nid.naver.com/user2/help/myInfo.nhn?m=viewChangePasswd")
        );
    }

    #[test]
    fn append_2fa_quirk_comes_from_apple_list() {
        let rules = rules();
        assert!(rules.quirks("www.etrade.com", "/").append_2fa);
        assert!(!rules.quirks("example.com", "/").append_2fa);
    }

    #[test]
    fn every_hasp_sites_file_is_bundled() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/sites/hasp");
        let on_disk = std::fs::read_dir(dir).unwrap().count();
        assert_eq!(on_disk, HASP_SITE_FILES.len());
    }

    #[test]
    fn hasp_entries_are_well_formed() {
        let psl = crate::matcher::psl::PublicSuffixList::bundled();
        let rules = rules();
        assert!(!rules.entries().is_empty());
        for entry in rules.entries() {
            let domain = entry.matcher.domain.as_str();
            assert_eq!(psl.registrable_domain(domain), Some(domain), "{domain}");
            for related in &entry.related {
                assert_eq!(
                    psl.registrable_domain(related),
                    Some(related.as_str()),
                    "{related}"
                );
            }
            if let Some(text) = &entry.password_rules {
                assert!(
                    crate::generator::rules::PasswordRules::parse_strict(text).is_ok(),
                    "{domain}"
                );
            }
            if let Some(url) = &entry.change_password_url {
                assert!(url.starts_with("https://"), "{domain}");
            }
            assert!(
                entry.matcher.paths.iter().all(|p| p.starts_with('/')),
                "{domain}"
            );
        }
    }

    #[test]
    fn rejects_unknown_fields_and_versions() {
        let bad = r#"{"version":1,"entries":[{"match":{"domain":"a.com"},"surprise":1}]}"#;
        assert!(serde_json::from_str::<SiteFile>(bad).is_err());
        let file = SiteFile {
            version: 2,
            entries: Vec::new(),
        };
        let err = SiteRules::from_sources(vec![file], "{}", "[]", "{}", "[]");
        assert!(err.is_err());
    }
}
