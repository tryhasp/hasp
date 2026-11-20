use crate::matcher::MatchError;
use crate::matcher::origin::{Origin, Refusal};
use crate::matcher::psl::PublicSuffixList;
use crate::matcher::sites::SiteRules;
use crate::model::url::{MatchMode, UrlEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchLevel {
    None,
    Related,
    Domain,
    Exact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fill {
    Never,
    ConfirmFirst,
    OneClick,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    pub level: MatchLevel,
    pub fill: Fill,
    pub refusal: Option<Refusal>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ranked<K> {
    pub key: K,
    pub result: Match,
}

#[derive(Debug)]
pub struct Matcher {
    psl: PublicSuffixList,
    sites: SiteRules,
}

impl Match {
    const NONE: Self = Self {
        level: MatchLevel::None,
        fill: Fill::Never,
        refusal: None,
    };

    fn refused(refusal: Refusal) -> Self {
        Self {
            level: MatchLevel::None,
            fill: Fill::Never,
            refusal: Some(refusal),
        }
    }
}

impl Matcher {
    pub fn new(psl: PublicSuffixList, sites: SiteRules) -> Self {
        Self { psl, sites }
    }

    pub fn bundled() -> Result<Self, MatchError> {
        Ok(Self::new(
            PublicSuffixList::bundled(),
            SiteRules::bundled()?,
        ))
    }

    pub fn sites(&self) -> &SiteRules {
        &self.sites
    }

    pub fn psl(&self) -> &PublicSuffixList {
        &self.psl
    }

    pub fn rank_page(&self, page_url: &str, entries: &[UrlEntry]) -> Match {
        match Origin::parse(page_url) {
            Ok(page) => self.rank(&page, entries),
            Err(_) => Match::refused(Refusal::UnsupportedScheme),
        }
    }

    pub fn rank(&self, page: &Origin, entries: &[UrlEntry]) -> Match {
        if let Err(refusal) = page.check_fillable() {
            return Match::refused(refusal);
        }
        entries
            .iter()
            .map(|entry| self.rank_entry(page, entry))
            .max_by_key(|m| (m.level, m.fill))
            .unwrap_or(Match::NONE)
    }

    pub fn rank_items<K: Clone>(
        &self,
        page: &Origin,
        items: &[(K, Vec<UrlEntry>)],
    ) -> Vec<Ranked<K>> {
        let mut ranked: Vec<Ranked<K>> = items
            .iter()
            .map(|(key, entries)| Ranked {
                key: key.clone(),
                result: self.rank(page, entries),
            })
            .filter(|r| r.result.level != MatchLevel::None)
            .collect();
        ranked.sort_by_key(|r| std::cmp::Reverse((r.result.level, r.result.fill)));
        ranked
    }

    fn rank_entry(&self, page: &Origin, entry: &UrlEntry) -> Match {
        if entry.mode() == MatchMode::Never {
            return Match::NONE;
        }
        let Ok(item) = Origin::parse(entry.url()) else {
            return Match::NONE;
        };
        if page.same_host_and_port(&item) {
            return Match {
                level: MatchLevel::Exact,
                fill: Fill::OneClick,
                refusal: None,
            };
        }
        if entry.mode() == MatchMode::Host {
            return Match::NONE;
        }
        let (Some(page_host), Some(item_host)) = (page.domain(), item.domain()) else {
            return Match::NONE;
        };
        if page_host == item_host {
            return Match::NONE;
        }
        let confirmed = entry.confirmed_hosts().iter().any(|h| h == page_host);
        let fill = if confirmed {
            Fill::OneClick
        } else {
            Fill::ConfirmFirst
        };
        if self.same_registrable_domain(page_host, item_host) {
            return Match {
                level: MatchLevel::Domain,
                fill,
                refusal: None,
            };
        }
        if confirmed || self.sites.is_related(item_host, page_host) {
            return Match {
                level: MatchLevel::Related,
                fill,
                refusal: None,
            };
        }
        Match::NONE
    }

    fn same_registrable_domain(&self, a: &str, b: &str) -> bool {
        match (
            self.psl.registrable_domain(a),
            self.psl.registrable_domain(b),
        ) {
            (Some(x), Some(y)) => x == y,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests;
