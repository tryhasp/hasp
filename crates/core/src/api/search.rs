use super::{ItemRow, ItemStatus, SearchQuery};
use crate::matcher::origin::Origin;
use crate::matcher::policy::{MatchLevel, Matcher};
use crate::model::url::{MatchMode, UrlEntry};

const FAVOURITE_BONUS: u32 = 5;
const BOOST_EXACT: u32 = 200;
const BOOST_DOMAIN: u32 = 100;
const BOOST_RELATED: u32 = 60;

enum Filter {
    Favourite,
    Untagged,
    Passkey,
    Expiring,
    Archived,
    Tag(String),
    Category(String),
    Vault(String),
}

struct Parsed {
    terms: Vec<String>,
    filters: Vec<Filter>,
}

fn parse(text: &str) -> Parsed {
    let mut terms = Vec::new();
    let mut filters = Vec::new();
    let mut quoted = String::new();
    let mut in_quote = false;
    for raw in text.split_whitespace() {
        if in_quote {
            quoted.push(' ');
            quoted.push_str(raw);
            if raw.ends_with('"') {
                quoted.pop();
                terms.push(quoted.to_lowercase());
                quoted.clear();
                in_quote = false;
            }
            continue;
        }
        if let Some(rest) = raw.strip_prefix('"') {
            if rest.len() > 1 && rest.ends_with('"') {
                terms.push(rest[..rest.len() - 1].to_lowercase());
            } else {
                rest.clone_into(&mut quoted);
                in_quote = true;
            }
            continue;
        }
        match raw.strip_prefix('=') {
            Some("favorite" | "favourite") => filters.push(Filter::Favourite),
            Some("untagged") => filters.push(Filter::Untagged),
            Some("passkey") => filters.push(Filter::Passkey),
            Some("expiring") => filters.push(Filter::Expiring),
            Some("archived") => filters.push(Filter::Archived),
            Some(rest) => {
                if let Some(v) = rest.strip_prefix("tag:") {
                    filters.push(Filter::Tag(v.to_lowercase()));
                } else if let Some(v) = rest.strip_prefix("category:") {
                    filters.push(Filter::Category(v.to_lowercase()));
                } else if let Some(v) = rest.strip_prefix("vault:") {
                    filters.push(Filter::Vault(v.to_lowercase()));
                } else {
                    terms.push(raw.to_lowercase());
                }
            }
            None => terms.push(raw.to_lowercase()),
        }
    }
    if in_quote && !quoted.is_empty() {
        terms.push(quoted.to_lowercase());
    }
    Parsed { terms, filters }
}

fn subsequence(needle: &str, hay: &str) -> bool {
    let mut hay = hay.chars();
    needle.chars().all(|c| hay.any(|h| h == c))
}

fn term_score(term: &str, row: &ItemRow) -> Option<u32> {
    let title = row.title.to_lowercase();
    let subtitle = row.subtitle.to_lowercase();
    let mut best = None::<u32>;
    let mut take = |score: u32| best = Some(best.map_or(score, |b| b.max(score)));
    if title.starts_with(term) {
        take(100);
    } else if title
        .split(|c: char| !c.is_alphanumeric())
        .any(|w| w.starts_with(term))
    {
        take(80);
    } else if title.contains(term) {
        take(60);
    } else if subsequence(term, &title) {
        take(20);
    }
    if subtitle.contains(term) {
        take(40);
    }
    if row.hosts.iter().any(|h| h.to_lowercase().contains(term)) {
        take(50);
    }
    if row.tags.iter().any(|t| t.to_lowercase().contains(term)) {
        take(30);
    }
    best
}

fn passes(filter: &Filter, row: &ItemRow, now_window: bool) -> bool {
    match filter {
        Filter::Favourite => row.favourite,
        Filter::Untagged => row.tags.is_empty(),
        Filter::Passkey => row.has_passkey,
        Filter::Expiring => now_window,
        Filter::Archived => row.status == ItemStatus::Archived,
        Filter::Tag(tag) => row.tags.iter().any(|t| {
            let t = t.to_lowercase();
            t == *tag || t.starts_with(&format!("{tag}/"))
        }),
        Filter::Category(kind) => row.kind.to_lowercase() == *kind,
        Filter::Vault(id) => row.vault.starts_with(id),
    }
}

fn boost(matcher: &Matcher, page: &Origin, row: &ItemRow) -> u32 {
    let entries: Vec<UrlEntry> = row
        .hosts
        .iter()
        .filter_map(|host| {
            UrlEntry::new(
                crate::model::id::Id::from_bytes([0; 16]),
                &format!("https://{host}/"),
                MatchMode::Domain,
                crate::model::url::UrlKind::Website,
            )
            .ok()
        })
        .collect();
    match matcher.rank(page, &entries).level {
        MatchLevel::Exact => BOOST_EXACT,
        MatchLevel::Domain => BOOST_DOMAIN,
        MatchLevel::Related => BOOST_RELATED,
        MatchLevel::None => 0,
    }
}

pub(super) fn run(matcher: &Matcher, rows: Vec<ItemRow>, query: &SearchQuery) -> Vec<ItemRow> {
    let parsed = parse(&query.text);
    let page = query
        .boost_url
        .as_deref()
        .and_then(|u| Origin::parse(u).ok());
    let wanted_status = query.status.unwrap_or(ItemStatus::Active);
    let mut scored: Vec<(u32, ItemRow)> = rows
        .into_iter()
        .filter(|row| {
            let archived_filter = parsed.filters.iter().any(|f| matches!(f, Filter::Archived));
            if archived_filter {
                row.status == ItemStatus::Archived
            } else {
                row.status == wanted_status
            }
        })
        .filter(|row| query.kind.as_ref().is_none_or(|k| row.kind == *k))
        .filter(|row| query.vault.as_ref().is_none_or(|v| row.vault == *v))
        .filter(|row| {
            query
                .tag
                .as_ref()
                .is_none_or(|tag| row.tags.iter().any(|t| t == tag))
        })
        .filter(|row| !query.favourites_only || row.favourite)
        .filter(|row| {
            parsed
                .filters
                .iter()
                .all(|f| passes(f, row, row.expires_at.is_some()))
        })
        .filter_map(|row| {
            let mut total = 0_u32;
            for term in &parsed.terms {
                total = total.saturating_add(term_score(term, &row)?);
            }
            if row.favourite {
                total = total.saturating_add(FAVOURITE_BONUS);
            }
            if let Some(page) = &page {
                total = total.saturating_add(boost(matcher, page, &row));
            }
            Some((total, row))
        })
        .collect();
    scored.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.title.to_lowercase().cmp(&b.1.title.to_lowercase()))
    });
    let limit = if query.limit == 0 {
        usize::MAX
    } else {
        usize::try_from(query.limit).unwrap_or(usize::MAX)
    };
    scored.into_iter().take(limit).map(|(_, row)| row).collect()
}
