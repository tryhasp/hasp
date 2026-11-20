use super::*;
use crate::model::id::Id;
use crate::model::url::UrlKind;

fn matcher() -> Matcher {
    Matcher::bundled().unwrap()
}

fn entry(url: &str, mode: MatchMode) -> UrlEntry {
    UrlEntry::new(Id::from_bytes([7; 16]), url, mode, UrlKind::Website).unwrap()
}

fn rank(page: &str, url: &str, mode: MatchMode) -> (MatchLevel, Fill) {
    let m = matcher().rank_page(page, &[entry(url, mode)]);
    (m.level, m.fill)
}

use Fill::{ConfirmFirst as Confirm, Never as NoFill, OneClick as One};
use MatchLevel::{Domain as Dom, Exact, None as NoMatch, Related};

const D: MatchMode = MatchMode::Domain;
const H: MatchMode = MatchMode::Host;
const N: MatchMode = MatchMode::Never;

fn assert_ranks(cases: &[(&str, &str, MatchMode, MatchLevel, Fill)]) {
    for (page, url, mode, level, fill) in cases {
        assert_eq!(
            rank(page, url, *mode),
            (*level, *fill),
            "{page} vs {url} {mode:?}"
        );
    }
}

#[test]
fn policy_matches_one_registrable_domain_across_case_default_port_scheme_and_subdomain() {
    assert_ranks(&[
        (
            "https://example.com/login",
            "https://example.com",
            D,
            Exact,
            One,
        ),
        (
            "https://EXAMPLE.com:443/",
            "https://example.com/",
            D,
            Exact,
            One,
        ),
        ("https://example.com/", "http://example.com/", D, Exact, One),
        (
            "https://example.com:8443/",
            "https://example.com/",
            D,
            NoMatch,
            NoFill,
        ),
        (
            "https://login.example.com",
            "https://example.com",
            D,
            Dom,
            Confirm,
        ),
        (
            "https://example.com",
            "https://www.example.com",
            D,
            Dom,
            Confirm,
        ),
    ]);
}

#[test]
fn policy_host_and_never_modes_narrow_the_match() {
    assert_ranks(&[
        (
            "https://login.example.com",
            "https://example.com",
            H,
            NoMatch,
            NoFill,
        ),
        ("https://example.com", "https://example.com", H, Exact, One),
        (
            "https://example.com",
            "https://example.com",
            N,
            NoMatch,
            NoFill,
        ),
        (
            "https://login.example.com",
            "https://example.com",
            N,
            NoMatch,
            NoFill,
        ),
    ]);
}

#[test]
fn policy_domain_boundaries_follow_the_public_suffix_list_and_idna() {
    assert_ranks(&[
        (
            "https://evil.com",
            "https://example.com",
            D,
            NoMatch,
            NoFill,
        ),
        (
            "https://example.com.evil.com",
            "https://example.com",
            D,
            NoMatch,
            NoFill,
        ),
        (
            "https://notexample.com",
            "https://example.com",
            D,
            NoMatch,
            NoFill,
        ),
        (
            "https://www.naver.co.kr",
            "https://mail.naver.co.kr",
            D,
            Dom,
            Confirm,
        ),
        (
            "https://other.co.kr",
            "https://naver.co.kr",
            D,
            NoMatch,
            NoFill,
        ),
        (
            "https://a.github.io",
            "https://b.github.io",
            D,
            NoMatch,
            NoFill,
        ),
        (
            "https://a.github.io/x",
            "https://www.a.github.io",
            D,
            Dom,
            Confirm,
        ),
        (
            "https://xn--bcher-kva.de",
            "https://bücher.de",
            D,
            Exact,
            One,
        ),
        (
            "https://shop.bücher.de",
            "https://bücher.de",
            D,
            Dom,
            Confirm,
        ),
    ]);
}

#[test]
fn policy_scheme_downgrade_ports_and_ip_hosts_match_exactly_or_not_at_all() {
    assert_ranks(&[
        (
            "http://example.com",
            "https://example.com",
            D,
            NoMatch,
            NoFill,
        ),
        (
            "http://localhost:3000",
            "http://localhost:3000",
            D,
            Exact,
            One,
        ),
        (
            "http://localhost:3000",
            "http://localhost:4000",
            D,
            NoMatch,
            NoFill,
        ),
        (
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8080",
            D,
            Exact,
            One,
        ),
        ("https://10.0.0.1", "https://10.0.0.1", D, Exact, One),
        ("https://10.0.0.1", "https://10.0.0.2", D, NoMatch, NoFill),
    ]);
}

#[test]
fn policy_related_domains_are_suggested_and_never_filled_in_one_click() {
    assert_ranks(&[
        (
            "https://daum.net",
            "https://accounts.kakao.com",
            D,
            Related,
            Confirm,
        ),
        (
            "https://themeforest.net",
            "https://envato.com",
            D,
            Related,
            Confirm,
        ),
        (
            "https://themeforest.net",
            "https://envato.com",
            H,
            NoMatch,
            NoFill,
        ),
        (
            "https://hosting.com",
            "https://a2hosting.com",
            D,
            Related,
            Confirm,
        ),
        (
            "https://a2hosting.com",
            "https://hosting.com",
            D,
            NoMatch,
            NoFill,
        ),
    ]);
}

#[test]
fn policy_refuses_non_web_pages() {
    assert_ranks(&[
        (
            "javascript:alert(1)",
            "https://example.com",
            D,
            NoMatch,
            NoFill,
        ),
        (
            "file:///tmp/a.html",
            "https://example.com",
            D,
            NoMatch,
            NoFill,
        ),
    ]);
}

#[test]
fn directed_groups_suggest_old_domain_items_on_the_new_domain_only() {
    assert_eq!(
        rank(
            "https://hosting.com",
            "https://a2hosting.com",
            MatchMode::Domain
        ),
        (Related, Confirm)
    );
    assert_eq!(
        rank(
            "https://a2hosting.com",
            "https://hosting.com",
            MatchMode::Domain
        ),
        (NoMatch, NoFill)
    );
}

#[test]
fn insecure_pages_are_refused_with_a_reason() {
    let m = matcher().rank_page(
        "http://example.com",
        &[entry("https://example.com", MatchMode::Domain)],
    );
    assert_eq!(m.refusal, Some(Refusal::InsecureOrigin));
    let m = matcher().rank_page("file:///x", &[]);
    assert_eq!(m.refusal, Some(Refusal::UnsupportedScheme));
}

#[test]
fn confirmed_hosts_upgrade_fill_and_admit_unrelated_hosts() {
    let mut url = entry("https://example.com", MatchMode::Domain);
    url.confirm_host("login.example.com").unwrap();
    url.confirm_host("example-login.net").unwrap();
    let m = matcher();
    let on_sub = m.rank_page("https://login.example.com", std::slice::from_ref(&url));
    assert_eq!((on_sub.level, on_sub.fill), (Dom, One));
    let on_other = m.rank_page("https://example-login.net", std::slice::from_ref(&url));
    assert_eq!((on_other.level, on_other.fill), (Related, One));
    let on_unconfirmed = m.rank_page("https://other.example.com", std::slice::from_ref(&url));
    assert_eq!((on_unconfirmed.level, on_unconfirmed.fill), (Dom, Confirm));
    url.set_mode(MatchMode::Host);
    let strict = m.rank_page("https://example-login.net", std::slice::from_ref(&url));
    assert_eq!(strict.level, NoMatch);
}

#[test]
fn best_entry_wins_and_items_sort_by_level() {
    let m = matcher();
    let page = Origin::parse("https://login.example.com").unwrap();
    let items = vec![
        ("none", vec![entry("https://other.com", MatchMode::Domain)]),
        (
            "domain",
            vec![entry("https://example.com", MatchMode::Domain)],
        ),
        (
            "exact",
            vec![
                entry("https://example.com", MatchMode::Domain),
                entry("https://login.example.com", MatchMode::Host),
            ],
        ),
    ];
    let ranked = m.rank_items(&page, &items);
    let keys: Vec<&str> = ranked.iter().map(|r| r.key).collect();
    assert_eq!(keys, ["exact", "domain"]);
    assert_eq!(ranked[0].result.level, Exact);
}

#[test]
fn page_that_is_an_ip_never_matches_by_domain() {
    let page = Origin::parse("https://10.0.0.1").unwrap();
    let m = matcher().rank(&page, &[entry("https://example.com", MatchMode::Domain)]);
    assert_eq!(m.level, NoMatch);
}
