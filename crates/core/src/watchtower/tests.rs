use std::collections::BTreeMap;
use std::future::Future;
use std::pin::pin;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use secrecy::SecretString;

use super::*;
use crate::model::field::{Date, Field, MonthYear, Section};
use crate::model::item::{ItemParts, ItemState};
use crate::model::url::{MatchMode, UrlEntry, UrlKind};
use crate::watchtower::pwned::{PADDING_HEADER, PREFIX_LEN};
use crate::watchtower::report::Category;

const NOW: Time = 20_776 * 86_400;
const DAY: u64 = 86_400;
const STRONG: &str = "v8#Kq2!zRw9@Lm4x";

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
    }
}

fn key(n: u32) -> Id {
    let mut bytes = [0u8; 16];
    bytes[..4].copy_from_slice(&n.to_le_bytes());
    Id::from_bytes(bytes)
}

fn templates() -> Templates {
    Templates::bundled().unwrap()
}

fn parts(kind: &str, sections: Vec<Section>, urls: Vec<UrlEntry>) -> ItemParts {
    ItemParts {
        kind: kind.to_owned(),
        title: "t".to_owned(),
        subtitle: String::new(),
        tags: Vec::new(),
        favourite: None,
        state: ItemState::Active,
        sections,
        notes: None,
        urls,
        apps: Vec::new(),
        passkeys: Vec::new(),
        attachments: Vec::new(),
        password_history: Vec::new(),
        client_modified: 10,
        created: 10,
        expires_at: None,
    }
}

fn password_section(password: &str) -> Section {
    let field = Field::new(
        Id::from_bytes([200; 16]),
        "password",
        FieldValue::Concealed(SecretString::from(password)),
    )
    .unwrap()
    .with_purpose(Purpose::Password)
    .unwrap();
    Section::new(Id::from_bytes([7; 16]), "", vec![field]).unwrap()
}

fn url(text: &str) -> UrlEntry {
    UrlEntry::new(
        Id::from_bytes([9; 16]),
        text,
        MatchMode::Domain,
        UrlKind::Website,
    )
    .unwrap()
}

fn login(password: &str) -> Item {
    Item::new(parts("login", vec![password_section(password)], Vec::new())).unwrap()
}

fn login_at(password: &str, address: &str) -> Item {
    Item::new(parts(
        "login",
        vec![password_section(password)],
        vec![url(address)],
    ))
    .unwrap()
}

fn expiring(kind: &str, value: FieldValue, alert: bool) -> Item {
    let field = Field::new(Id::from_bytes([201; 16]), "expires", value)
        .unwrap()
        .with_expires_alert(alert);
    let section = Section::new(Id::from_bytes([8; 16]), "", vec![field]).unwrap();
    Item::new(parts(kind, vec![section], Vec::new())).unwrap()
}

fn card_expiring(year: u16, month: u8) -> Item {
    expiring(
        "credit-card",
        FieldValue::MonthYear(MonthYear::new(year, month).unwrap()),
        true,
    )
}

fn watchtower_with(items: &[(u32, Item)]) -> Watchtower {
    let mut watchtower = Watchtower::new().unwrap();
    let templates = templates();
    for (n, item) in items {
        watchtower.upsert(key(*n), item, &templates);
    }
    watchtower
}

fn categories(report: &Report, n: u32) -> Vec<Category> {
    report
        .items
        .iter()
        .find(|item| item.item == key(n))
        .map(|item| item.findings.iter().map(Finding::category).collect())
        .unwrap_or_default()
}

struct FakeRange {
    bodies: BTreeMap<String, String>,
    seen: Mutex<Vec<String>>,
}

impl FakeRange {
    fn new(bodies: &[(&str, String)]) -> Self {
        Self {
            bodies: bodies
                .iter()
                .map(|(p, b)| ((*p).to_owned(), b.clone()))
                .collect(),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

impl RangeClient for FakeRange {
    fn range(
        &self,
        prefix: &Prefix,
    ) -> impl Future<Output = Result<String, WatchtowerError>> + Send {
        self.seen.lock().unwrap().push(prefix.as_str().to_owned());
        std::future::ready(
            self.bodies
                .get(prefix.as_str())
                .cloned()
                .ok_or(WatchtowerError::Network),
        )
    }
}

fn password_body(count: u64) -> String {
    format!(
        "0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:{count}\r\n\
         FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n"
    )
}

#[test]
fn flags_weak_passwords_with_reasons() {
    let watchtower =
        watchtower_with(&[(1, login("abc")), (2, login(STRONG)), (3, login("dkssud"))]);
    let report = watchtower.report(NOW);
    assert_eq!(categories(&report, 1), vec![Category::Weak]);
    assert!(categories(&report, 2).is_empty());
    assert_eq!(categories(&report, 3), vec![Category::Weak]);
    assert_eq!(report.counts.weak, 2);
    let Detail::Weak { reasons, .. } = &report.items[0].findings[0].detail else {
        panic!("expected weak");
    };
    assert!(reasons.contains(&WeakReason::TooShort));
}

#[test]
fn hangul_typed_on_qwerty_is_reported_weak() {
    let watchtower = watchtower_with(&[(1, login("dkssudgktpdy")), (2, login("안녕하세요"))]);
    let report = watchtower.report(NOW);
    assert_eq!(categories(&report, 1), vec![Category::Weak]);
    assert_eq!(categories(&report, 2), vec![Category::Weak]);
}

#[test]
fn reused_passwords_group_active_items_only() {
    let mut watchtower = watchtower_with(&[
        (1, login(STRONG)),
        (2, login(STRONG)),
        (3, login(STRONG)),
        (4, login("another-Strong#pass-77")),
    ]);
    let report = watchtower.report(NOW);
    for n in 1..=3 {
        let finding = &report
            .items
            .iter()
            .find(|i| i.item == key(n))
            .unwrap()
            .findings[0];
        assert_eq!(finding.detail, Detail::Reused { items: 3 });
    }
    assert!(categories(&report, 4).is_empty());
    assert_eq!(report.counts.reused, 3);

    let archived = login(STRONG).with_state(ItemState::Archived { at: 5 }, 11);
    watchtower.upsert(key(3), &archived, &templates());
    let report = watchtower.report(NOW);
    assert_eq!(
        report
            .items
            .iter()
            .find(|i| i.item == key(1))
            .unwrap()
            .findings[0]
            .detail,
        Detail::Reused { items: 2 }
    );
    assert!(categories(&report, 3).is_empty());

    watchtower.remove(key(2));
    assert_eq!(watchtower.report(NOW).counts.reused, 0);
}

#[test]
fn reuse_uses_keyed_hashes_that_differ_between_instances() {
    let item = login(STRONG);
    let a = watchtower_with(&[(1, login(STRONG))]);
    let b = watchtower_with(&[(1, item)]);
    let tag_a = a.entries.get(&key(1)).unwrap().passwords[0].tag;
    let tag_b = b.entries.get(&key(1)).unwrap().passwords[0].tag;
    assert_ne!(tag_a, tag_b);
    assert!(!format!("{a:?}").contains(STRONG));
    assert_eq!(a.groups.len(), 1);
}

#[test]
fn repeated_password_inside_one_item_is_not_reuse() {
    let second = Field::new(
        Id::from_bytes([202; 16]),
        "again",
        FieldValue::Concealed(SecretString::from(STRONG)),
    )
    .unwrap()
    .with_purpose(Purpose::Password)
    .unwrap();
    let first = password_section(STRONG).into_fields().remove(0);
    let section = Section::new(Id::from_bytes([7; 16]), "", vec![first, second]).unwrap();
    let item = Item::new(parts("login", vec![section], Vec::new())).unwrap();
    let watchtower = watchtower_with(&[(1, item)]);
    assert_eq!(watchtower.report(NOW).counts.reused, 0);
}

#[test]
fn flags_logins_with_only_plain_http_urls() {
    let watchtower = watchtower_with(&[
        (1, login_at(STRONG, "http://shop.example")),
        (2, login_at("second-Strong#pass-21", "https://shop.example")),
        (3, login_at("third-Strong#pass-32", "http://localhost:3000")),
        (4, login("fourth-Strong#pass-43")),
    ]);
    let report = watchtower.report(NOW);
    assert_eq!(categories(&report, 1), vec![Category::InsecureUrl]);
    assert!(categories(&report, 2).is_empty());
    assert!(categories(&report, 3).is_empty());
    assert!(categories(&report, 4).is_empty());
}

#[test]
fn flags_expiry_inside_the_template_window() {
    let watchtower = watchtower_with(&[
        (1, card_expiring(2026, 12)),
        (2, card_expiring(2027, 6)),
        (3, card_expiring(2026, 10)),
        (
            4,
            expiring(
                "credit-card",
                FieldValue::MonthYear(MonthYear::new(2026, 12).unwrap()),
                false,
            ),
        ),
    ]);
    let report = watchtower.report(NOW);
    let days = |n: u32| match &report
        .items
        .iter()
        .find(|i| i.item == key(n))
        .unwrap()
        .findings[0]
    {
        Finding {
            detail: Detail::Expiring { days_left },
            severity,
        } => (*days_left, *severity),
        other => panic!("{other:?}"),
    };
    assert_eq!(days(1), (43, Severity::Low));
    assert_eq!(days(3), (-18, Severity::High));
    assert!(categories(&report, 2).is_empty());
    assert!(categories(&report, 4).is_empty());
}

#[test]
fn passports_use_their_long_window_and_dates_are_end_of_day() {
    let in_nine_months = Date::new(2027, 8, 19).unwrap();
    let passport = expiring("passport", FieldValue::Date(in_nine_months), true);
    let far = expiring(
        "passport",
        FieldValue::Date(Date::new(2029, 1, 1).unwrap()),
        true,
    );
    let today = expiring(
        "passport",
        FieldValue::Date(Date::new(2026, 11, 19).unwrap()),
        true,
    );
    let watchtower = watchtower_with(&[(1, passport), (2, far), (3, today)]);
    let report = watchtower.report(NOW + DAY / 2);
    assert_eq!(categories(&report, 1), vec![Category::Expiring]);
    assert!(categories(&report, 2).is_empty());
    let finding = &report
        .items
        .iter()
        .find(|i| i.item == key(3))
        .unwrap()
        .findings[0];
    assert_eq!(finding.detail, Detail::Expiring { days_left: 0 });
    assert_eq!(finding.severity, Severity::Medium);
}

#[test]
fn expiry_follows_the_clock_without_recomputing_items() {
    let watchtower = watchtower_with(&[(1, card_expiring(2027, 2))]);
    assert!(watchtower.report(NOW).items.is_empty());
    assert_eq!(watchtower.report(NOW + 60 * DAY).counts.expiring, 1);
}

#[test]
fn only_active_items_are_checked() {
    let trashed = login("abc").with_state(ItemState::Trashed { at: 1 }, 11);
    let archived = login("abc").with_state(ItemState::Archived { at: 1 }, 11);
    let watchtower = watchtower_with(&[(1, trashed), (2, archived), (3, login("abc"))]);
    assert_eq!(watchtower.len(), 1);
    assert_eq!(watchtower.report(NOW).counts.weak, 1);
}

#[test]
fn upsert_replaces_only_the_changed_item() {
    let mut watchtower = watchtower_with(&[(1, login("abc")), (2, login("dkssud"))]);
    let before = watchtower.item_report(key(2), NOW);
    watchtower.upsert(key(1), &login(STRONG), &templates());
    assert!(watchtower.item_report(key(1), NOW).is_none());
    assert_eq!(watchtower.item_report(key(2), NOW), before);
    assert_eq!(watchtower.report(NOW).counts.weak, 1);
}

#[test]
fn report_orders_the_most_severe_items_first() {
    let watchtower = watchtower_with(&[
        (1, login_at(STRONG, "http://a.example")),
        (2, login("123456")),
        (3, card_expiring(2026, 12)),
    ]);
    let report = watchtower.report(NOW);
    assert_eq!(report.items[0].item, key(2));
    assert_eq!(report.items[0].severity(), Severity::High);
    assert_eq!(report.counts.total(), 3);
}

#[test]
fn breach_lookup_sends_only_five_hex_characters() {
    let mut watchtower = watchtower_with(&[(1, login("password"))]);
    watchtower.set_pwned_mode(PwnedMode::OptedIn);
    let client = FakeRange::new(&[("5BAA6", password_body(10_434_004))]);
    let run = block_on(watchtower.check_pwned(&client, NOW)).unwrap();
    assert_eq!(
        run,
        PwnedRun {
            requests: 1,
            resolved: 1
        }
    );
    let requests = client.requests();
    assert_eq!(requests, vec!["5BAA6".to_owned()]);
    for request in &requests {
        assert_eq!(request.len(), PREFIX_LEN);
        assert!(
            request
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_lowercase())
        );
        assert!(!"password".contains(request.as_str()));
    }
    assert_eq!(PADDING_HEADER, ("Add-Padding", "true"));
    let finding = &watchtower.report(NOW).items[0].findings[0];
    assert_eq!(finding.detail, Detail::Pwned { count: 10_434_004 });
    assert_eq!(finding.severity, Severity::High);
}

#[test]
fn padding_only_matches_are_not_breaches() {
    let mut watchtower = watchtower_with(&[(1, login("password"))]);
    watchtower.set_pwned_mode(PwnedMode::OptedIn);
    let client = FakeRange::new(&[("5BAA6", password_body(0))]);
    block_on(watchtower.check_pwned(&client, NOW)).unwrap();
    assert_eq!(watchtower.report(NOW).counts.pwned, 0);
}

#[test]
fn breach_check_is_opt_in() {
    let mut watchtower = watchtower_with(&[(1, login("password"))]);
    let client = FakeRange::new(&[]);
    let result = block_on(watchtower.check_pwned(&client, NOW));
    assert!(matches!(result, Err(WatchtowerError::PwnedDisabled)));
    assert!(client.requests().is_empty());
}

#[test]
fn identical_prefixes_share_one_request_and_results_are_cached() {
    let mut watchtower = watchtower_with(&[(1, login("password")), (2, login("password"))]);
    watchtower.set_pwned_mode(PwnedMode::OptedIn);
    let client = FakeRange::new(&[("5BAA6", password_body(5))]);
    let run = block_on(watchtower.check_pwned(&client, NOW)).unwrap();
    assert_eq!(
        run,
        PwnedRun {
            requests: 1,
            resolved: 2
        }
    );
    let again = block_on(watchtower.check_pwned(&client, NOW + DAY - 1)).unwrap();
    assert_eq!(
        again,
        PwnedRun {
            requests: 0,
            resolved: 0
        }
    );
    let stale = block_on(watchtower.check_pwned(&client, NOW + DAY)).unwrap();
    assert_eq!(
        stale,
        PwnedRun {
            requests: 1,
            resolved: 2
        }
    );
    assert_eq!(client.requests().len(), 2);
}

#[test]
fn cached_prefix_serves_a_new_item_without_a_request() {
    let mut watchtower = watchtower_with(&[(1, login("password"))]);
    watchtower.set_pwned_mode(PwnedMode::OptedIn);
    let client = FakeRange::new(&[("5BAA6", password_body(5))]);
    block_on(watchtower.check_pwned(&client, NOW)).unwrap();
    watchtower.upsert(key(2), &login("password"), &templates());
    let run = block_on(watchtower.check_pwned(&client, NOW + 10)).unwrap();
    assert_eq!(
        run,
        PwnedRun {
            requests: 0,
            resolved: 1
        }
    );
}

#[test]
fn a_changed_password_loses_its_verdict_and_an_unchanged_one_keeps_it() {
    let mut watchtower = watchtower_with(&[(1, login("password"))]);
    watchtower.set_pwned_mode(PwnedMode::OptedIn);
    let client = FakeRange::new(&[("5BAA6", password_body(5))]);
    block_on(watchtower.check_pwned(&client, NOW)).unwrap();
    watchtower.upsert(key(1), &login("password"), &templates());
    assert_eq!(watchtower.report(NOW).counts.pwned, 1);
    watchtower.upsert(key(1), &login(STRONG), &templates());
    assert_eq!(watchtower.report(NOW).counts.pwned, 0);
}

#[test]
fn network_failure_surfaces_and_keeps_earlier_results() {
    let mut watchtower = watchtower_with(&[(1, login("password")), (2, login("letmein"))]);
    watchtower.set_pwned_mode(PwnedMode::OptedIn);
    let client = FakeRange::new(&[("5BAA6", password_body(5))]);
    let result = block_on(watchtower.check_pwned(&client, NOW));
    assert!(matches!(result, Err(WatchtowerError::Network)));
    assert_eq!(watchtower.report(NOW).counts.pwned, 1);
}

#[test]
fn turning_the_check_off_forgets_breach_results() {
    let mut watchtower = watchtower_with(&[(1, login("password"))]);
    watchtower.set_pwned_mode(PwnedMode::OptedIn);
    let client = FakeRange::new(&[("5BAA6", password_body(5))]);
    block_on(watchtower.check_pwned(&client, NOW)).unwrap();
    watchtower.set_pwned_mode(PwnedMode::Off);
    assert_eq!(watchtower.report(NOW).counts.pwned, 0);
}

#[test]
fn checks_two_thousand_items_quickly() {
    let templates = templates();
    let mut watchtower = Watchtower::new().unwrap();
    let started = Instant::now();
    for n in 0..2_000u32 {
        let password = match n % 4 {
            0 => format!("Zq{n}#wLp2-xV{n}"),
            1 => format!("shared-{}-pass!", n % 10),
            2 => format!("dkssud{n}"),
            _ => format!("{n}abcdef"),
        };
        let item = login_at(&password, "http://bench.example");
        watchtower.upsert(key(n), &item, &templates);
    }
    let upserted = started.elapsed();
    let report_started = Instant::now();
    let report = watchtower.report(NOW);
    let reported = report_started.elapsed();
    assert_eq!(watchtower.len(), 2_000);
    assert_eq!(report.counts.insecure_url, 2_000);
    assert!(report.counts.reused > 0 && report.counts.weak > 0);
    assert!(upserted.as_secs() < 5, "upsert took {upserted:?}");
    assert!(reported.as_millis() < 100, "report took {reported:?}");
}
