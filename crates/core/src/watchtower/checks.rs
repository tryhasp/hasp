use std::net::IpAddr;

use url::{Host, Url};

use crate::model::field::{Date, FieldValue, MonthYear, Section};
use crate::model::item::{Item, Time};
use crate::model::url::UrlEntry;

pub(super) const SECONDS_PER_DAY: u64 = 86_400;

pub(super) fn only_insecure_urls(urls: &[UrlEntry]) -> bool {
    !urls.is_empty()
        && urls.iter().all(|entry| {
            Url::parse(entry.url()).is_ok_and(|parsed| {
                parsed.scheme() == "http" && !parsed.host().as_ref().is_some_and(is_loopback)
            })
        })
}

fn is_loopback(host: &Host<&str>) -> bool {
    match *host {
        Host::Domain(name) => {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            name == "localhost" || name.ends_with(".localhost")
        }
        Host::Ipv4(address) => IpAddr::V4(address).is_loopback(),
        Host::Ipv6(address) => IpAddr::V6(address).is_loopback(),
    }
}

pub(super) fn expiry_dates(item: &Item) -> Vec<Time> {
    let mut dates: Vec<Time> = item
        .details()
        .sections
        .iter()
        .flat_map(Section::fields)
        .filter(|field| field.expires_alert())
        .filter_map(|field| match field.value() {
            FieldValue::Date(date) => Some(end_of_date(*date)),
            FieldValue::MonthYear(month_year) => Some(end_of_month(*month_year)),
            FieldValue::Text(_)
            | FieldValue::Concealed(_)
            | FieldValue::Url(_)
            | FieldValue::Email(_)
            | FieldValue::Phone(_)
            | FieldValue::Otp(_)
            | FieldValue::Address(_)
            | FieldValue::Menu(_)
            | FieldValue::SecurityQuestion { .. }
            | FieldValue::SignInWith(_) => None,
        })
        .collect();
    dates.extend(item.overview().expires_at);
    dates.sort_unstable();
    dates.dedup();
    dates
}

pub(super) fn days_until(expiry: Time, now: Time) -> i64 {
    let expiry = i64::try_from(expiry).unwrap_or(i64::MAX);
    let now = i64::try_from(now).unwrap_or(i64::MAX);
    let seconds = i64::try_from(SECONDS_PER_DAY).unwrap_or(1);
    (expiry - now).div_euclid(seconds)
}

fn end_of_date(date: Date) -> Time {
    days_from_civil(date.year(), date.month(), date.day()).saturating_add(1) * SECONDS_PER_DAY
}

fn end_of_month(month_year: MonthYear) -> Time {
    let (year, month) = if month_year.month() == 12 {
        (month_year.year().saturating_add(1), 1)
    } else {
        (month_year.year(), month_year.month() + 1)
    };
    days_from_civil(year, month, 1) * SECONDS_PER_DAY
}

// Why: Howard Hinnant's civil-from-days inverse; exact for the proleptic Gregorian calendar.
fn days_from_civil(year: u16, month: u8, day: u8) -> u64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month_index = (i64::from(month) + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    u64::try_from(era * 146_097 + day_of_era - 719_468).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::id::Id;
    use crate::model::url::{MatchMode, UrlKind};

    fn url(text: &str) -> UrlEntry {
        UrlEntry::new(
            Id::from_bytes([1; 16]),
            text,
            MatchMode::Domain,
            UrlKind::Website,
        )
        .unwrap()
    }

    #[test]
    fn civil_dates_match_known_epoch_days() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2026, 11, 19), 20_776);
    }

    #[test]
    fn month_end_is_the_first_of_the_next_month() {
        let december = MonthYear::new(2026, 12).unwrap();
        assert_eq!(
            end_of_month(december),
            days_from_civil(2027, 1, 1) * SECONDS_PER_DAY
        );
        let february = MonthYear::new(2028, 2).unwrap();
        assert_eq!(
            end_of_month(february),
            days_from_civil(2028, 3, 1) * SECONDS_PER_DAY
        );
    }

    #[test]
    fn days_until_floors_and_goes_negative() {
        assert_eq!(days_until(10 * SECONDS_PER_DAY, 0), 10);
        assert_eq!(days_until(10 * SECONDS_PER_DAY, SECONDS_PER_DAY / 2), 9);
        assert_eq!(days_until(0, SECONDS_PER_DAY), -1);
    }

    #[test]
    fn flags_logins_whose_only_urls_are_plain_http() {
        assert!(only_insecure_urls(&[url("http://example.com/login")]));
        assert!(only_insecure_urls(&[
            url("http://a.example"),
            url("http://b.example")
        ]));
        assert!(!only_insecure_urls(&[
            url("http://a.example"),
            url("https://a.example")
        ]));
        assert!(!only_insecure_urls(&[url("https://example.com")]));
        assert!(!only_insecure_urls(&[]));
    }

    #[test]
    fn loopback_http_is_not_insecure() {
        for loopback in [
            "http://localhost:3000",
            "http://app.localhost",
            "http://127.0.0.1:8080",
            "http://127.5.5.5",
            "http://[::1]:80",
        ] {
            assert!(!only_insecure_urls(&[url(loopback)]), "{loopback}");
        }
        assert!(only_insecure_urls(&[url("http://192.168.1.10")]));
        assert!(only_insecure_urls(&[url("http://notlocalhost.com")]));
    }
}
