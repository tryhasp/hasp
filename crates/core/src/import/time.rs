use crate::model::field::{Date, MonthYear};

const SECONDS_PER_DAY: i64 = 86_400;

pub(super) fn date_from_epoch(seconds: i64) -> Option<Date> {
    let (year, month, day) = civil_from_days(seconds.div_euclid(SECONDS_PER_DAY));
    Date::new(
        u16::try_from(year).ok()?,
        u8::try_from(month).ok()?,
        u8::try_from(day).ok()?,
    )
    .ok()
}

pub(super) fn month_year_from_number(value: i64) -> Option<MonthYear> {
    MonthYear::new(
        u16::try_from(value.div_euclid(100)).ok()?,
        u8::try_from(value.rem_euclid(100)).ok()?,
    )
    .ok()
}

pub(super) fn parse_rfc3339(text: &str) -> Option<u64> {
    let text = text.trim();
    let (date, rest) = text.split_once(['T', 't', ' '])?;
    let mut date_parts = date.splitn(3, '-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || !(1970..=9999).contains(&year) {
        return None;
    }
    let split = rest.find(['Z', 'z', '+', '-']).unwrap_or(rest.len());
    let (clock, zone) = rest.split_at(split);
    let clock = clock.split('.').next()?;
    let mut clock_parts = clock.splitn(3, ':');
    let hour: i64 = clock_parts.next()?.parse().ok()?;
    let minute: i64 = clock_parts.next()?.parse().ok()?;
    let second: i64 = clock_parts.next().unwrap_or("0").parse().ok()?;
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let offset = zone_offset(zone)?;
    let seconds =
        days_from_civil(year, month, day) * SECONDS_PER_DAY + hour * 3600 + minute * 60 + second
            - offset;
    u64::try_from(seconds).ok()
}

fn zone_offset(zone: &str) -> Option<i64> {
    if zone.is_empty() || zone.eq_ignore_ascii_case("z") {
        return Some(0);
    }
    let sign = match zone.chars().next()? {
        '+' => 1,
        '-' => -1,
        _ => return None,
    };
    let body = zone.get(1..)?;
    let (hours, minutes) = body.split_once(':').unwrap_or((body, "0"));
    let hours: i64 = hours.parse().ok()?;
    let minutes: i64 = minutes.parse().ok()?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some(sign * (hours * 3600 + minutes * 60))
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub(crate) fn civil_date(unix: u64) -> String {
    let (year, month, day) = civil_from_days(i64::try_from(unix / 86_400).unwrap_or(0));
    format!("{year:04}-{month:02}-{day:02}")
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc3339_with_zones_and_fractions() {
        assert_eq!(parse_rfc3339("2024-01-02T03:04:05Z"), Some(1_704_164_645));
        assert_eq!(
            parse_rfc3339("2024-01-02T03:04:05.987Z"),
            Some(1_704_164_645)
        );
        assert_eq!(
            parse_rfc3339("2024-01-02T12:04:05+09:00"),
            Some(1_704_164_645)
        );
        assert_eq!(parse_rfc3339("1969-12-31T00:00:00Z"), None);
        assert_eq!(parse_rfc3339("garbage"), None);
        assert_eq!(parse_rfc3339("2024-13-02T03:04:05Z"), None);
    }

    #[test]
    fn converts_epoch_to_dates_and_month_years() {
        let date = date_from_epoch(1_704_164_645).unwrap();
        assert_eq!((date.year(), date.month(), date.day()), (2024, 1, 2));
        let before = date_from_epoch(-86_400).unwrap();
        assert_eq!(
            (before.year(), before.month(), before.day()),
            (1969, 12, 31)
        );
        let month_year = month_year_from_number(202_712).unwrap();
        assert_eq!((month_year.year(), month_year.month()), (2027, 12));
        assert!(month_year_from_number(202_713).is_none());
    }
}
