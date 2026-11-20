mod hangul;
mod words;

use std::collections::BTreeMap;
use std::sync::OnceLock;

const MAX_ANALYSED: usize = 128;
const MAX_HANGUL_RUN: usize = 24;
const MIN_PATTERN: usize = 3;
const MIN_WALK: usize = 4;
const MAX_WALK: usize = 13;
const SYLLABLE_BITS: f64 = 9.0;
const KOREAN_WORD_BASE_BITS: f64 = 6.0;
const LEET_BITS: f64 = 2.0;
const CASE_BITS: f64 = 1.0;
const SEQUENCE_BITS: f64 = 6.0;
const WALK_BITS: f64 = 6.0;
const YEAR_BITS: f64 = 7.0;
const SHORT_DATE_BITS: f64 = 13.0;
const LONG_DATE_BITS: f64 = 15.0;
const ROWS: [&str; 8] = [
    "qwertyuiop",
    "poiuytrewq",
    "asdfghjkl",
    "lkjhgfdsa",
    "zxcvbnm",
    "mnbvcxz",
    "1234567890",
    "0987654321",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WeakReason {
    TooShort,
    OneCharacterClass,
    Guessable,
}

pub const MIN_LENGTH: usize = 8;
pub const GUESSABLE_BELOW_BITS: f64 = 28.0;

struct Text<'a> {
    chars: &'a [char],
    lowered: Vec<char>,
    leets: [Vec<char>; 2],
}

struct Dictionary {
    words: BTreeMap<String, f64>,
    longest: usize,
}

pub fn estimate_bits(password: &str) -> f64 {
    let chars: Vec<char> = password.chars().collect();
    let analysed = chars.get(..MAX_ANALYSED).unwrap_or(&chars);
    let tail: f64 = chars
        .get(MAX_ANALYSED..)
        .unwrap_or_default()
        .iter()
        .map(|&c| char_bits(c))
        .sum();
    cheapest_cover(analysed) + tail
}

pub fn weak_reasons(password: &str, bits: f64) -> Vec<WeakReason> {
    let mut reasons = Vec::new();
    if password.chars().count() < MIN_LENGTH {
        reasons.push(WeakReason::TooShort);
    }
    if character_classes(password) <= 1 {
        reasons.push(WeakReason::OneCharacterClass);
    }
    if bits < GUESSABLE_BELOW_BITS {
        reasons.push(WeakReason::Guessable);
    }
    reasons
}

pub fn character_classes(password: &str) -> usize {
    let mut seen = [false; 5];
    for c in password.chars() {
        let slot = match c {
            'a'..='z' => 0,
            'A'..='Z' => 1,
            '0'..='9' => 2,
            ' '..='~' => 3,
            _ => 4,
        };
        if let Some(flag) = seen.get_mut(slot) {
            *flag = true;
        }
    }
    seen.into_iter().filter(|present| *present).count()
}

fn cheapest_cover(chars: &[char]) -> f64 {
    let dictionary = dictionary();
    let lowered: Vec<char> = chars.iter().map(char::to_ascii_lowercase).collect();
    let text = Text {
        chars,
        leets: leet_variants(&lowered),
        lowered,
    };
    let mut best = vec![f64::INFINITY; chars.len() + 1];
    if let Some(start) = best.first_mut() {
        *start = 0.0;
    }
    for i in 0..chars.len() {
        let base = best.get(i).copied().unwrap_or(f64::INFINITY);
        let mut offer = |end: usize, cost: f64| {
            if let Some(slot) = best.get_mut(end)
                && base + cost < *slot
            {
                *slot = base + cost;
            }
        };
        if let Some(&c) = chars.get(i) {
            offer(i + 1, char_bits(c));
        }
        dictionary_segments(dictionary, &text, i, &mut offer);
        repeat_segments(chars, i, &mut offer);
        sequence_segments(chars, i, &mut offer);
        walk_segments(&text.lowered, i, &mut offer);
        date_segments(chars, i, &mut offer);
        hangul_segments(chars, i, &mut offer);
    }
    best.last().copied().unwrap_or(0.0)
}

fn dictionary() -> &'static Dictionary {
    static DICTIONARY: OnceLock<Dictionary> = OnceLock::new();
    DICTIONARY.get_or_init(|| {
        let mut words = BTreeMap::new();
        let mut insert = |word: String, bits: f64| {
            words
                .entry(word)
                .and_modify(|known: &mut f64| *known = known.min(bits))
                .or_insert(bits);
        };
        for (rank, word) in words::COMMON_PASSWORDS.iter().enumerate() {
            insert((*word).to_owned(), rank_bits(rank));
        }
        for (rank, word) in words::KOREAN_WORDS.iter().enumerate() {
            let bits = KOREAN_WORD_BASE_BITS + rank_bits(rank);
            insert((*word).to_owned(), bits);
            if let Some(typed) = hangul::typed_form(word) {
                insert(typed, bits);
            }
        }
        let longest = words.keys().map(|w| w.chars().count()).max().unwrap_or(0);
        Dictionary { words, longest }
    })
}

fn rank_bits(rank: usize) -> f64 {
    f64::from(u32::try_from(rank + 2).unwrap_or(u32::MAX)).log2()
}

fn leet_variants(lowered: &[char]) -> [Vec<char>; 2] {
    let substitute = |one: char| -> Vec<char> {
        lowered
            .iter()
            .map(|&c| match c {
                '@' | '4' => 'a',
                '0' => 'o',
                '3' => 'e',
                '$' | '5' => 's',
                '7' | '+' => 't',
                '!' => 'i',
                '1' => one,
                other => other,
            })
            .collect()
    };
    [substitute('i'), substitute('l')]
}

fn dictionary_segments(
    dictionary: &Dictionary,
    text: &Text<'_>,
    start: usize,
    offer: &mut impl FnMut(usize, f64),
) {
    let Text {
        chars,
        lowered,
        leets,
    } = text;
    let longest = dictionary.longest.min(chars.len() - start);
    for len in 2..=longest {
        let end = start + len;
        let (Some(original), Some(plain)) = (chars.get(start..end), lowered.get(start..end)) else {
            continue;
        };
        let case_cost = if original == plain { 0.0 } else { CASE_BITS };
        let plain_key: String = plain.iter().collect();
        if let Some(bits) = dictionary.words.get(&plain_key) {
            offer(end, bits + case_cost);
        }
        for variant in leets {
            let Some(key) = variant.get(start..end) else {
                continue;
            };
            if key == plain {
                continue;
            }
            let key: String = key.iter().collect();
            if let Some(bits) = dictionary.words.get(&key) {
                offer(end, bits + case_cost + LEET_BITS);
            }
        }
    }
}

fn repeat_segments(chars: &[char], start: usize, offer: &mut impl FnMut(usize, f64)) {
    let Some(&first) = chars.get(start) else {
        return;
    };
    let run = chars
        .get(start..)
        .unwrap_or_default()
        .iter()
        .take_while(|&&c| c == first)
        .count();
    for len in MIN_PATTERN..=run {
        offer(start + len, char_bits(first) + length_bits(len));
    }
}

fn sequence_segments(chars: &[char], start: usize, offer: &mut impl FnMut(usize, f64)) {
    let (Some(&first), Some(&second)) = (chars.get(start), chars.get(start + 1)) else {
        return;
    };
    if !first.is_ascii_alphanumeric() || !second.is_ascii_alphanumeric() {
        return;
    }
    let step = i64::from(u32::from(second)) - i64::from(u32::from(first));
    if step.abs() != 1 {
        return;
    }
    let mut len = 2;
    let mut previous = second;
    for &next in chars.get(start + 2..).unwrap_or_default() {
        let consecutive = next.is_ascii_alphanumeric()
            && i64::from(u32::from(next)) - i64::from(u32::from(previous)) == step
            && next.is_ascii_digit() == first.is_ascii_digit();
        if !consecutive {
            break;
        }
        len += 1;
        previous = next;
    }
    for run in MIN_PATTERN..=len {
        offer(start + run, SEQUENCE_BITS + length_bits(run));
    }
}

fn walk_segments(lowered: &[char], start: usize, offer: &mut impl FnMut(usize, f64)) {
    let longest = MAX_WALK.min(lowered.len() - start);
    for len in MIN_WALK..=longest {
        let Some(window) = lowered.get(start..start + len) else {
            continue;
        };
        let text: String = window.iter().collect();
        if ROWS.iter().any(|row| row.contains(&text)) {
            offer(start + len, WALK_BITS + length_bits(len));
        }
    }
}

fn date_segments(chars: &[char], start: usize, offer: &mut impl FnMut(usize, f64)) {
    for (len, bits) in [(4, YEAR_BITS), (6, SHORT_DATE_BITS), (8, LONG_DATE_BITS)] {
        let Some(window) = chars.get(start..start + len) else {
            continue;
        };
        let Some(digits) = window
            .iter()
            .map(|c| c.to_digit(10))
            .collect::<Option<Vec<u32>>>()
        else {
            continue;
        };
        if plausible_date(&digits) {
            offer(start + len, bits);
        }
    }
}

fn plausible_date(digits: &[u32]) -> bool {
    let number = |range: std::ops::Range<usize>| {
        digits
            .get(range)
            .map(|part| part.iter().fold(0, |acc, d| acc * 10 + d))
    };
    let month_day = |month: Option<u32>, day: Option<u32>| {
        matches!(month, Some(1..=12)) && matches!(day, Some(1..=31))
    };
    let year = |y: Option<u32>| matches!(y, Some(1900..=2099));
    match digits.len() {
        4 => year(number(0..4)),
        6 => {
            month_day(number(2..4), number(4..6))
                || month_day(number(0..2), number(2..4))
                || month_day(number(2..4), number(0..2))
        }
        8 => {
            (year(number(0..4)) && month_day(number(4..6), number(6..8)))
                || (year(number(4..8))
                    && (month_day(number(0..2), number(2..4))
                        || month_day(number(2..4), number(0..2))))
        }
        _ => false,
    }
}

fn hangul_segments(chars: &[char], start: usize, offer: &mut impl FnMut(usize, f64)) {
    let Some(&first) = chars.get(start) else {
        return;
    };
    if !first.is_ascii_alphabetic() {
        return;
    }
    let run = chars
        .get(start..)
        .unwrap_or_default()
        .iter()
        .take_while(|c| c.is_ascii_alphabetic())
        .count()
        .min(MAX_HANGUL_RUN);
    for len in MIN_PATTERN..=run {
        let Some(letters) = chars.get(start..start + len) else {
            continue;
        };
        if let Some(count) = hangul::syllables_typed_on_qwerty(letters)
            && count >= 2
        {
            let case_cost = if letters.iter().any(char::is_ascii_uppercase) {
                CASE_BITS
            } else {
                0.0
            };
            offer(
                start + len,
                SYLLABLE_BITS * f64::from(u32::try_from(count).unwrap_or(u32::MAX)) + case_cost,
            );
        }
    }
}

fn length_bits(len: usize) -> f64 {
    f64::from(u32::try_from(len).unwrap_or(u32::MAX)).log2()
}

fn char_bits(c: char) -> f64 {
    match c {
        'a'..='z' | 'A'..='Z' => 26f64.log2(),
        '0'..='9' => 10f64.log2(),
        ' '..='~' => 33f64.log2(),
        c if hangul::is_syllable(c) => SYLLABLE_BITS,
        _ => 7.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn weak(password: &str) -> bool {
        !weak_reasons(password, estimate_bits(password)).is_empty()
    }

    #[test]
    fn common_passwords_are_cheap_even_when_disguised() {
        assert!(estimate_bits("password") < 8.0);
        assert!(estimate_bits("Password") < 9.0);
        assert!(estimate_bits("p@ssw0rd") < 12.0);
        assert!(estimate_bits("1q2w3e4r") < 10.0);
    }

    #[test]
    fn repeats_sequences_and_walks_are_cheap() {
        assert!(estimate_bits("aaaaaaaaaaaa") < 12.0);
        assert!(estimate_bits("abcdefghijkl") < 15.0);
        assert!(estimate_bits("9876543210") < 15.0);
        assert!(estimate_bits("zxcvbnm,./") < 25.0);
        assert!(estimate_bits("qazwsxedc") > estimate_bits("qwertyuio"));
    }

    #[test]
    fn dates_are_cheap() {
        assert!(estimate_bits("19900101") < 16.0);
        assert!(estimate_bits("1987") < 8.0);
    }

    #[test]
    fn hangul_typed_on_a_qwerty_layout_is_weak() {
        assert!(estimate_bits("dkssud") < 20.0);
        assert!(weak("dkssud"));
        assert!(weak("dkssudgktpdy"));
        assert!(weak("dkssud1234"));
        assert!(estimate_bits("dkssudgktpdy") < estimate_bits("xqzjvkwpmhtb"));
    }

    #[test]
    fn hangul_text_and_korean_words_are_scored() {
        assert!(weak("안녕하세요"));
        assert!(weak("사랑해"));
        assert!(estimate_bits("꿈꾸는고래의아침") > 50.0);
    }

    #[test]
    fn random_mixed_passwords_are_strong() {
        assert!(estimate_bits("v8#Kq2!zRw9@Lm4x") > 70.0);
        assert!(!weak("v8#Kq2!zRw9@Lm4x"));
        assert!(!weak("correct-horse-battery-staple"));
    }

    #[test]
    fn long_inputs_are_bounded_and_empty_is_zero() {
        assert!(estimate_bits("").abs() < 1e-12);
        let long = "k7#Qx".repeat(500);
        assert!(estimate_bits(&long) > 200.0);
    }

    #[test]
    fn reasons_cover_length_class_and_guessability() {
        assert_eq!(
            weak_reasons("abc", 5.0),
            vec![
                WeakReason::TooShort,
                WeakReason::OneCharacterClass,
                WeakReason::Guessable
            ]
        );
        assert!(weak_reasons("Zq9#wLp2", 60.0).is_empty());
        assert_eq!(
            weak_reasons("abcdefghij", 60.0),
            vec![WeakReason::OneCharacterClass]
        );
    }

    #[test]
    fn classes_count_unicode_as_one() {
        assert_eq!(character_classes("aA1!한"), 5);
        assert_eq!(character_classes(""), 0);
    }
}
