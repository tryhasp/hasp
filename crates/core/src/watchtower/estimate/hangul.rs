const CHO: [&str; 19] = [
    "r", "R", "s", "e", "E", "f", "a", "q", "Q", "t", "T", "d", "w", "W", "c", "z", "x", "v", "g",
];
const JUNG: [&str; 21] = [
    "k", "o", "i", "O", "j", "p", "u", "P", "h", "hk", "ho", "hl", "y", "n", "nj", "np", "nl", "b",
    "m", "ml", "l",
];
const JONG: [&str; 28] = [
    "", "r", "R", "rt", "s", "sw", "sg", "e", "f", "fr", "fa", "fq", "ft", "fx", "fv", "fg", "a",
    "q", "qt", "t", "T", "d", "w", "c", "z", "x", "v", "g",
];
const SHIFTED: &str = "REQTWOP";
const SYLLABLE_BASE: u32 = 0xAC00;
const JUNG_COUNT: u32 = 21;
const JONG_COUNT: u32 = 28;

pub(super) fn is_syllable(c: char) -> bool {
    ('\u{AC00}'..='\u{D7A3}').contains(&c)
}

pub(super) fn typed_form(word: &str) -> Option<String> {
    let mut out = String::new();
    for c in word.chars() {
        let index = u32::from(c).checked_sub(SYLLABLE_BASE)?;
        if !is_syllable(c) {
            return None;
        }
        let tail = index % JONG_COUNT;
        let vowel = (index / JONG_COUNT) % JUNG_COUNT;
        let lead = index / (JONG_COUNT * JUNG_COUNT);
        out.push_str(CHO.get(usize::try_from(lead).ok()?)?);
        out.push_str(JUNG.get(usize::try_from(vowel).ok()?)?);
        out.push_str(JONG.get(usize::try_from(tail).ok()?)?);
    }
    Some(out)
}

pub(super) fn syllables_typed_on_qwerty(letters: &[char]) -> Option<usize> {
    let keys: Vec<char> = letters
        .iter()
        .map(|&c| {
            if c.is_ascii_uppercase() && !SHIFTED.contains(c) {
                c.to_ascii_lowercase()
            } else {
                c
            }
        })
        .collect();
    parse(&keys)
}

fn parse(keys: &[char]) -> Option<usize> {
    if keys.is_empty() {
        return Some(0);
    }
    let after_cho = keys.get(1..)?;
    if !CHO.iter().any(|cho| starts_with(keys, cho)) {
        return None;
    }
    for vowel in JUNG.iter().rev().filter(|v| starts_with(after_cho, v)) {
        let after_vowel = after_cho.get(vowel.len()..)?;
        for final_ in JONG.iter().rev().filter(|f| starts_with(after_vowel, f)) {
            if let Some(rest) = after_vowel.get(final_.len()..)
                && let Some(count) = parse(rest)
            {
                return count.checked_add(1);
            }
        }
    }
    None
}

fn starts_with(keys: &[char], pattern: &str) -> bool {
    let mut remaining = keys.iter();
    pattern.chars().all(|p| remaining.next() == Some(&p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(text: &str) -> Vec<char> {
        text.chars().collect()
    }

    #[test]
    fn composes_the_two_set_keyboard_layout() {
        assert_eq!(typed_form("안녕").unwrap(), "dkssud");
        assert_eq!(typed_form("안녕하세요").unwrap(), "dkssudgktpdy");
        assert_eq!(typed_form("사랑해").unwrap(), "tkfkdgo");
        assert_eq!(typed_form("닭").unwrap(), "ekfr");
        assert_eq!(typed_form("의").unwrap(), "dml");
    }

    #[test]
    fn counts_syllables_of_latin_typed_hangul() {
        assert_eq!(syllables_typed_on_qwerty(&typed("dkssud")), Some(2));
        assert_eq!(syllables_typed_on_qwerty(&typed("dkssudgktpdy")), Some(5));
        assert_eq!(syllables_typed_on_qwerty(&typed("Rhkrtk")), Some(2));
    }

    #[test]
    fn rejects_text_that_is_not_hangul_on_qwerty() {
        assert_eq!(syllables_typed_on_qwerty(&typed("hello")), None);
        assert_eq!(syllables_typed_on_qwerty(&typed("zxcv")), None);
        assert_eq!(syllables_typed_on_qwerty(&typed("")), Some(0));
    }

    #[test]
    fn typed_form_refuses_non_syllables() {
        assert_eq!(typed_form("abc"), None);
        assert_eq!(typed_form("ㄱ"), None);
    }
}
