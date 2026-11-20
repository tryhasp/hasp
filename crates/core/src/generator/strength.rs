const LOWER_POOL: u32 = 26;
const UPPER_POOL: u32 = 26;
const DIGIT_POOL: u32 = 10;
const SYMBOL_POOL: u32 = 33;
const OTHER_POOL: u32 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    VeryWeak,
    Weak,
    Fair,
    Strong,
    VeryStrong,
}

impl Strength {
    pub fn from_bits(bits: f64) -> Self {
        match bits {
            b if b < 28.0 => Self::VeryWeak,
            b if b < 36.0 => Self::Weak,
            b if b < 60.0 => Self::Fair,
            b if b < 100.0 => Self::Strong,
            _ => Self::VeryStrong,
        }
    }
}

pub fn uniform_bits(alphabet_len: usize, length: usize) -> f64 {
    let alphabet = f64::from(u32::try_from(alphabet_len).unwrap_or(u32::MAX));
    let length = f64::from(u32::try_from(length).unwrap_or(u32::MAX));
    if alphabet < 2.0 {
        0.0
    } else {
        alphabet.log2() * length
    }
}

pub fn estimate_bits(password: &str) -> f64 {
    let (mut lower, mut upper, mut digit, mut symbol, mut other) =
        (false, false, false, false, false);
    for c in password.chars() {
        match c {
            'a'..='z' => lower = true,
            'A'..='Z' => upper = true,
            '0'..='9' => digit = true,
            ' '..='~' => symbol = true,
            _ => other = true,
        }
    }
    let pool: u32 = [
        (lower, LOWER_POOL),
        (upper, UPPER_POOL),
        (digit, DIGIT_POOL),
        (symbol, SYMBOL_POOL),
        (other, OTHER_POOL),
    ]
    .into_iter()
    .filter(|(present, _)| *present)
    .map(|(_, size)| size)
    .sum();
    let alphabet = usize::try_from(pool).unwrap_or(0);
    uniform_bits(alphabet, password.chars().count())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_bits_is_length_times_log2() {
        assert!((uniform_bits(62, 20) - 119.08).abs() < 0.01);
        assert!(uniform_bits(1, 20).abs() < 1e-12);
        assert!(uniform_bits(0, 20).abs() < 1e-12);
    }

    #[test]
    fn estimate_uses_the_classes_present() {
        assert!((estimate_bits("abcdefgh") - 8.0 * 26f64.log2()).abs() < 1e-9);
        assert!((estimate_bits("aA1!") - 4.0 * 95f64.log2()).abs() < 1e-9);
        assert!(estimate_bits("").abs() < 1e-12);
        assert!(estimate_bits("\u{d55c}") > 0.0);
    }

    #[test]
    fn strength_bands() {
        assert_eq!(Strength::from_bits(10.0), Strength::VeryWeak);
        assert_eq!(Strength::from_bits(30.0), Strength::Weak);
        assert_eq!(Strength::from_bits(40.0), Strength::Fair);
        assert_eq!(Strength::from_bits(80.0), Strength::Strong);
        assert_eq!(Strength::from_bits(128.0), Strength::VeryStrong);
        assert!(Strength::Strong > Strength::Weak);
    }
}
