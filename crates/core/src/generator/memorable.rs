use secrecy::SecretString;

use crate::generator::GeneratorError;
use crate::generator::entropy::{Entropy, below, index};

const BUNDLED: &str = include_str!("eff_large_wordlist.txt");
const WORD_COUNT: usize = 7776;
const MIN_WORDS: u32 = 3;
const MAX_WORDS: u32 = 16;
const MAX_SEPARATOR_CHARS: usize = 4;

#[derive(Debug)]
pub struct Wordlist {
    words: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemorableOptions {
    pub words: u32,
    pub separator: String,
    pub capitalize: bool,
    pub append_digit: bool,
}

impl Wordlist {
    pub fn bundled() -> Result<Self, GeneratorError> {
        Self::parse(BUNDLED)
    }

    fn parse(text: &'static str) -> Result<Self, GeneratorError> {
        let mut words = Vec::with_capacity(WORD_COUNT);
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let (dice, word) = line.split_once('\t').ok_or(GeneratorError::Wordlist)?;
            let valid_dice = dice.len() == 5 && dice.bytes().all(|b| (b'1'..=b'6').contains(&b));
            let valid_word =
                !word.is_empty() && word.bytes().all(|b| b.is_ascii_lowercase() || b == b'-');
            if !valid_dice || !valid_word {
                return Err(GeneratorError::Wordlist);
            }
            words.push(word);
        }
        if words.len() != WORD_COUNT {
            return Err(GeneratorError::Wordlist);
        }
        Ok(Self { words })
    }

    pub fn len(&self) -> usize {
        self.words.len()
    }

    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    pub fn contains(&self, word: &str) -> bool {
        self.words.contains(&word)
    }
}

impl MemorableOptions {
    pub fn standard() -> Self {
        Self {
            words: 5,
            separator: "-".to_owned(),
            capitalize: false,
            append_digit: false,
        }
    }

    fn validate(&self) -> Result<(), GeneratorError> {
        if !(MIN_WORDS..=MAX_WORDS).contains(&self.words) {
            return Err(GeneratorError::Options("word count"));
        }
        if self.separator.chars().count() > MAX_SEPARATOR_CHARS
            || self.separator.chars().any(char::is_control)
        {
            return Err(GeneratorError::Options("separator"));
        }
        Ok(())
    }

    pub fn entropy_bits(&self, list: &Wordlist) -> f64 {
        let per_word = f64::from(u32::try_from(list.len()).unwrap_or(u32::MAX)).log2();
        let digit = if self.append_digit { 10f64.log2() } else { 0.0 };
        per_word * f64::from(self.words) + digit
    }
}

pub fn memorable<E: Entropy + ?Sized>(
    entropy: &mut E,
    list: &Wordlist,
    options: &MemorableOptions,
) -> Result<SecretString, GeneratorError> {
    options.validate()?;
    let mut parts: Vec<String> =
        Vec::with_capacity(usize::try_from(options.words).unwrap_or(0) + 1);
    for _ in 0..options.words {
        let word = list
            .words
            .get(index(entropy, list.words.len())?)
            .ok_or(GeneratorError::Wordlist)?;
        parts.push(if options.capitalize {
            capitalise(word)
        } else {
            (*word).to_owned()
        });
    }
    let mut password = parts.join(&options.separator);
    if options.append_digit {
        password.push(char::from(
            b'0' + u8::try_from(below(entropy, 10)?).unwrap_or(0),
        ));
    }
    Ok(SecretString::from(password))
}

fn capitalise(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;
    use crate::generator::entropy::testing::SeededEntropy;

    fn list() -> Wordlist {
        Wordlist::bundled().unwrap()
    }

    #[test]
    fn bundled_list_is_the_eff_large_list() {
        let list = list();
        assert_eq!(list.len(), 7776);
        assert!(list.contains("abacus") && list.contains("zoning") && list.contains("yo-yo"));
        assert_eq!(list.words.first().copied(), Some("abacus"));
        assert_eq!(list.words.last().copied(), Some("zoom"));
    }

    #[test]
    fn standard_passphrase_has_five_listed_words() {
        let list = list();
        let pw = memorable(
            &mut SeededEntropy::new(11),
            &list,
            &MemorableOptions::standard(),
        )
        .unwrap();
        let text = pw.expose_secret();
        let words: Vec<&str> = text.split('-').collect();
        assert!(words.len() >= 5);
        assert!(text.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
    }

    #[test]
    fn options_shape_the_output() {
        let list = list();
        let options = MemorableOptions {
            words: 4,
            separator: " ".to_owned(),
            capitalize: true,
            append_digit: true,
        };
        let pw = memorable(&mut SeededEntropy::new(2), &list, &options).unwrap();
        let text = pw.expose_secret();
        assert!(text.chars().last().unwrap().is_ascii_digit());
        assert!(
            text.split(' ')
                .all(|w| w.chars().next().unwrap().is_ascii_uppercase())
        );
        assert_eq!(text.split(' ').count(), 4);
    }

    #[test]
    fn rejects_bad_options() {
        let list = list();
        for options in [
            MemorableOptions {
                words: 2,
                ..MemorableOptions::standard()
            },
            MemorableOptions {
                words: 17,
                ..MemorableOptions::standard()
            },
            MemorableOptions {
                separator: "-----".to_owned(),
                ..MemorableOptions::standard()
            },
            MemorableOptions {
                separator: "\n".to_owned(),
                ..MemorableOptions::standard()
            },
        ] {
            assert!(memorable(&mut SeededEntropy::new(1), &list, &options).is_err());
        }
    }

    #[test]
    fn entropy_matches_word_count() {
        let list = list();
        let bits = MemorableOptions::standard().entropy_bits(&list);
        assert!((bits - 64.62).abs() < 0.01, "{bits}");
        let with_digit = MemorableOptions {
            append_digit: true,
            ..MemorableOptions::standard()
        };
        assert!((with_digit.entropy_bits(&list) - bits - 3.32).abs() < 0.01);
    }

    #[test]
    fn malformed_lists_are_rejected() {
        assert!(Wordlist::parse("11111\tabacus\n").is_err());
        assert!(Wordlist::parse("garbage").is_err());
    }
}
