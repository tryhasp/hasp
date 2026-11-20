use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::generator::GeneratorError;
use crate::generator::entropy::{Entropy, index, shuffle};
use crate::generator::rules::{FieldConstraints, PasswordRules, class, longest_run};

pub const SAFE_SYMBOLS: &str = "!@#$%^&*";
pub const AMBIGUOUS: &str = "Il1O0o|";
const MAX_LENGTH: u32 = 1024;
const MAX_ATTEMPTS: u32 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Symbols {
    None,
    Only(String),
    AllPrintable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classes {
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RandomOptions {
    pub length: u32,
    pub classes: Classes,
    pub symbols: Symbols,
    pub exclude_ambiguous: bool,
}

impl RandomOptions {
    pub fn standard() -> Self {
        Self {
            length: 20,
            classes: Classes {
                lower: true,
                upper: true,
                digits: true,
            },
            symbols: Symbols::Only(SAFE_SYMBOLS.to_owned()),
            exclude_ambiguous: false,
        }
    }

    pub fn korean_safe() -> Self {
        Self {
            length: 16,
            exclude_ambiguous: true,
            ..Self::standard()
        }
    }

    pub fn rules(&self) -> Result<PasswordRules, GeneratorError> {
        let mut allowed = std::collections::BTreeSet::new();
        let mut required = Vec::new();
        let classes = [
            (self.classes.lower, "lower"),
            (self.classes.upper, "upper"),
            (self.classes.digits, "digit"),
        ];
        for (enabled, name) in classes {
            if let (true, Some(set)) = (enabled, class(name)) {
                allowed.extend(set.iter().copied());
                required.push(set);
            }
        }
        let symbols: std::collections::BTreeSet<char> = match &self.symbols {
            Symbols::None => std::collections::BTreeSet::new(),
            Symbols::Only(chars) => chars.chars().collect(),
            Symbols::AllPrintable => class("special").unwrap_or_default(),
        };
        if !symbols.is_empty() {
            allowed.extend(symbols.iter().copied());
        }
        if allowed.is_empty() {
            return Err(GeneratorError::Options("no character class selected"));
        }
        let mut rules = PasswordRules::unrestricted();
        rules.allowed = allowed;
        rules.required = required;
        if self.exclude_ambiguous {
            rules = rules.forbidding(AMBIGUOUS.chars());
        }
        Ok(rules)
    }
}

pub fn random<E: Entropy + ?Sized>(
    entropy: &mut E,
    options: &RandomOptions,
    site: Option<&PasswordRules>,
    field: FieldConstraints,
) -> Result<SecretString, GeneratorError> {
    let base = match site {
        Some(rules) => rules.clone(),
        None => options.rules()?,
    };
    let rules = base.with_field(field);
    from_rules(entropy, &rules, options.length)
}

pub fn from_rules<E: Entropy + ?Sized>(
    entropy: &mut E,
    rules: &PasswordRules,
    preferred_length: u32,
) -> Result<SecretString, GeneratorError> {
    let alphabet = rules.alphabet();
    if alphabet.is_empty() {
        return Err(GeneratorError::Unsatisfiable("empty alphabet"));
    }
    let mut required: Vec<Vec<char>> = Vec::with_capacity(rules.required.len());
    for set in &rules.required {
        let usable: Vec<char> = alphabet
            .iter()
            .copied()
            .filter(|c| set.contains(c))
            .collect();
        if usable.is_empty() {
            return Err(GeneratorError::Unsatisfiable(
                "required class has no usable character",
            ));
        }
        required.push(usable);
    }
    let required_count = u32::try_from(required.len())
        .map_err(|_| GeneratorError::Unsatisfiable("too many required classes"))?;
    let min = rules.min_length.max(required_count).max(1);
    let max = rules.max_length.unwrap_or(MAX_LENGTH).min(MAX_LENGTH);
    if min > max {
        return Err(GeneratorError::Unsatisfiable("length bounds"));
    }
    let length = preferred_length.clamp(min, max);
    let length_usize =
        usize::try_from(length).map_err(|_| GeneratorError::Unsatisfiable("length bounds"))?;
    if alphabet.len() == 1 && rules.max_consecutive.is_some_and(|m| length > m) {
        return Err(GeneratorError::Unsatisfiable(
            "max-consecutive with one character",
        ));
    }
    for _ in 0..MAX_ATTEMPTS {
        let mut chars: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(length_usize));
        for usable in &required {
            chars.push(pick(entropy, usable)?);
        }
        while chars.len() < length_usize {
            chars.push(pick(entropy, &alphabet)?);
        }
        shuffle(entropy, chars.as_mut_slice())?;
        let candidate: String = chars.iter().collect();
        if rules
            .max_consecutive
            .is_some_and(|m| longest_run(&candidate) > m)
        {
            continue;
        }
        if !rules.accepts(&candidate) {
            return Err(GeneratorError::Unsatisfiable(
                "generated value violates rules",
            ));
        }
        return Ok(SecretString::from(candidate));
    }
    Err(GeneratorError::Unsatisfiable(
        "max-consecutive attempts exhausted",
    ))
}

fn pick<E: Entropy + ?Sized>(entropy: &mut E, from: &[char]) -> Result<char, GeneratorError> {
    from.get(index(entropy, from.len())?)
        .copied()
        .ok_or(GeneratorError::Unsatisfiable("empty alphabet"))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use secrecy::ExposeSecret;

    use super::*;
    use crate::generator::entropy::{OsEntropy, testing::SeededEntropy};

    const NONE: FieldConstraints = FieldConstraints {
        min_length: None,
        max_length: None,
    };

    fn text(secret: &SecretString) -> String {
        secret.expose_secret().to_owned()
    }

    #[test]
    fn standard_options_make_a_mixed_password_of_twenty() {
        let pw = text(&random(&mut OsEntropy, &RandomOptions::standard(), None, NONE).unwrap());
        assert_eq!(pw.chars().count(), 20);
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn korean_safe_preset_uses_only_listed_symbols_and_no_ambiguous() {
        let options = RandomOptions::korean_safe();
        for seed in 0..200 {
            let pw = text(&random(&mut SeededEntropy::new(seed), &options, None, NONE).unwrap());
            assert_eq!(pw.chars().count(), 16);
            assert!(
                pw.chars()
                    .all(|c| c.is_ascii_alphanumeric() || SAFE_SYMBOLS.contains(c))
            );
            assert!(!pw.chars().any(|c| AMBIGUOUS.contains(c)), "{pw}");
        }
    }

    #[test]
    fn field_attributes_beat_requested_length() {
        let options = RandomOptions::standard();
        let field = FieldConstraints {
            min_length: None,
            max_length: Some(12),
        };
        assert_eq!(
            text(&random(&mut OsEntropy, &options, None, field).unwrap()).len(),
            12
        );
        let field = FieldConstraints {
            min_length: Some(30),
            max_length: None,
        };
        assert_eq!(
            text(&random(&mut OsEntropy, &options, None, field).unwrap()).len(),
            30
        );
    }

    #[test]
    fn site_rules_replace_the_option_charset() {
        let rules = PasswordRules::parse(
            "minlength: 8; maxlength: 10; required: digit; allowed: upper; max-consecutive: 2",
        );
        for seed in 0..100 {
            let pw = text(
                &random(
                    &mut SeededEntropy::new(seed),
                    &RandomOptions::standard(),
                    Some(&rules),
                    NONE,
                )
                .unwrap(),
            );
            assert!(rules.accepts(&pw), "{pw}");
            assert_eq!(pw.len(), 10);
        }
    }

    #[test]
    fn reports_unsatisfiable_rules() {
        let cases = [
            "minlength: 12; maxlength: 8",
            "maxlength: 2; required: lower; required: upper; required: digit",
            "allowed: [a]; max-consecutive: 1; minlength: 4",
        ];
        for text in cases {
            let rules = PasswordRules::parse(text);
            assert!(from_rules(&mut OsEntropy, &rules, 20).is_err(), "{text}");
        }
        let rules = PasswordRules::parse("required: [ ]");
        assert!(from_rules(&mut OsEntropy, &rules, 20).is_err());
        let rules = PasswordRules::parse("required: digit").forbidding('0'..='9');
        assert!(from_rules(&mut OsEntropy, &rules, 20).is_err());
    }

    #[test]
    fn rejects_options_without_any_class() {
        let options = RandomOptions {
            classes: Classes {
                lower: false,
                upper: false,
                digits: false,
            },
            symbols: Symbols::None,
            ..RandomOptions::standard()
        };
        assert!(random(&mut OsEntropy, &options, None, NONE).is_err());
    }

    #[test]
    fn tight_max_consecutive_on_small_alphabet_still_terminates() {
        let rules = PasswordRules::parse("allowed: [ab]; max-consecutive: 1; minlength: 12");
        let pw = text(&from_rules(&mut SeededEntropy::new(3), &rules, 12).unwrap());
        assert!(rules.accepts(&pw), "{pw}");
    }

    #[test]
    fn every_bundled_apple_rule_is_satisfiable() {
        let map: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>> =
            serde_json::from_str(include_str!(
                "../../../../data/sites/apple/password-rules.json"
            ))
            .unwrap();
        for (domain, entry) in &map {
            let rules = PasswordRules::parse(&entry["password-rules"]);
            for seed in 0..5 {
                let pw = from_rules(&mut SeededEntropy::new(seed), &rules, 20)
                    .unwrap_or_else(|e| panic!("{domain}: {e}"));
                assert!(rules.accepts(pw.expose_secret()), "{domain}");
            }
        }
    }

    fn arb_rules() -> impl Strategy<Value = PasswordRules> {
        let classes = prop::sample::subsequence(vec!["lower", "upper", "digit", "special"], 0..=4);
        let custom = prop::option::of(prop::sample::select(vec![
            "[!@#]", "[-_.]", "[xyz]", "[0-3]",
        ]));
        (
            classes,
            custom,
            0u32..24,
            prop::option::of(8u32..40),
            prop::option::of(1u32..4),
            prop::bool::ANY,
        )
            .prop_map(|(classes, custom, min, max, consecutive, allow_all)| {
                let mut parts: Vec<String> =
                    classes.iter().map(|c| format!("required: {c}")).collect();
                parts.extend(custom.map(|c| format!("required: {c}")));
                if allow_all {
                    parts.push("allowed: ascii-printable".to_owned());
                }
                parts.push(format!("minlength: {min}"));
                parts.extend(max.map(|m| format!("maxlength: {m}")));
                parts.extend(consecutive.map(|c| format!("max-consecutive: {c}")));
                PasswordRules::parse(&parts.join("; "))
            })
    }

    proptest! {
        #[test]
        fn generated_passwords_always_satisfy_the_rules(
            rules in arb_rules(),
            preferred in 1u32..64,
            field_max in prop::option::of(6u32..48),
            seed in any::<u64>(),
        ) {
            let rules = rules.with_field(FieldConstraints { min_length: None, max_length: field_max });
            match from_rules(&mut SeededEntropy::new(seed), &rules, preferred) {
                Ok(pw) => prop_assert!(rules.accepts(pw.expose_secret()), "{}", pw.expose_secret()),
                Err(GeneratorError::Unsatisfiable(_)) => {
                    let min = rules.min_length.max(u32::try_from(rules.required.len()).unwrap());
                    prop_assert!(rules.max_length.is_some_and(|m| m < min) || rules.max_consecutive.is_some());
                }
                Err(other) => prop_assert!(false, "{other}"),
            }
        }

        #[test]
        fn option_driven_passwords_satisfy_their_own_rules(
            length in 4u32..80,
            lower in any::<bool>(),
            upper in any::<bool>(),
            digits in any::<bool>(),
            ambiguous in any::<bool>(),
            seed in any::<u64>(),
        ) {
            let options = RandomOptions { length, classes: Classes { lower, upper, digits }, symbols: Symbols::Only(SAFE_SYMBOLS.to_owned()), exclude_ambiguous: ambiguous };
            let pw = random(&mut SeededEntropy::new(seed), &options, None, NONE).unwrap();
            let rules = options.rules().unwrap();
            prop_assert!(rules.accepts(pw.expose_secret()));
            prop_assert_eq!(pw.expose_secret().chars().count(), usize::try_from(length).unwrap());
        }
    }
}
