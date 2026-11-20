use std::collections::BTreeSet;

use crate::generator::GeneratorError;

const SPACE: char = ' ';
const ASCII_FIRST: u8 = 0x20;
const ASCII_LAST: u8 = 0x7e;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordRules {
    pub min_length: u32,
    pub max_length: Option<u32>,
    pub allowed: BTreeSet<char>,
    pub required: Vec<BTreeSet<char>>,
    pub max_consecutive: Option<u32>,
    pub forbidden: BTreeSet<char>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldConstraints {
    pub min_length: Option<u32>,
    pub max_length: Option<u32>,
}

#[derive(Debug)]
enum Rule {
    Allowed(Vec<BTreeSet<char>>),
    Required(Vec<BTreeSet<char>>),
    MaxConsecutive(u32),
    MinLength(u32),
    MaxLength(u32),
    Ignored,
}

struct Parser {
    input: Vec<char>,
    errors: u32,
}

pub(crate) fn ascii_printable() -> BTreeSet<char> {
    (ASCII_FIRST..=ASCII_LAST).map(char::from).collect()
}

pub(crate) fn class(name: &str) -> Option<BTreeSet<char>> {
    let range = |a: char, b: char| a..=b;
    match name.to_ascii_lowercase().as_str() {
        "upper" => Some(range('A', 'Z').collect()),
        "lower" => Some(range('a', 'z').collect()),
        "digit" => Some(range('0', '9').collect()),
        "special" => Some(
            ascii_printable()
                .into_iter()
                .filter(|c| !c.is_ascii_alphanumeric())
                .collect(),
        ),
        "ascii-printable" | "unicode" => Some(ascii_printable()),
        _ => None,
    }
}

impl PasswordRules {
    pub fn parse(text: &str) -> Self {
        Self::build(Parser::new(text).run().0)
    }

    pub fn parse_strict(text: &str) -> Result<Self, GeneratorError> {
        let (rules, errors) = Parser::new(text).run();
        if errors > 0 {
            return Err(GeneratorError::Rules("syntax"));
        }
        Ok(Self::build(rules))
    }

    pub fn unrestricted() -> Self {
        Self::build(Vec::new())
    }

    #[must_use]
    pub fn with_field(mut self, field: FieldConstraints) -> Self {
        if let Some(min) = field.min_length {
            self.min_length = self.min_length.max(min);
        }
        if let Some(max) = field.max_length {
            self.max_length = Some(self.max_length.map_or(max, |m| m.min(max)));
        }
        self
    }

    #[must_use]
    pub fn forbidding(mut self, chars: impl IntoIterator<Item = char>) -> Self {
        self.forbidden.extend(chars);
        self
    }

    pub fn alphabet(&self) -> Vec<char> {
        self.allowed
            .iter()
            .copied()
            .filter(|c| *c != SPACE && !self.forbidden.contains(c))
            .collect()
    }

    pub fn accepts(&self, candidate: &str) -> bool {
        let len = candidate.chars().count();
        let Ok(len) = u32::try_from(len) else {
            return false;
        };
        if len < self.min_length || self.max_length.is_some_and(|max| len > max) {
            return false;
        }
        if candidate
            .chars()
            .any(|c| !self.allowed.contains(&c) || self.forbidden.contains(&c))
        {
            return false;
        }
        if !self
            .required
            .iter()
            .all(|set| candidate.chars().any(|c| set.contains(&c)))
        {
            return false;
        }
        match self.max_consecutive {
            Some(max) => longest_run(candidate) <= max,
            None => true,
        }
    }

    fn build(rules: Vec<Rule>) -> Self {
        let mut min_length = 0;
        let mut max_length: Option<u32> = None;
        let mut max_consecutive: Option<u32> = None;
        let mut required = Vec::new();
        let mut allowed = BTreeSet::new();
        for rule in rules {
            match rule {
                Rule::MinLength(n) => min_length = min_length.max(n),
                Rule::MaxLength(n) => max_length = Some(max_length.map_or(n, |m| m.min(n))),
                Rule::MaxConsecutive(n) => {
                    max_consecutive = Some(max_consecutive.map_or(n, |m| m.min(n)));
                }
                Rule::Required(sets) => {
                    let union: BTreeSet<char> = sets.into_iter().flatten().collect();
                    allowed.extend(union.iter().copied());
                    required.push(union);
                }
                Rule::Allowed(sets) => allowed.extend(sets.into_iter().flatten()),
                Rule::Ignored => {}
            }
        }
        if allowed.is_empty() {
            allowed = ascii_printable();
        }
        Self {
            min_length,
            max_length,
            allowed,
            required,
            max_consecutive,
            forbidden: BTreeSet::new(),
        }
    }
}

pub(crate) fn longest_run(text: &str) -> u32 {
    let mut longest = 0u32;
    let mut run = 0u32;
    let mut previous = None;
    for c in text.chars() {
        run = if previous == Some(c) {
            run.saturating_add(1)
        } else {
            1
        };
        previous = Some(c);
        longest = longest.max(run);
    }
    longest
}

impl Parser {
    fn new(text: &str) -> Self {
        Self {
            input: text.chars().collect(),
            errors: 0,
        }
    }

    fn run(mut self) -> (Vec<Rule>, u32) {
        let rules = self.rules().unwrap_or_default();
        (rules, self.errors)
    }

    fn rules(&mut self) -> Option<Vec<Rule>> {
        let mut rules = Vec::new();
        let mut pos = self.skip_space(0);
        while pos < self.input.len() {
            if !self.at(pos).is_some_and(is_identifier_char) {
                self.errors += 1;
                return Some(rules);
            }
            let (rule, next) = self.rule(pos);
            if let Some(rule) = rule {
                rules.push(rule);
            }
            pos = self.skip_space(next);
            if pos >= self.input.len() {
                break;
            }
            if self.at(pos) == Some(';') {
                pos = self.skip_space(pos + 1);
                continue;
            }
            self.errors += 1;
            return None;
        }
        Some(rules)
    }

    fn rule(&mut self, start: usize) -> (Option<Rule>, usize) {
        let (name, mut pos) = self.identifier(start);
        let known = [
            "allowed",
            "required",
            "max-consecutive",
            "max-repeating",
            "max-sequential",
            "minlength",
            "maxlength",
        ];
        if !known.contains(&name.as_str()) {
            self.errors += 1;
            return (None, start);
        }
        if self.at(pos) != Some(':') {
            self.errors += 1;
            return (None, pos);
        }
        pos = self.skip_space(pos + 1);
        if pos >= self.input.len() || self.at(pos) == Some(';') {
            self.errors += 1;
            return (None, pos);
        }
        match name.as_str() {
            "allowed" | "required" => {
                let (sets, next) = self.class_list(pos);
                let rule = sets.map(|s| {
                    if name == "allowed" {
                        Rule::Allowed(s)
                    } else {
                        Rule::Required(s)
                    }
                });
                (rule, next)
            }
            _ => {
                let (value, next) = self.integer(pos);
                let rule = value.map(|n| match name.as_str() {
                    "max-consecutive" if n > 0 => Rule::MaxConsecutive(n),
                    "minlength" => Rule::MinLength(n),
                    "maxlength" => Rule::MaxLength(n),
                    _ => Rule::Ignored,
                });
                (rule, next)
            }
        }
    }

    fn class_list(&mut self, mut pos: usize) -> (Option<Vec<BTreeSet<char>>>, usize) {
        let mut sets = Vec::new();
        loop {
            match self.at(pos) {
                Some(c) if is_identifier_char(c) => {
                    let start = pos;
                    let (name, next) = self.identifier(pos);
                    let Some(set) = class(&name) else {
                        self.errors += 1;
                        return (None, start);
                    };
                    sets.push(set);
                    pos = next;
                }
                Some('[') => {
                    let (custom, next) = self.custom_class(pos);
                    if let Some(chars) = custom.filter(|c| !c.is_empty()) {
                        sets.push(chars);
                    }
                    pos = next;
                }
                _ => {
                    self.errors += 1;
                    return (None, pos);
                }
            }
            pos = self.skip_space(pos);
            if pos >= self.input.len() || self.at(pos) == Some(';') {
                break;
            }
            if self.at(pos) == Some(',') {
                pos = self.skip_space(pos + 1);
                if pos >= self.input.len() {
                    self.errors += 1;
                    return (None, pos);
                }
                continue;
            }
            self.errors += 1;
            return (None, pos);
        }
        (Some(sets), pos)
    }

    fn custom_class(&mut self, start: usize) -> (Option<BTreeSet<char>>, usize) {
        let len = self.input.len();
        let mut pos = start + 1;
        if pos >= len {
            self.errors += 1;
            return (None, pos);
        }
        let initial = pos;
        let mut chars = Vec::new();
        while pos < len {
            let c = self.input.get(pos).copied().unwrap_or(']');
            if !(' '..='~').contains(&c) {
                pos += 1;
                continue;
            }
            if c == '-' && pos > initial {
                self.errors += 1;
                pos += 1;
                continue;
            }
            chars.push(c);
            pos += 1;
            if c == ']' {
                break;
            }
        }
        let next_is_close = self.at(pos) == Some(']');
        let ended_on_close = pos == len && self.at(pos - 1) == Some(']');
        if (pos < len && !next_is_close) || ended_on_close {
            chars.pop();
            if let Some(next) = self.at(pos)
                && !is_space(next)
                && next != ','
                && next != ';'
            {
                self.errors += 1;
            }
            return (Some(chars.into_iter().collect()), pos);
        }
        if next_is_close {
            return (Some(chars.into_iter().collect()), pos + 1);
        }
        self.errors += 1;
        (None, pos)
    }

    fn integer(&mut self, start: usize) -> (Option<u32>, usize) {
        if !self.at(start).is_some_and(|c| c.is_ascii_digit()) {
            self.errors += 1;
            return (None, start);
        }
        let mut pos = start;
        let mut value: u64 = 0;
        let mut overflow = false;
        while let Some(digit) = self.at(pos).and_then(|c| c.to_digit(10)) {
            value = value.saturating_mul(10).saturating_add(u64::from(digit));
            if value > u64::from(u32::MAX) {
                overflow = true;
            }
            pos += 1;
        }
        let after = self.skip_space(pos);
        if overflow || !(after >= self.input.len() || self.at(after) == Some(';')) {
            self.errors += 1;
            return (None, after);
        }
        (u32::try_from(value).ok(), after)
    }

    fn identifier(&self, start: usize) -> (String, usize) {
        let mut pos = start;
        let mut name = String::new();
        while let Some(c) = self.at(pos).filter(|c| is_identifier_char(*c)) {
            name.push(c);
            pos += 1;
        }
        (name, pos)
    }

    fn skip_space(&self, mut pos: usize) -> usize {
        while self.at(pos).is_some_and(is_space) {
            pos += 1;
        }
        pos
    }

    fn at(&self, pos: usize) -> Option<char> {
        self.input.get(pos).copied()
    }
}

fn is_identifier_char(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '-'
}

fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\u{c}' | '\n' | '\r' | '\t')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(text: &str) -> BTreeSet<char> {
        text.chars().collect()
    }

    #[test]
    fn parses_lengths_and_classes() {
        let rules = PasswordRules::parse(
            "minlength: 8; maxlength: 16; required: lower, upper; required: digit; max-consecutive: 2;",
        );
        assert_eq!(rules.min_length, 8);
        assert_eq!(rules.max_length, Some(16));
        assert_eq!(rules.max_consecutive, Some(2));
        assert_eq!(rules.required.len(), 2);
        assert_eq!(rules.required[0].len(), 52);
        assert_eq!(rules.required[1], set("0123456789"));
        assert_eq!(rules.allowed.len(), 62);
    }

    #[test]
    fn custom_classes_follow_apple_escaping() {
        let rules = PasswordRules::parse("required: [-!#$%&'()*+/:;=?@[^_`{|}~]];");
        assert_eq!(rules.required[0], set("-!#$%&'()*+/:;=?@[^_`{|}~]"));
        let rules = PasswordRules::parse("allowed: [!#$%]; required: [a-];");
        assert_eq!(rules.allowed, set("!#$%a"));
    }

    #[test]
    fn allowed_defaults_to_required_union_then_ascii_printable() {
        assert_eq!(
            PasswordRules::parse("required: upper; required: digit")
                .allowed
                .len(),
            36
        );
        assert_eq!(
            PasswordRules::parse("minlength: 6").allowed,
            ascii_printable()
        );
        assert_eq!(
            PasswordRules::parse("allowed: unicode").allowed,
            ascii_printable()
        );
        assert_eq!(PasswordRules::parse("").allowed, ascii_printable());
    }

    #[test]
    fn special_matches_apple_definition() {
        let special = class("special").unwrap();
        assert_eq!(special.len(), 33);
        assert!(special.contains(&' ') && special.contains(&'~') && !special.contains(&'a'));
    }

    #[test]
    fn combines_repeated_properties_like_apple() {
        let rules = PasswordRules::parse(
            "minlength: 6; minlength: 10; maxlength: 30; maxlength: 20; max-consecutive: 3; max-consecutive: 2",
        );
        assert_eq!(
            (rules.min_length, rules.max_length, rules.max_consecutive),
            (10, Some(20), Some(2))
        );
    }

    #[test]
    fn names_and_classes_are_handled_like_apple() {
        let rules = PasswordRules::parse("required: UPPER, Digit");
        assert_eq!(rules.required[0].len(), 36);
        assert_eq!(
            PasswordRules::parse("max-repeating: 2; minlength: 9").min_length,
            9
        );
        assert_eq!(PasswordRules::parse("MINLENGTH: 9").min_length, 0);
    }

    #[test]
    fn tolerant_parse_drops_bad_values_and_strict_parse_rejects() {
        for text in [
            "minlength: abc",
            "required: bogus",
            "minlength: 8 maxlength: 9",
            "bogus: 3",
            "minlength:",
            "required: lower,",
        ] {
            assert!(PasswordRules::parse_strict(text).is_err(), "{text}");
        }
        assert_eq!(
            PasswordRules::parse("minlength: abc; maxlength: 12").max_length,
            None
        );
        assert_eq!(PasswordRules::parse("bogus: 3; minlength: 9").min_length, 0);
        assert!(
            PasswordRules::parse_strict("minlength: 8; maxlength: 16; required: lower;").is_ok()
        );
        assert!(PasswordRules::parse_strict("").is_ok());
    }

    #[test]
    fn field_attributes_tighten_site_rules() {
        let rules =
            PasswordRules::parse("minlength: 8; maxlength: 32").with_field(FieldConstraints {
                min_length: Some(10),
                max_length: Some(20),
            });
        assert_eq!((rules.min_length, rules.max_length), (10, Some(20)));
        let rules =
            PasswordRules::parse("minlength: 12; maxlength: 14").with_field(FieldConstraints {
                min_length: None,
                max_length: Some(40),
            });
        assert_eq!((rules.min_length, rules.max_length), (12, Some(14)));
    }

    #[test]
    fn accepts_checks_every_constraint() {
        let rules = PasswordRules::parse(
            "minlength: 6; maxlength: 8; required: upper; required: digit; allowed: lower; max-consecutive: 2",
        );
        assert!(rules.accepts("Abcde1"));
        assert!(!rules.accepts("Abc1"));
        assert!(!rules.accepts("Abcdefgh12"));
        assert!(!rules.accepts("abcdef1"));
        assert!(!rules.accepts("Abcdef!1"));
        assert!(!rules.accepts("Abbbcd1"));
        assert!(rules.accepts("Aabbcd1"));
    }

    #[test]
    fn longest_run_counts_identical_neighbours() {
        assert_eq!(longest_run(""), 0);
        assert_eq!(longest_run("abc"), 1);
        assert_eq!(longest_run("aabbbc"), 3);
    }

    #[test]
    fn every_bundled_apple_rule_parses_strictly_or_loudly() {
        let text = include_str!("../../../../data/sites/apple/password-rules.json");
        let map: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>> =
            serde_json::from_str(text).unwrap();
        for (domain, entry) in &map {
            let rules = entry.get("password-rules").unwrap();
            let parsed = PasswordRules::parse(rules);
            assert!(!parsed.allowed.is_empty(), "{domain}");
        }
    }
}
