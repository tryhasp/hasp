use secrecy::ExposeSecret;

use super::engine::Engine;
use super::{GeneratedPassword, GeneratorKind, GeneratorRequest, Secret, Strength};
use crate::CoreError;
use crate::generator::entropy::OsEntropy;
use crate::generator::memorable::{MemorableOptions, memorable};
use crate::generator::pin::{pin, pin_entropy_bits};
use crate::generator::random::{Classes, RandomOptions, Symbols, random};
use crate::generator::rules::{FieldConstraints, PasswordRules};
use crate::generator::strength::{self, estimate_bits};
use crate::matcher::origin::Origin;
use crate::store::Store;
use crate::transport::Transport;

fn strength_of(bits: f64) -> Strength {
    match strength::Strength::from_bits(bits) {
        strength::Strength::VeryWeak => Strength::VeryWeak,
        strength::Strength::Weak => Strength::Weak,
        strength::Strength::Fair => Strength::Fair,
        strength::Strength::Strong => Strength::Strong,
        strength::Strength::VeryStrong => Strength::VeryStrong,
    }
}

impl<T: Transport, S: Store> Engine<T, S> {
    /// Rule order: the field's own limits, then the site's password rules (given
    /// text, else the dataset entry for the origin), then the options.
    pub fn generate(&self, request: &GeneratorRequest) -> Result<GeneratedPassword, CoreError> {
        let mut entropy = OsEntropy;
        let (password, bits, applied) = match request.kind {
            GeneratorKind::Memorable => {
                let options = MemorableOptions {
                    words: request.words,
                    separator: request.separator.clone(),
                    capitalize: request.capitalize,
                    append_digit: request.append_digit,
                };
                (
                    memorable(&mut entropy, &self.wordlist, &options)?,
                    options.entropy_bits(&self.wordlist),
                    false,
                )
            }
            GeneratorKind::Pin => (
                pin(&mut entropy, request.length)?,
                pin_entropy_bits(request.length),
                false,
            ),
            GeneratorKind::Random | GeneratorKind::KoreanSafe => {
                let mut options = if request.kind == GeneratorKind::KoreanSafe {
                    RandomOptions::korean_safe()
                } else {
                    RandomOptions {
                        length: request.length,
                        classes: Classes {
                            lower: request.lower,
                            upper: request.upper,
                            digits: request.digits,
                        },
                        symbols: match request.symbols.as_deref() {
                            None => Symbols::None,
                            Some("") => Symbols::AllPrintable,
                            Some(set) => Symbols::Only(set.to_owned()),
                        },
                        exclude_ambiguous: request.exclude_ambiguous,
                    }
                };
                if request.kind == GeneratorKind::KoreanSafe && request.length > 0 {
                    options.length = request.length;
                }
                let site = self.site_rules(request);
                let field = FieldConstraints {
                    min_length: request.field_min_length,
                    max_length: request.field_max_length,
                };
                let password = random(&mut entropy, &options, site.as_ref(), field)?;
                let bits = estimate_bits(password.expose_secret());
                (password, bits, site.is_some())
            }
        };
        let value = password.expose_secret();
        Ok(GeneratedPassword {
            length: u32::try_from(value.chars().count()).unwrap_or(u32::MAX),
            value: Secret::new(value.as_bytes().to_vec()),
            bits,
            strength: strength_of(bits),
            site_rules_applied: applied,
        })
    }

    fn site_rules(&self, request: &GeneratorRequest) -> Option<PasswordRules> {
        if let Some(text) = &request.site_rules {
            return Some(PasswordRules::parse(text));
        }
        let host = Origin::parse(request.origin.as_deref()?)
            .ok()?
            .host_string();
        self.matcher
            .sites()
            .password_rules(&host)
            .map(PasswordRules::parse)
    }
}
