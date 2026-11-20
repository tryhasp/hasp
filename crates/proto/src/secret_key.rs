use core::fmt;

use hasp_crypto::{SecretBytes, ct_eq, fill_random, sha256};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::ProtoError;

pub const SECRET_SYMBOLS: usize = 26;
const CHECK_SYMBOLS: usize = 4;
const GROUP: usize = 5;
const BASE: u32 = 31;
const CHECK_MODULUS: u32 = 923_521;
const REJECTION_BOUND: u8 = 248;
const CHECK_LABEL: &[u8] = b"hasp/v1/sk-check";
const ALPHABET: &[u8; 31] = b"23456789ABCDEFGHJKLMNPQRSTVWXYZ";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretKind {
    SecretKey,
    RecoveryCode,
}

impl SecretKind {
    fn tag(self) -> &'static str {
        match self {
            Self::SecretKey => "V1",
            Self::RecoveryCode => "R1",
        }
    }

    fn from_tag(tag: &str) -> Result<Self, ProtoError> {
        match tag {
            "V1" => Ok(Self::SecretKey),
            "R1" => Ok(Self::RecoveryCode),
            _ => Err(ProtoError::Format),
        }
    }
}

pub struct SecretAscii(SecretBytes);

impl SecretAscii {
    pub fn generate() -> Result<Self, ProtoError> {
        let mut symbols = Vec::with_capacity(SECRET_SYMBOLS);
        while symbols.len() < SECRET_SYMBOLS {
            let mut pool = Zeroizing::new([0_u8; 64]);
            fill_random(pool.as_mut_slice())?;
            for &byte in pool.iter() {
                if byte < REJECTION_BOUND && symbols.len() < SECRET_SYMBOLS {
                    let index = byte
                        .checked_rem(31)
                        .ok_or(ProtoError::Internal("alphabet"))?;
                    symbols.push(symbol(index)?);
                }
            }
        }
        Ok(Self(SecretBytes::from_vec(symbols)))
    }

    pub fn from_ascii(ascii: &[u8]) -> Result<Self, ProtoError> {
        if ascii.len() != SECRET_SYMBOLS || ascii.iter().any(|byte| index_of(*byte).is_none()) {
            return Err(ProtoError::Format);
        }
        Ok(Self(SecretBytes::from_vec(ascii.to_vec())))
    }

    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }
}

impl fmt::Debug for SecretAscii {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretAscii(..)")
    }
}

pub struct SecretText(SecretString);

impl SecretText {
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretText(..)")
    }
}

/// Formats 26 secret symbols plus 4 check symbols.
///
/// ```
/// use hasp_proto::{SecretAscii, SecretKind, encode_secret_key, parse_secret_key};
///
/// let secret = SecretAscii::from_ascii(b"ABCDEFGHJKLMNPQRSTVWXYZ234")?;
/// let text = encode_secret_key(SecretKind::SecretKey, &secret)?;
/// assert!(text.expose().starts_with("V1-ABCDE-"));
/// let (kind, parsed) = parse_secret_key(text.expose())?;
/// assert_eq!(kind, SecretKind::SecretKey);
/// assert_eq!(parsed.expose(), secret.expose());
/// # Ok::<(), hasp_proto::ProtoError>(())
/// ```
pub fn encode_secret_key(kind: SecretKind, secret: &SecretAscii) -> Result<SecretText, ProtoError> {
    let check = check_symbols(kind, secret.expose())?;
    let mut flat = Zeroizing::new(String::with_capacity(
        SECRET_SYMBOLS
            .saturating_add(CHECK_SYMBOLS)
            .saturating_add(8),
    ));
    flat.push_str(kind.tag());
    for (i, &byte) in secret.expose().iter().chain(check.iter()).enumerate() {
        if i % GROUP == 0 {
            flat.push('-');
        }
        flat.push(char::from(byte));
    }
    Ok(SecretText(SecretString::from(flat.as_str())))
}

pub fn parse_secret_key(text: &str) -> Result<(SecretKind, SecretAscii), ProtoError> {
    let normalized: Zeroizing<String> = Zeroizing::new(
        text.chars()
            .filter(|ch| *ch != '-' && !ch.is_whitespace())
            .map(|ch| ch.to_ascii_uppercase())
            .collect(),
    );
    let (tag, symbols) = normalized.split_at_checked(2).ok_or(ProtoError::Format)?;
    let kind = SecretKind::from_tag(tag)?;
    if symbols.len() != SECRET_SYMBOLS.saturating_add(CHECK_SYMBOLS) {
        return Err(ProtoError::Format);
    }
    let (secret, check) = symbols
        .as_bytes()
        .split_at_checked(SECRET_SYMBOLS)
        .ok_or(ProtoError::Format)?;
    let secret = SecretAscii::from_ascii(secret)?;
    let expected = check_symbols(kind, secret.expose())?;
    if !ct_eq(check, &expected) {
        return Err(ProtoError::Format);
    }
    Ok((kind, secret))
}

fn check_symbols(kind: SecretKind, secret: &[u8]) -> Result<[u8; CHECK_SYMBOLS], ProtoError> {
    let digest = sha256(&[CHECK_LABEL, kind.tag().as_bytes(), secret]);
    let word = digest
        .first_chunk::<4>()
        .ok_or(ProtoError::Internal("digest"))?;
    let mut value = u32::from_be_bytes(*word)
        .checked_rem(CHECK_MODULUS)
        .ok_or(ProtoError::Internal("modulus"))?;
    let mut out = [0_u8; CHECK_SYMBOLS];
    for slot in out.iter_mut().rev() {
        let digit = u8::try_from(
            value
                .checked_rem(BASE)
                .ok_or(ProtoError::Internal("base"))?,
        )
        .map_err(|_| ProtoError::Internal("digit"))?;
        *slot = symbol(digit)?;
        value = value
            .checked_div(BASE)
            .ok_or(ProtoError::Internal("base"))?;
    }
    Ok(out)
}

fn symbol(index: u8) -> Result<u8, ProtoError> {
    ALPHABET
        .get(usize::from(index))
        .copied()
        .ok_or(ProtoError::Internal("alphabet"))
}

fn index_of(byte: u8) -> Option<usize> {
    ALPHABET.iter().position(|candidate| *candidate == byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8; 26] = b"ABCDEFGHJKLMNPQRSTVWXYZ234";

    #[test]
    fn encodes_prefix_six_groups_and_check_symbols() {
        let secret = SecretAscii::from_ascii(SAMPLE).unwrap();
        let text = encode_secret_key(SecretKind::SecretKey, &secret).unwrap();
        let shown = text.expose();
        assert!(shown.starts_with("V1-ABCDE-FGHJK-LMNPQ-RSTVW-XYZ23-4"));
        assert_eq!(shown.len(), 2 + 6 * 6);
        assert_eq!(shown.split('-').count(), 7);
    }

    #[test]
    fn parse_roundtrips_both_kinds() {
        for kind in [SecretKind::SecretKey, SecretKind::RecoveryCode] {
            let secret = SecretAscii::from_ascii(SAMPLE).unwrap();
            let text = encode_secret_key(kind, &secret).unwrap();
            let (parsed_kind, parsed) = parse_secret_key(text.expose()).unwrap();
            assert_eq!(parsed_kind, kind);
            assert_eq!(parsed.expose(), SAMPLE);
        }
    }

    #[test]
    fn kinds_have_different_check_symbols() {
        let secret = SecretAscii::from_ascii(SAMPLE).unwrap();
        let a = encode_secret_key(SecretKind::SecretKey, &secret).unwrap();
        let b = encode_secret_key(SecretKind::RecoveryCode, &secret).unwrap();
        assert_ne!(a.expose().strip_prefix("V1"), b.expose().strip_prefix("R1"));
    }

    #[test]
    fn parse_accepts_lowercase_and_loose_separators() {
        let secret = SecretAscii::from_ascii(SAMPLE).unwrap();
        let text = encode_secret_key(SecretKind::SecretKey, &secret).unwrap();
        let loose = text.expose().to_lowercase().replace('-', " ");
        assert!(parse_secret_key(&loose).is_ok());
    }

    #[test]
    fn parse_rejects_every_single_symbol_typo() {
        let secret = SecretAscii::from_ascii(SAMPLE).unwrap();
        let text = encode_secret_key(SecretKind::SecretKey, &secret).unwrap();
        let original: Vec<char> = text.expose().chars().collect();
        for i in (0..original.len()).filter(|i| original[*i] != '-' && *i >= 2) {
            for &replacement in ALPHABET {
                let replacement = char::from(replacement);
                if replacement == original[i] {
                    continue;
                }
                let mut mutated = original.clone();
                mutated[i] = replacement;
                let mutated: String = mutated.into_iter().collect();
                assert!(parse_secret_key(&mutated).is_err(), "{mutated}");
            }
        }
    }

    #[test]
    fn parse_rejects_wrong_prefix_length_and_alphabet() {
        let secret = SecretAscii::from_ascii(SAMPLE).unwrap();
        let text = encode_secret_key(SecretKind::SecretKey, &secret).unwrap();
        let shown = text.expose();
        assert!(parse_secret_key(&shown.replacen("V1", "V2", 1)).is_err());
        let mut shorter = shown.to_owned();
        shorter.pop();
        assert!(parse_secret_key(&shorter).is_err());
        assert!(parse_secret_key(&format!("{shown}2")).is_err());
        assert!(parse_secret_key(&shown.replacen('A', "0", 1)).is_err());
        assert!(parse_secret_key("").is_err());
        assert!(parse_secret_key("V").is_err());
    }

    #[test]
    fn from_ascii_rejects_bad_length_and_symbols() {
        assert!(SecretAscii::from_ascii(&SAMPLE[..25]).is_err());
        let mut bad = *SAMPLE;
        bad[3] = b'I';
        assert!(SecretAscii::from_ascii(&bad).is_err());
        bad[3] = b'a';
        assert!(SecretAscii::from_ascii(&bad).is_err());
    }

    #[test]
    fn generate_yields_alphabet_symbols_and_differs() {
        let a = SecretAscii::generate().unwrap();
        let b = SecretAscii::generate().unwrap();
        assert_eq!(a.expose().len(), SECRET_SYMBOLS);
        assert!(a.expose().iter().all(|byte| index_of(*byte).is_some()));
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn debug_is_redacted() {
        let secret = SecretAscii::from_ascii(SAMPLE).unwrap();
        assert_eq!(format!("{secret:?}"), "SecretAscii(..)");
        let text = encode_secret_key(SecretKind::SecretKey, &secret).unwrap();
        assert_eq!(format!("{text:?}"), "SecretText(..)");
    }
}
