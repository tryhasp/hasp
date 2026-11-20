use hasp_proto::ProtoError;
use icu_casemap::CaseMapperBorrowed;
use icu_normalizer::{ComposingNormalizerBorrowed, DecomposingNormalizerBorrowed};
use icu_properties::props::{DefaultIgnorableCodePoint, GeneralCategory};
use icu_properties::{CodePointMapData, CodePointSetData};
use zeroize::Zeroizing;

use crate::CoreError;

/// Password: trim (`White_Space`), then NFKD. Accepts every code point.
pub fn normalise_password(password: &str) -> Zeroizing<String> {
    nfkd(trim(password))
}

/// Login id: trim (`White_Space`), reject unassigned code points, then `toNFKC_Casefold`
/// (Unicode 18.0.0). Fails with `Format` on an unassigned code point.
pub fn normalise_login(login: &str) -> Result<String, CoreError> {
    let trimmed = trim(login);
    let categories = CodePointMapData::<GeneralCategory>::new();
    if trimmed
        .chars()
        .any(|c| categories.get(c) == GeneralCategory::Unassigned)
    {
        return Err(ProtoError::Format.into());
    }
    let mapped: String = trimmed.chars().map(nfkc_casefold_char).collect();
    Ok(ComposingNormalizerBorrowed::new_nfc()
        .normalize(&mapped)
        .into_owned())
}

pub(crate) fn nfc(text: &str) -> String {
    ComposingNormalizerBorrowed::new_nfc()
        .normalize(text)
        .into_owned()
}

pub(crate) fn nfkd(text: &str) -> Zeroizing<String> {
    const MAX_EXPANSION: usize = 18;
    let mut out = Zeroizing::new(String::with_capacity(
        text.len().saturating_mul(MAX_EXPANSION),
    ));
    DecomposingNormalizerBorrowed::new_nfkd()
        .normalize_to(text, &mut *out)
        .unwrap_or_default();
    out
}

fn trim(text: &str) -> &str {
    text.trim_matches(char::is_whitespace)
}

// Why: ICU4X has no NFKC_Casefold operation; this composition equals the UCD NFKC_CF mapping
// for every scalar value (checked against DerivedNormalizationProps.txt 18.0.0).
fn nfkc_casefold_char(c: char) -> String {
    let nfd = DecomposingNormalizerBorrowed::new_nfd();
    let nfkc = ComposingNormalizerBorrowed::new_nfkc();
    let mut buffer = [0; 4];
    let first = fold_without_ignorables(&nfd.normalize(c.encode_utf8(&mut buffer)));
    let second = fold_without_ignorables(&nfkc.normalize(&first));
    nfkc.normalize(&second).into_owned()
}

fn fold_without_ignorables(text: &str) -> String {
    let ignorables = CodePointSetData::new::<DefaultIgnorableCodePoint>();
    CaseMapperBorrowed::new()
        .fold_string(text)
        .chars()
        .filter(|c| !ignorables.contains(*c))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(text: &str) -> String {
        normalise_login(text).map_err(|_| ()).unwrap_or_default()
    }

    #[test]
    fn password_trims_white_space_and_decomposes() {
        assert_eq!(
            &*normalise_password("\u{3000}\u{85}\u{3142}\u{3163}\n"),
            "\u{1107}\u{1175}"
        );
        assert_eq!(
            &*normalise_password("\u{200b}a\u{feff}"),
            "\u{200b}a\u{feff}"
        );
        assert_eq!(&*normalise_password("\u{ac01}"), "\u{1100}\u{1161}\u{11a8}");
    }

    #[test]
    fn password_keeps_case_and_unassigned() {
        assert_eq!(&*normalise_password("Ab\u{378}"), "Ab\u{378}");
    }

    #[test]
    fn login_folds_full_case() {
        assert_eq!(login("STRASSE"), "strasse");
        assert_eq!(login("Stra\u{df}e"), "strasse");
        assert_eq!(login("\u{1e9e}"), "ss");
        assert_eq!(login("\u{3a3}\u{3c2}"), "\u{3c3}\u{3c3}");
        assert_eq!(login("\u{130}"), "i\u{307}");
        assert_eq!(login("\u{131}"), "\u{131}");
    }

    #[test]
    fn login_applies_compatibility_mapping_and_composes() {
        assert_eq!(login("\u{ff30}\u{ff21}\u{ff53}\u{ff53}"), "pass");
        assert_eq!(login("\u{3142}\u{3163}"), "\u{be44}");
        assert_eq!(login("\u{ffa1}\u{ffc2}"), "\u{ac00}");
    }

    #[test]
    fn login_removes_default_ignorables_but_trim_does_not_see_them() {
        assert_eq!(login("p\u{200b}w"), "pw");
        assert_eq!(login("\u{feff}p\u{ad}w"), "pw");
        assert_eq!(login(" \u{200b} "), "");
    }

    #[test]
    fn login_rejects_unassigned_code_points() {
        assert!(normalise_login("a\u{378}").is_err());
        assert!(normalise_login(" \u{fdd0} ").is_err());
        assert!(normalise_login("\u{e000}").is_ok());
        assert!(normalise_login("\u{558}").is_ok());
    }

    #[test]
    fn login_equals_ucd_mapping_applied_per_character() {
        assert_eq!(login("\u{1f96}\u{487}"), "\u{1f26}\u{3b9}\u{487}");
    }
}
