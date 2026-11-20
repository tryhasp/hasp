mod base32;
mod mac;
pub mod uri;

use secrecy::{ExposeSecret, SecretSlice, SecretString};

const MAX_SECRET_LEN: usize = 1024;
const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";
const STEAM_DIGITS: u8 = 5;
const STEAM_PERIOD_S: u32 = 30;
const MIN_DIGITS: u8 = 6;
const MAX_DIGITS: u8 = 10;
const MAX_PERIOD_S: u32 = 86_400;
const TRUNCATION_MASK: u32 = 0x7fff_ffff;

#[derive(Debug, thiserror::Error)]
pub enum OtpError {
    #[error("secret must be 1 to {MAX_SECRET_LEN} bytes")]
    SecretLength,
    #[error("digits must be {MIN_DIGITS} to {MAX_DIGITS}")]
    Digits,
    #[error("period must be 1 to {MAX_PERIOD_S} seconds")]
    Period,
    #[error("invalid base32 secret")]
    Base32,
    #[error("invalid otpauth uri")]
    Uri,
    #[error("unsupported otp parameter")]
    Unsupported,
    #[error("parameters are not time based")]
    NotTotp,
    #[error("parameters are not counter based")]
    NotHotp,
    #[error("crypto: {0}")]
    Crypto(#[from] hasp_crypto::CryptoError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpAlg {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpKind {
    Totp { period_s: u32 },
    Hotp { counter: u64 },
}

#[derive(Debug)]
pub struct OtpParams {
    secret: SecretSlice<u8>,
    algorithm: OtpAlg,
    digits: u8,
    kind: OtpKind,
    issuer: Option<String>,
    account: Option<String>,
    steam: bool,
}

impl OtpAlg {
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    pub fn parse(name: &str) -> Result<Self, OtpError> {
        match name.to_ascii_uppercase().as_str() {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            _ => Err(OtpError::Unsupported),
        }
    }
}

impl OtpParams {
    pub fn new(
        secret: &[u8],
        kind: OtpKind,
        algorithm: OtpAlg,
        digits: u8,
    ) -> Result<Self, OtpError> {
        if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
            return Err(OtpError::Digits);
        }
        Self::checked(secret, kind, algorithm, digits, false)
    }

    pub fn steam(secret: &[u8]) -> Result<Self, OtpError> {
        let kind = OtpKind::Totp {
            period_s: STEAM_PERIOD_S,
        };
        Self::checked(secret, kind, OtpAlg::Sha1, STEAM_DIGITS, true)
    }

    fn checked(
        secret: &[u8],
        kind: OtpKind,
        algorithm: OtpAlg,
        digits: u8,
        steam: bool,
    ) -> Result<Self, OtpError> {
        if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
            return Err(OtpError::SecretLength);
        }
        if let OtpKind::Totp { period_s } = kind
            && !(1..=MAX_PERIOD_S).contains(&period_s)
        {
            return Err(OtpError::Period);
        }
        Ok(Self {
            secret: SecretSlice::from(secret.to_vec()),
            algorithm,
            digits,
            kind,
            issuer: None,
            account: None,
            steam,
        })
    }

    #[must_use]
    pub fn with_label(mut self, issuer: Option<String>, account: Option<String>) -> Self {
        self.issuer = issuer;
        self.account = account;
        self
    }

    pub fn expose_secret(&self) -> &[u8] {
        self.secret.expose_secret()
    }

    pub fn algorithm(&self) -> OtpAlg {
        self.algorithm
    }

    pub fn digits(&self) -> u8 {
        self.digits
    }

    pub fn kind(&self) -> OtpKind {
        self.kind
    }

    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    pub fn is_steam(&self) -> bool {
        self.steam
    }

    pub fn code_at(&self, unix_seconds: u64) -> Result<SecretString, OtpError> {
        match self.kind {
            OtpKind::Totp { period_s } => self.code_for_counter(unix_seconds / u64::from(period_s)),
            OtpKind::Hotp { .. } => Err(OtpError::NotTotp),
        }
    }

    pub fn current_hotp(&self) -> Result<SecretString, OtpError> {
        match self.kind {
            OtpKind::Hotp { counter } => self.code_for_counter(counter),
            OtpKind::Totp { .. } => Err(OtpError::NotHotp),
        }
    }

    pub fn code_for_counter(&self, counter: u64) -> Result<SecretString, OtpError> {
        let digest = mac::compute(
            self.algorithm,
            self.secret.expose_secret(),
            &counter.to_be_bytes(),
        )?;
        let truncated = truncate(digest.expose());
        Ok(SecretString::from(if self.steam {
            steam_code(truncated)
        } else {
            decimal_code(truncated, self.digits)
        }))
    }

    pub fn seconds_remaining(&self, unix_seconds: u64) -> Result<u32, OtpError> {
        match self.kind {
            OtpKind::Totp { period_s } => {
                let elapsed = unix_seconds % u64::from(period_s);
                let left = u64::from(period_s) - elapsed;
                u32::try_from(left).map_err(|_| OtpError::Period)
            }
            OtpKind::Hotp { .. } => Err(OtpError::NotTotp),
        }
    }
}

fn truncate(digest: &[u8]) -> u32 {
    let Some(&last) = digest.last() else {
        return 0;
    };
    let offset = usize::from(last & 0x0f);
    let mut word = [0u8; 4];
    for (slot, byte) in word.iter_mut().zip(digest.iter().skip(offset)) {
        *slot = *byte;
    }
    u32::from_be_bytes(word) & TRUNCATION_MASK
}

fn decimal_code(truncated: u32, digits: u8) -> String {
    let modulus = 10u64.pow(u32::from(digits));
    let value = u64::from(truncated) % modulus;
    format!("{value:0width$}", width = usize::from(digits))
}

fn steam_code(mut truncated: u32) -> String {
    let base = u32::try_from(STEAM_ALPHABET.len()).unwrap_or(26);
    let mut code = String::with_capacity(usize::from(STEAM_DIGITS));
    for _ in 0..STEAM_DIGITS {
        let index = usize::try_from(truncated % base).unwrap_or(0);
        code.push(char::from(
            STEAM_ALPHABET.get(index).copied().unwrap_or(b'2'),
        ));
        truncated /= base;
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA1_KEY: &[u8] = b"12345678901234567890";
    const SHA256_KEY: &[u8] = b"12345678901234567890123456789012";
    const SHA512_KEY: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    fn totp(key: &[u8], alg: OtpAlg, digits: u8, t: u64) -> String {
        let params = OtpParams::new(key, OtpKind::Totp { period_s: 30 }, alg, digits).unwrap();
        params.code_at(t).unwrap().expose_secret().to_owned()
    }

    #[test]
    fn matches_rfc4226_appendix_d() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        let params =
            OtpParams::new(SHA1_KEY, OtpKind::Hotp { counter: 0 }, OtpAlg::Sha1, 6).unwrap();
        for (counter, code) in (0u64..).zip(expected) {
            assert_eq!(
                params.code_for_counter(counter).unwrap().expose_secret(),
                code
            );
        }
    }

    #[test]
    fn matches_rfc6238_appendix_b() {
        let times = [
            59u64,
            1_111_111_109,
            1_111_111_111,
            1_234_567_890,
            2_000_000_000,
            20_000_000_000,
        ];
        let sha1 = [
            "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
        ];
        let sha256 = [
            "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
        ];
        let sha512 = [
            "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
        ];
        for (i, t) in times.iter().enumerate() {
            assert_eq!(totp(SHA1_KEY, OtpAlg::Sha1, 8, *t), sha1[i]);
            assert_eq!(totp(SHA256_KEY, OtpAlg::Sha256, 8, *t), sha256[i]);
            assert_eq!(totp(SHA512_KEY, OtpAlg::Sha512, 8, *t), sha512[i]);
        }
    }

    #[test]
    fn six_digit_code_truncates_the_eight_digit_code() {
        assert_eq!(totp(SHA1_KEY, OtpAlg::Sha1, 6, 59), "287082");
    }

    #[test]
    fn honours_custom_period() {
        let params =
            OtpParams::new(SHA1_KEY, OtpKind::Totp { period_s: 60 }, OtpAlg::Sha1, 6).unwrap();
        assert_eq!(
            params.code_at(60).unwrap().expose_secret(),
            params.code_at(119).unwrap().expose_secret()
        );
        assert_ne!(
            params.code_at(119).unwrap().expose_secret(),
            params.code_at(120).unwrap().expose_secret()
        );
        assert_eq!(params.seconds_remaining(61).unwrap(), 59);
        assert_eq!(params.seconds_remaining(60).unwrap(), 60);
    }

    #[test]
    fn steam_code_uses_the_steam_alphabet() {
        let params = OtpParams::steam(SHA1_KEY).unwrap();
        let code = params.code_for_counter(0).unwrap();
        assert_eq!(code.expose_secret(), "GG5F5");
    }

    #[test]
    fn rejects_invalid_parameters() {
        let totp = OtpKind::Totp { period_s: 30 };
        assert!(matches!(
            OtpParams::new(b"", totp, OtpAlg::Sha1, 6),
            Err(OtpError::SecretLength)
        ));
        assert!(matches!(
            OtpParams::new(b"k", totp, OtpAlg::Sha1, 5),
            Err(OtpError::Digits)
        ));
        assert!(matches!(
            OtpParams::new(b"k", totp, OtpAlg::Sha1, 11),
            Err(OtpError::Digits)
        ));
        let zero = OtpKind::Totp { period_s: 0 };
        assert!(matches!(
            OtpParams::new(b"k", zero, OtpAlg::Sha1, 6),
            Err(OtpError::Period)
        ));
    }

    #[test]
    fn kind_mismatch_is_an_error() {
        let hotp = OtpParams::new(b"k", OtpKind::Hotp { counter: 1 }, OtpAlg::Sha1, 6).unwrap();
        assert!(matches!(hotp.code_at(0), Err(OtpError::NotTotp)));
        let totp = OtpParams::new(b"k", OtpKind::Totp { period_s: 30 }, OtpAlg::Sha1, 6).unwrap();
        assert!(matches!(totp.current_hotp(), Err(OtpError::NotHotp)));
    }

    #[test]
    fn debug_is_redacted() {
        let params = OtpParams::new(
            b"supersecret",
            OtpKind::Totp { period_s: 30 },
            OtpAlg::Sha1,
            6,
        )
        .unwrap();
        let text = format!("{params:?}");
        assert!(!text.contains(&format!("{:?}", b"supersecret".to_vec())));
    }
}
