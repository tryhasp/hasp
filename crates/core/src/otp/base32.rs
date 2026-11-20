use crate::otp::OtpError;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub(super) fn decode(text: &str) -> Result<Vec<u8>, OtpError> {
    let mut out = Vec::with_capacity(text.len() / 8 * 5 + 5);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for ch in text.chars().filter(|c| !c.is_whitespace() && *c != '-') {
        if ch == '=' {
            continue;
        }
        let upper = ch.to_ascii_uppercase();
        let value = ALPHABET
            .iter()
            .position(|&a| char::from(a) == upper)
            .ok_or(OtpError::Base32)?;
        buffer = (buffer << 5) | u32::try_from(value).map_err(|_| OtpError::Base32)?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).map_err(|_| OtpError::Base32)?);
            buffer &= (1 << bits) - 1;
        }
    }
    if out.is_empty() {
        return Err(OtpError::Base32);
    }
    Ok(out)
}

pub(super) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    for chunk in bytes.chunks(5) {
        let mut word = [0u8; 5];
        for (slot, byte) in word.iter_mut().zip(chunk) {
            *slot = *byte;
        }
        let acc = word.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
        let symbols = (chunk.len() * 8).div_ceil(5);
        for i in 0..8 {
            if i < symbols {
                let shift = 35 - 5 * i;
                let index = usize::try_from((acc >> shift) & 0x1f).unwrap_or(0);
                out.push(char::from(ALPHABET.get(index).copied().unwrap_or(b'A')));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc4648_vectors() {
        let cases = [
            ("f", "MY======"),
            ("fo", "MZXQ===="),
            ("foo", "MZXW6==="),
            ("foob", "MZXW6YQ="),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI======"),
        ];
        for (plain, encoded) in cases {
            assert_eq!(encode(plain.as_bytes()), encoded);
            assert_eq!(decode(encoded).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn decodes_lowercase_spaced_unpadded_input() {
        assert_eq!(decode("mzxw 6ytb-oi").unwrap(), b"foobar");
    }

    #[test]
    fn rejects_invalid_characters_and_empty_input() {
        assert!(decode("MZXW1").is_err());
        assert!(decode("").is_err());
        assert!(decode("====").is_err());
    }
}
