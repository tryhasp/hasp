const DIGITS: &[u8; 16] = b"0123456789abcdef";

pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        for nibble in [byte.wrapping_shr(4), byte & 0x0f] {
            let digit = DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0');
            out.push(char::from(digit));
        }
    }
    out
}

pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|&[high, low]| Some(nibble(high)?.wrapping_shl(4) | nibble(low)?))
        .collect()
}

fn nibble(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_and_rejects_malformed_text() {
        assert_eq!(to_hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(from_hex("00ABff"), Some(vec![0x00, 0xab, 0xff]));
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex("+1"), None);
        assert_eq!(from_hex(""), Some(Vec::new()));
    }
}
