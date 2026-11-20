const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let mut acc = 0_u32;
        for (i, byte) in (0_u32..).zip(chunk) {
            let shift = 16_u32.saturating_sub(i.saturating_mul(8));
            acc |= u32::from(*byte).checked_shl(shift).unwrap_or(0);
        }
        for i in 0..=u32::try_from(chunk.len()).unwrap_or(0) {
            let shift = 18_u32.saturating_sub(i.saturating_mul(6));
            let index = usize::try_from(acc.checked_shr(shift).unwrap_or(0) & 0x3f).unwrap_or(0);
            out.push(char::from(ALPHABET.get(index).copied().unwrap_or(b'A')));
        }
    }
    out
}

/// Rejects padding, any other alphabet and non-zero trailing bits, so every value has one text.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len().saturating_mul(3) / 4);
    let mut acc = 0_u32;
    let mut bits = 0_u32;
    for ch in text.bytes() {
        let value = u32::try_from(ALPHABET.iter().position(|c| *c == ch)?).ok()?;
        acc = acc.checked_shl(6).unwrap_or(0) | value;
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from(acc.checked_shr(bits).unwrap_or(0) & 0xff).ok()?);
            acc &= 1_u32.checked_shl(bits).unwrap_or(0).saturating_sub(1);
        }
    }
    if acc != 0 {
        return None;
    }
    Some(out)
}

pub fn decode_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    decode(text)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc_4648_vectors_without_padding() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg");
        assert_eq!(encode(b"fo"), "Zm8");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn round_trips_every_length() {
        for len in 0..40_u8 {
            let bytes: Vec<u8> = (0..len).map(|b| b.wrapping_mul(37)).collect();
            assert_eq!(decode(&encode(&bytes)), Some(bytes));
        }
    }

    #[test]
    fn rejects_padding_alphabet_escapes_and_stray_bits() {
        assert_eq!(decode("Zg=="), None);
        assert_eq!(decode("Zm+v"), None);
        assert_eq!(decode("Zh"), None);
        assert_eq!(decode("Z"), None);
    }
}
