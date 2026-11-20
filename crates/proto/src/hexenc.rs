use crate::ProtoError;

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn crockford_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        acc = acc.wrapping_shl(8) | u32::from(byte);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            out.push(symbol(acc.wrapping_shr(bits) & 0x1f));
        }
        acc &= low_mask(bits);
    }
    if bits > 0 {
        out.push(symbol(acc.wrapping_shl(5_u32.saturating_sub(bits)) & 0x1f));
    }
    out
}

pub fn crockford_decode(text: &str) -> Result<Vec<u8>, ProtoError> {
    let mut out = Vec::with_capacity(text.len().saturating_mul(5) / 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for ch in text.chars() {
        let value = CROCKFORD
            .iter()
            .position(|&c| char::from(c) == ch.to_ascii_uppercase())
            .and_then(|i| u32::try_from(i).ok())
            .ok_or(ProtoError::Format)?;
        acc = acc.wrapping_shl(5) | value;
        bits = bits.saturating_add(5);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from(acc.wrapping_shr(bits) & 0xff).map_err(|_| ProtoError::Format)?);
            acc &= low_mask(bits);
        }
    }
    if acc != 0 {
        return Err(ProtoError::Format);
    }
    Ok(out)
}

fn low_mask(bits: u32) -> u32 {
    1_u32.wrapping_shl(bits).wrapping_sub(1)
}

fn symbol(index: u32) -> char {
    char::from(
        CROCKFORD
            .get(usize::try_from(index).unwrap_or(0))
            .copied()
            .unwrap_or(b'0'),
    )
}

pub(crate) fn grouped(text: &str, group: usize) -> String {
    let mut out = String::with_capacity(text.len().saturating_mul(2));
    for (i, ch) in text.chars().enumerate() {
        if i > 0 && i.checked_rem(group) == Some(0) {
            out.push('-');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crockford_matches_known_encodings() {
        assert_eq!(crockford_encode(b""), "");
        assert_eq!(crockford_encode(b"f"), "CR");
        assert_eq!(crockford_encode(b"foobar"), "CSQPYRK1E8");
    }

    #[test]
    fn crockford_roundtrips_and_rejects_nonzero_padding() {
        for len in 0..40_u8 {
            let data: Vec<u8> = (0..len)
                .map(|i| i.wrapping_mul(37).wrapping_add(11))
                .collect();
            assert_eq!(crockford_decode(&crockford_encode(&data)).unwrap(), data);
        }
        assert!(crockford_decode("CS").is_err());
        assert!(crockford_decode("C!").is_err());
    }

    #[test]
    fn groups_every_four_symbols() {
        assert_eq!(grouped("ABCDEFGHIJ", 4), "ABCD-EFGH-IJ");
    }
}
