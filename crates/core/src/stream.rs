use zeroize::Zeroizing;

pub(crate) const CHUNK_SIZE: usize = 1 << 20;
pub(crate) const NONCE_PREFIX_LEN: usize = 15;
pub(crate) const PAD_BLOCK: usize = 4096;

pub(crate) fn chunk_nonce(prefix: &[u8; NONCE_PREFIX_LEN], index: u64, last: bool) -> [u8; 24] {
    let mut nonce = [0_u8; 24];
    let (head, tail) = nonce.split_at_mut(NONCE_PREFIX_LEN);
    head.copy_from_slice(prefix);
    let (counter, flag) = tail.split_at_mut(8);
    counter.copy_from_slice(&index.to_be_bytes());
    flag.fill(u8::from(last));
    nonce
}

pub(crate) fn pad_last(plaintext: &[u8]) -> Zeroizing<Vec<u8>> {
    let padded_len = plaintext
        .len()
        .saturating_add(1)
        .div_ceil(PAD_BLOCK)
        .saturating_mul(PAD_BLOCK);
    let mut padded = Zeroizing::new(Vec::with_capacity(padded_len));
    padded.extend_from_slice(plaintext);
    padded.push(0x80);
    padded.resize(padded_len, 0);
    padded
}

pub(crate) fn unpad_last(padded: &[u8]) -> Option<&[u8]> {
    if padded.is_empty() || !padded.len().is_multiple_of(PAD_BLOCK) {
        return None;
    }
    let marker = padded.iter().rposition(|b| *b != 0)?;
    if padded.get(marker) != Some(&0x80) || padded.len().saturating_sub(marker) > PAD_BLOCK {
        return None;
    }
    padded.get(..marker)
}
