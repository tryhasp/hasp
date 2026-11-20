use crate::CryptoError;

pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buf).map_err(|_| CryptoError::Random)
}

pub fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0_u8; N];
    fill_random(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_distinct_output() {
        let first = random_array::<32>().unwrap();
        let second = random_array::<32>().unwrap();
        assert_ne!(first, second);
        assert_ne!(first, [0; 32]);
    }

    #[test]
    fn fills_empty_buffer() {
        fill_random(&mut []).unwrap();
    }
}
