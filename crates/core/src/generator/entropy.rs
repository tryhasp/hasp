use crate::generator::GeneratorError;

pub trait Entropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), GeneratorError>;
}

#[derive(Debug, Clone, Copy)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), GeneratorError> {
        Ok(hasp_crypto::fill_random(buf)?)
    }
}

pub(crate) fn below<E: Entropy + ?Sized>(
    entropy: &mut E,
    bound: u32,
) -> Result<u32, GeneratorError> {
    if bound == 0 {
        return Err(GeneratorError::Options("empty range"));
    }
    let zone = (u32::MAX / bound) * bound;
    loop {
        let mut word = [0u8; 4];
        entropy.fill(&mut word)?;
        let value = u32::from_le_bytes(word);
        if value < zone {
            return Ok(value % bound);
        }
    }
}

pub(crate) fn index<E: Entropy + ?Sized>(
    entropy: &mut E,
    len: usize,
) -> Result<usize, GeneratorError> {
    let bound = u32::try_from(len).map_err(|_| GeneratorError::Options("range too large"))?;
    usize::try_from(below(entropy, bound)?).map_err(|_| GeneratorError::Options("range too large"))
}

pub(crate) fn shuffle<E: Entropy + ?Sized, T>(
    entropy: &mut E,
    items: &mut [T],
) -> Result<(), GeneratorError> {
    for i in (1..items.len()).rev() {
        let j = index(entropy, i + 1)?;
        items.swap(i, j);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    #[derive(Debug)]
    pub(crate) struct SeededEntropy(u64);

    impl SeededEntropy {
        pub(crate) fn new(seed: u64) -> Self {
            Self(seed | 1)
        }
    }

    impl Entropy for SeededEntropy {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), GeneratorError> {
            for byte in buf {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                *byte = self.0.to_le_bytes()[3];
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::SeededEntropy;
    use super::*;

    #[test]
    fn below_stays_in_range_and_covers_it() {
        let mut entropy = SeededEntropy::new(7);
        let mut seen = [false; 6];
        for _ in 0..500 {
            let v = below(&mut entropy, 6).unwrap();
            seen[usize::try_from(v).unwrap()] = true;
        }
        assert!(seen.iter().all(|s| *s));
    }

    #[test]
    fn below_rejects_zero_bound() {
        assert!(below(&mut SeededEntropy::new(1), 0).is_err());
    }

    #[test]
    fn below_is_unbiased_for_a_non_power_of_two() {
        let mut entropy = SeededEntropy::new(99);
        let mut counts = [0u32; 3];
        for _ in 0..30_000 {
            counts[usize::try_from(below(&mut entropy, 3).unwrap()).unwrap()] += 1;
        }
        assert!(
            counts.iter().all(|c| (9_000..11_000).contains(c)),
            "{counts:?}"
        );
    }

    #[test]
    fn shuffle_permutes() {
        let mut entropy = SeededEntropy::new(5);
        let mut items: Vec<u32> = (0..20).collect();
        shuffle(&mut entropy, &mut items).unwrap();
        let mut sorted = items.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..20).collect::<Vec<_>>());
        assert_ne!(items, sorted);
    }

    #[test]
    fn os_entropy_fills_with_crypto_randomness() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        OsEntropy.fill(&mut a).unwrap();
        OsEntropy.fill(&mut b).unwrap();
        assert_ne!(a, b);
    }
}
