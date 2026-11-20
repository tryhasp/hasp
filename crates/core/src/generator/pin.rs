use secrecy::SecretString;

use crate::generator::GeneratorError;
use crate::generator::entropy::{Entropy, below};

const MIN_LENGTH: u32 = 4;
const MAX_LENGTH: u32 = 32;

pub fn pin<E: Entropy + ?Sized>(
    entropy: &mut E,
    length: u32,
) -> Result<SecretString, GeneratorError> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
        return Err(GeneratorError::Options("pin length"));
    }
    let mut digits = String::with_capacity(usize::try_from(length).unwrap_or(0));
    for _ in 0..length {
        digits.push(char::from(
            b'0' + u8::try_from(below(entropy, 10)?).unwrap_or(0),
        ));
    }
    Ok(SecretString::from(digits))
}

pub fn pin_entropy_bits(length: u32) -> f64 {
    10f64.log2() * f64::from(length)
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;
    use crate::generator::entropy::testing::SeededEntropy;

    #[test]
    fn makes_digits_of_the_requested_length() {
        for length in [4, 6, 12, 32] {
            let pin = pin(&mut SeededEntropy::new(u64::from(length)), length).unwrap();
            assert_eq!(pin.expose_secret().len(), usize::try_from(length).unwrap());
            assert!(pin.expose_secret().bytes().all(|b| b.is_ascii_digit()));
        }
    }

    #[test]
    fn rejects_out_of_range_lengths() {
        assert!(pin(&mut SeededEntropy::new(1), 3).is_err());
        assert!(pin(&mut SeededEntropy::new(1), 33).is_err());
    }

    #[test]
    fn six_digits_are_about_twenty_bits() {
        assert!((pin_entropy_bits(6) - 19.93).abs() < 0.01);
    }
}
