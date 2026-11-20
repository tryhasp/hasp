use crate::otp::{OtpAlg, OtpError};

pub(super) fn compute(
    algorithm: OtpAlg,
    key: &[u8],
    message: &[u8],
) -> Result<hasp_crypto::SecretBytes, OtpError> {
    let hash = match algorithm {
        OtpAlg::Sha1 => hasp_crypto::HmacAlg::Sha1,
        OtpAlg::Sha256 => hasp_crypto::HmacAlg::Sha256,
        OtpAlg::Sha512 => hasp_crypto::HmacAlg::Sha512,
    };
    Ok(hasp_crypto::hmac(hash, key, message)?)
}
