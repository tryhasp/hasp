pub mod entropy;
pub mod memorable;
pub mod pin;
pub mod random;
pub mod rules;
pub mod strength;

#[derive(Debug, thiserror::Error)]
pub enum GeneratorError {
    #[error("invalid options: {0}")]
    Options(&'static str),
    #[error("rules cannot be satisfied: {0}")]
    Unsatisfiable(&'static str),
    #[error("invalid password rules: {0}")]
    Rules(&'static str),
    #[error("invalid wordlist")]
    Wordlist,
    #[error("crypto: {0}")]
    Crypto(#[from] hasp_crypto::CryptoError),
}
