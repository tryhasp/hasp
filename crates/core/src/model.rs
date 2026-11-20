pub mod field;
pub mod id;
pub mod item;
pub mod tag;
pub mod template;
pub mod url;
pub mod wire;

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("invalid tag")]
    Tag,
    #[error("invalid url")]
    Url,
    #[error("invalid field value: {0}")]
    Value(&'static str),
    #[error("invalid item: {0}")]
    Item(&'static str),
    #[error("invalid template {template}: {reason}")]
    Template {
        template: String,
        reason: &'static str,
    },
    #[error("unknown template {0}")]
    UnknownTemplate(String),
    #[error("template json: {0}")]
    TemplateJson(String),
    #[error("crypto: {0}")]
    Crypto(#[from] hasp_crypto::CryptoError),
}
