pub mod origin;
pub mod policy;
pub mod psl;
pub mod sites;

#[derive(Debug, thiserror::Error)]
pub enum MatchError {
    #[error("unparseable url")]
    Url,
    #[error("unsupported url scheme")]
    Scheme,
    #[error("url has no host")]
    Host,
    #[error("invalid sites dataset: {0}")]
    Dataset(&'static str),
}
