#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error(transparent)]
    Origin(#[from] hasp_core::transport::origin::OriginError),
    #[error("the TLS configuration could not be built")]
    Tls,
    #[error("the HTTP client could not be built")]
    Client,
}
