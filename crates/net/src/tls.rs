use std::sync::Arc;

use rustls::ClientConfig;
use rustls::crypto::ring;
use rustls_platform_verifier::BuilderVerifierExt;

use crate::NetError;

/// Chain validation is the operating system's (`rustls-platform-verifier`), so a private CA is
/// trusted by installing it in the system store. A key pin is not done at this layer: the pinned
/// server key is checked inside the protocol (P 6.1, 7.2).
pub(crate) fn client_config() -> Result<ClientConfig, NetError> {
    let provider = Arc::new(ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| NetError::Tls)?
        .with_platform_verifier()
        .map_err(|_| NetError::Tls)?
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}
