use hasp_crypto::SecretKey;

pub(crate) const SIGNUP_TTL: u64 = 7 * 24 * 3600;

#[derive(Debug)]
pub struct ServerConfig {
    pub origin: String,
    pub server_master: SecretKey,
    pub(crate) recovery_delay: u64,
    pub idle_expiry: u64,
    pub absolute_expiry: u64,
    pub reauth_window: u64,
    pub invite_ttl: u64,
    pub signup_ttl: u64,
    pub enrol_ttl: u64,
    pub pending_login_ttl: u64,
    pub recovery_window: u64,
    pub upload_ttl: u64,
    pub max_attachment_bytes: u64,
    pub max_ops: usize,
    pub max_shares: usize,
    pub history_versions: usize,
}

impl ServerConfig {
    pub fn new(origin: impl Into<String>, server_master: SecretKey) -> Self {
        Self {
            origin: origin.into(),
            server_master,
            recovery_delay: 24 * 3600,
            idle_expiry: 30 * 24 * 3600,
            absolute_expiry: 90 * 24 * 3600,
            reauth_window: 5 * 60,
            invite_ttl: 7 * 24 * 3600,
            signup_ttl: SIGNUP_TTL,
            enrol_ttl: 5 * 60,
            pending_login_ttl: 60,
            recovery_window: 3600,
            upload_ttl: 24 * 3600,
            max_attachment_bytes: 100 * 1024 * 1024,
            max_ops: 500,
            max_shares: 1024,
            history_versions: 10,
        }
    }

    /// Exists only with the `testing` feature or in unit tests, so a production `haspd` always
    /// waits 24 hours (protocol 7.11).
    #[cfg(any(test, feature = "testing"))]
    pub fn set_recovery_delay(&mut self, seconds: u64) {
        self.recovery_delay = seconds;
    }
}
