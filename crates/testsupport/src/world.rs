use std::sync::Arc;

use hasp_core::client::{Client, ClientConfig, SignUp};
use hasp_core::platform::{ManualClock as ClientClock, Platform};
use hasp_core::store::MemoryStore as ClientStore;
use hasp_crypto::SecretKey;
use hasp_server::{ManualClock, MemoryStore, Server, ServerConfig, Unlimited};
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

use crate::InProcess;

pub const ORIGIN: &str = "https://hasp.test";

pub type TestClient = Client<InProcess<MemoryStore>, ClientStore>;

#[derive(Debug)]
pub struct Device {
    pub client: TestClient,
    pub clock: Arc<ClientClock>,
}

#[derive(Debug)]
pub struct World {
    pub server: Arc<Server<MemoryStore>>,
    pub clock: ManualClock,
    admin: Option<Device>,
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

#[expect(
    clippy::expect_used,
    reason = "test support aborts on a broken fixture"
)]
impl World {
    pub fn new() -> Self {
        Self::with_config(|_| {})
    }

    pub fn with_config(adjust: impl FnOnce(&mut ServerConfig)) -> Self {
        let clock = ManualClock::new(1_000_000);
        let mut config = ServerConfig::new(ORIGIN, SecretKey::from_bytes([9; 32]));
        adjust(&mut config);
        let server = Arc::new(
            Server::new(
                config,
                MemoryStore::new(),
                Arc::new(clock.clone()),
                Arc::new(Unlimited),
            )
            .expect("server"),
        );
        Self {
            server,
            clock,
            admin: None,
        }
    }

    pub fn fingerprint(&self) -> [u8; 15] {
        let digest = hasp_crypto::sha256(&[&self.server.server_public_key()]);
        let mut out = [0_u8; 15];
        out.copy_from_slice(&digest[..15]);
        out
    }

    pub fn device(&self, hardware: bool) -> Device {
        let clock = Arc::new(ClientClock::new(1_000_000));
        let platform = if hardware {
            Platform::for_tests(Arc::clone(&clock))
        } else {
            Platform::password_only_for_tests(Arc::clone(&clock))
        };
        let transport = InProcess::new(Arc::clone(&self.server));
        let client = Client::new(
            transport,
            ClientStore::new(),
            platform,
            ClientConfig::new(if hardware { "macos" } else { "linux" }),
        );
        Device { client, clock }
    }

    pub fn client_with<T: hasp_core::transport::Transport>(
        &self,
        transport: T,
        hardware: bool,
    ) -> (Client<T, ClientStore>, Arc<ClientClock>) {
        self.client_on(transport, ClientStore::new(), hardware)
    }

    pub fn client_on<T: hasp_core::transport::Transport, S: hasp_core::store::Store>(
        &self,
        transport: T,
        store: S,
        hardware: bool,
    ) -> (Client<T, S>, Arc<ClientClock>) {
        let clock = Arc::new(ClientClock::new(1_000_000));
        let platform = if hardware {
            Platform::for_tests(Arc::clone(&clock))
        } else {
            Platform::password_only_for_tests(Arc::clone(&clock))
        };
        let client = Client::new(
            transport,
            store,
            platform,
            ClientConfig::new(if hardware { "macos" } else { "linux" }),
        );
        (client, clock)
    }

    pub fn transport(&self) -> InProcess<MemoryStore> {
        InProcess::new(Arc::clone(&self.server))
    }

    pub fn sync_clocks(&self, devices: &[&Device]) {
        for device in devices {
            device.clock.advance(0);
        }
    }

    pub async fn token(&mut self) -> String {
        let cancel = CancellationToken::new();
        if self.admin.is_none() {
            let bootstrap = self
                .server
                .issue_bootstrap_token()
                .expect("bootstrap")
                .to_text();
            let mut admin = self.device(true);
            Box::pin(admin.client.sign_up(
                &SignUp {
                    origin: ORIGIN,
                    token: &bootstrap,
                    login: "admin",
                    password: &SecretString::from("admin password long enough"),
                },
                &cancel,
            ))
            .await
            .expect("admin sign-up");
            self.admin = Some(admin);
        }
        let admin = self.admin.as_mut().expect("admin");
        admin
            .client
            .admin_create_token(&cancel)
            .await
            .expect("admin token")
    }

    pub async fn signup(&mut self, login: &str, password: &str, hardware: bool) -> Device {
        let token = self.token().await;
        let mut device = self.device(hardware);
        Box::pin(device.client.sign_up(
            &SignUp {
                origin: ORIGIN,
                token: &token,
                login,
                password: &SecretString::from(password),
            },
            &CancellationToken::new(),
        ))
        .await
        .expect("sign-up");
        device
    }
}
