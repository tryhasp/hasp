use hasp_crypto::{OpaqueClientLogin, SecretKey};
use hasp_proto::wire::{
    DeviceInfo, LoginFinish, LoginStart, OpId, OpaquePurpose, SessionId, SessionToken, SignupToken,
    decode_reply,
};
use hasp_proto::{AccountId, DeviceId, Seq, Uint53, VaultId, VaultKind};

use super::person::Person;
use super::rnd;
use super::vault_model::VaultModel;

pub trait Transport: Send + Sync + std::fmt::Debug {
    fn send(&self, token: Option<&SessionToken>, op: OpId, body: &[u8]) -> Vec<u8>;
}

pub trait TestStore: crate::Store + std::fmt::Debug + 'static {
    fn fresh() -> (Self, Box<dyn std::any::Any + Send>)
    where
        Self: Sized;
}

impl TestStore for crate::MemoryStore {
    fn fresh() -> (Self, Box<dyn std::any::Any + Send>) {
        (Self::new(), Box::new(()))
    }
}

pub type Harness = HarnessOf<crate::MemoryStore>;

#[derive(Debug)]
pub struct HarnessOf<S: TestStore> {
    pub server: std::sync::Arc<crate::Server<S>>,
    pub clock: crate::ManualClock,
    admin: Option<SessionToken>,
    transport: Option<Box<dyn Transport>>,
    _scratch: Box<dyn std::any::Any + Send>,
}

#[derive(Debug)]
pub struct Client {
    pub person: Person,
    pub vault: VaultModel,
    pub token: SessionToken,
    pub session_id: SessionId,
}

impl Client {
    pub fn caller(&self) -> crate::Caller {
        crate::Caller::with_token(self.token.clone())
    }
}

pub const ORIGIN: &str = "https://hasp.test";

impl<S: TestStore> HarnessOf<S> {
    pub fn new() -> Self {
        Self::with_limiter(std::sync::Arc::new(crate::Unlimited))
    }

    pub fn with_limiter(limiter: std::sync::Arc<dyn crate::RateLimiter>) -> Self {
        let (store, scratch) = S::fresh();
        Self::over(store, scratch, limiter)
    }

    pub fn over(
        store: S,
        scratch: Box<dyn std::any::Any + Send>,
        limiter: std::sync::Arc<dyn crate::RateLimiter>,
    ) -> Self {
        let clock = crate::ManualClock::new(1_000_000);
        let server = std::sync::Arc::new(
            crate::Server::new(
                crate::ServerConfig::new(ORIGIN, SecretKey::from_bytes([7; 32])),
                store,
                std::sync::Arc::new(clock.clone()),
                limiter,
            )
            .expect("server"),
        );
        let transport = Self::default_transport(&server);
        Self {
            server,
            clock,
            admin: None,
            transport,
            _scratch: scratch,
        }
    }

    #[cfg(test)]
    fn default_transport(server: &std::sync::Arc<crate::Server<S>>) -> Option<Box<dyn Transport>> {
        Some(Box::new(crate::http::Loopback::new(std::sync::Arc::clone(
            server,
        ))))
    }

    #[cfg(not(test))]
    fn default_transport(_: &std::sync::Arc<crate::Server<S>>) -> Option<Box<dyn Transport>> {
        None
    }

    #[must_use]
    pub fn direct(mut self) -> Self {
        self.transport = None;
        self
    }

    pub fn call<O: hasp_proto::wire::Operation>(
        &self,
        token: Option<&SessionToken>,
        request: &O,
    ) -> Result<O::Response, hasp_proto::wire::WireError> {
        if let Some(transport) = &self.transport {
            let body = request.to_cbor()?;
            return decode_reply::<O::Response>(&transport.send(token, O::ID, &body))?;
        }
        let caller = match token {
            Some(token) => crate::Caller::with_token(token.clone()),
            None => crate::Caller::anonymous(),
        };
        self.server.call(&caller, request)
    }

    pub fn signup_token(&mut self) -> SignupToken {
        match &self.admin {
            None => self.server.issue_bootstrap_token().expect("bootstrap"),
            Some(admin) => {
                self.call(
                    Some(admin),
                    &hasp_proto::wire::AdminTokenCreate {
                        kind: hasp_proto::wire::TokenKind::Signup,
                    },
                )
                .expect("admin token")
                .token
            }
        }
    }

    pub fn try_register(
        &self,
        token: &SignupToken,
        person: &Person,
        vault: &mut VaultModel,
    ) -> Result<(), hasp_proto::wire::WireError> {
        let (start, state) = person.register_start(token);
        let response = self.call(None, &start)?;
        let finish = person.register_finish(token, state, &response, vault);
        self.call(None, &finish).map(drop)
    }

    pub fn try_login(
        &self,
        person: &Person,
    ) -> Result<(SessionId, SessionToken), hasp_proto::wire::WireError> {
        let (start, state) = person.login_start();
        let response = self.call(None, &start)?;
        let (finish, key) = person
            .login_complete(ORIGIN, state, &response, "test")
            .map_err(|_| hasp_proto::wire::WireError::new(hasp_proto::wire::ErrorCode::Auth))?;
        let done = self.call(None, &finish)?;
        Ok((done.session_id, key.token(&done.session_id)))
    }

    pub fn reauth(
        &self,
        person: &Person,
        token: &SessionToken,
    ) -> Result<(), hasp_proto::wire::WireError> {
        let (state, ke1) = OpaqueClientLogin::start(&person.opk)
            .map_err(|_| hasp_proto::wire::WireError::new(hasp_proto::wire::ErrorCode::Internal))?;
        let response = self.call(
            Some(token),
            &hasp_proto::wire::ReauthStart { ke1: ke1.into() },
        )?;
        let (handle, ke3, _) = person
            .login_finish(ORIGIN, OpaquePurpose::Reauth, state, &response)
            .map_err(|_| hasp_proto::wire::WireError::new(hasp_proto::wire::ErrorCode::Auth))?;
        self.call(
            Some(token),
            &hasp_proto::wire::ReauthFinish {
                handle,
                ke3: ke3.into(),
            },
        )
        .map(drop)
    }

    pub fn garbage_login(
        &self,
        account_id: AccountId,
    ) -> Result<hasp_proto::wire::LoginFinishResponse, hasp_proto::wire::WireError> {
        let (state, ke1) = OpaqueClientLogin::start(&rnd())
            .map_err(|_| hasp_proto::wire::WireError::new(hasp_proto::wire::ErrorCode::Internal))?;
        drop(state);
        let response = self.call(
            None,
            &LoginStart {
                account_id,
                ke1: ke1.into(),
            },
        )?;
        self.call(
            None,
            &LoginFinish {
                handle: response.handle,
                ke3: vec![9; 64].into(),
                device: DeviceInfo {
                    device_id: DeviceId::from_bytes([1; 16]),
                    platform: "test".to_owned(),
                    label: None,
                },
            },
        )
    }

    pub fn signup(&mut self, login: &str) -> Client {
        let token = self.signup_token();
        let person = Person::new(login);
        let mut vault = VaultModel::new(VaultKind::Private, &person);
        self.try_register(&token, &person, &mut vault)
            .expect("registration");
        let (session_id, session) = self.try_login(&person).expect("login");
        if self.admin.is_none() {
            self.admin = Some(session.clone());
        }
        Client {
            person,
            vault,
            token: session,
            session_id,
        }
    }

    pub fn pull(
        &self,
        client: &Client,
        cursors: &[(VaultId, u64)],
    ) -> Result<hasp_proto::wire::PullResponse, hasp_proto::wire::WireError> {
        self.call(
            Some(&client.token),
            &hasp_proto::wire::Pull {
                vaults: cursors
                    .iter()
                    .map(|(vault_id, seq)| hasp_proto::wire::VaultCursor {
                        vault_id: *vault_id,
                        seq: Seq::new(*seq).expect("seq"),
                    })
                    .collect(),
                notices_after: Uint53::ZERO,
                limit: Uint53::ZERO,
            },
        )
    }
}

impl<S: TestStore> Default for HarnessOf<S> {
    fn default() -> Self {
        Self::new()
    }
}
