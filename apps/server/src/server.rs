use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use hasp_crypto::{
    KemSecretKey, OpaqueServerLogin, OpaqueServerSetup, Prk, SecretKey, SigningKey,
    hkdf_expand_key, hmac_sha256,
};
use hasp_proto::wire::{
    ErrorCode, LoginHandle, Notice, NoticeKind, OpId, Operation, SessionGrant, SessionId,
    SessionToken, SignupToken, TokenKind, WireError, decode_reply, decode_request, encode_reply,
};
use hasp_proto::{
    AccountId, AccountRecord, AccountStatus, Kdf, Seq, Signed, Uint53, VaultId, Wire, Writer,
};

use crate::clock::Clock;
use crate::config::ServerConfig;
use crate::rate::{RateClass, RateKey, RateLimiter};
use crate::store::{NoticeRow, ServerError, SessionRow, Store, TokenRow};

impl From<ServerError> for WireError {
    fn from(_: ServerError) -> Self {
        Self::new(ErrorCode::Internal)
    }
}

const SEEN_GRANULARITY: u64 = 60;

pub(crate) type Res<T> = Result<T, WireError>;

#[derive(Clone, Debug, Default)]
pub struct Caller {
    pub token: Option<SessionToken>,
    pub peer: Option<IpAddr>,
}

impl Caller {
    pub fn anonymous() -> Self {
        Self::default()
    }

    pub fn with_token(token: SessionToken) -> Self {
        Self {
            token: Some(token),
            peer: None,
        }
    }

    #[must_use]
    pub fn from_peer(mut self, peer: IpAddr) -> Self {
        self.peer = Some(peer);
        self
    }
}

pub(crate) struct Call<'a> {
    pub(crate) caller: &'a Caller,
    pub(crate) now: u64,
}

pub(crate) struct PendingLogin {
    pub(crate) login: OpaqueServerLogin,
    pub(crate) account: Option<AccountId>,
    pub(crate) session: Option<SessionId>,
    pub(crate) expires: u64,
}

pub(crate) struct State<S: Store> {
    pub(crate) store: S,
    pub(crate) pending: BTreeMap<LoginHandle, PendingLogin>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Read,
    Write,
}

#[derive(Clone, Copy)]
pub(crate) struct Route {
    pub(crate) mode: Mode,
}

pub struct Server<S: Store> {
    pub(crate) config: ServerConfig,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) limiter: Arc<dyn RateLimiter>,
    pub(crate) setup: OpaqueServerSetup,
    pub(crate) prelogin_key: SecretKey,
    pub(crate) decoy_record: Vec<u8>,
    state: Mutex<State<S>>,
}

impl<S: Store> std::fmt::Debug for Server<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Server(..)")
    }
}

pub(crate) fn ts(value: u64) -> Uint53 {
    Uint53::new(value.min(Uint53::MAX)).unwrap_or(Uint53::ZERO)
}

fn stream_key(master: &SecretKey, label: Kdf) -> Res<SecretKey> {
    let prk = Prk::from_secret(SecretKey::from_bytes(*master.expose()));
    let mut w = Writer::new();
    w.array(1)?;
    w.text(label.name())?;
    Ok(hkdf_expand_key(&prk, &w.into_bytes())?)
}

fn decoy_account_record(key: &SecretKey) -> Res<Vec<u8>> {
    let seed = |label: &[u8]| SecretKey::from_bytes(hmac_sha256(key, label));
    let kem_seed = SecretKey::from_bytes(hmac_sha256(key, b"decoy-kem"));
    let record = AccountRecord {
        account_id: AccountId::from_bytes([0; 16]),
        seq: Seq::ZERO,
        prev: None,
        ik_pk: SigningKey::from_seed(&seed(b"decoy-ik")).verifying_key(),
        kem_pk: KemSecretKey::from_seed(&kem_seed)?.public_key(),
        kdf: crate::ops::auth::FLOOR,
        status: AccountStatus::Active,
        rc_gen: Uint53::ZERO,
        min_v: Uint53::ZERO,
        created: Uint53::ZERO,
    };
    Ok(record.to_cbor()?)
}

impl<S: Store> Server<S> {
    pub fn new(
        config: ServerConfig,
        store: S,
        clock: Arc<dyn Clock>,
        limiter: Arc<dyn RateLimiter>,
    ) -> Result<Self, WireError> {
        let setup = OpaqueServerSetup::derive(&config.server_master)?;
        let prelogin_key = stream_key(&config.server_master, Kdf::SrvPrelogin)?;
        let decoy_record = decoy_account_record(&prelogin_key)?;
        Ok(Self {
            config,
            clock,
            limiter,
            setup,
            prelogin_key,
            decoy_record,
            state: Mutex::new(State {
                store,
                pending: BTreeMap::new(),
            }),
        })
    }

    pub fn server_public_key(&self) -> [u8; 32] {
        self.setup.public_key()
    }

    pub fn origin(&self) -> &str {
        &self.config.origin
    }

    /// Returned only while no account exists; the account created with it becomes the instance
    /// admin.
    pub fn issue_bootstrap_token(&self) -> Result<SignupToken, WireError> {
        let now = self.clock.now();
        let mut guard = self.lock()?;
        if guard.store.accounts().len()? > 0 {
            return Err(ErrorCode::Conflict.into());
        }
        let token = SignupToken::random()?;
        guard.store.signup_tokens().put(
            token.hash(),
            TokenRow {
                creator: None,
                target: None,
                expires: now.saturating_add(self.config.signup_ttl),
                used_by: None,
                kind: TokenKind::Signup,
                makes_admin: true,
            },
        )?;
        Ok(token)
    }

    pub fn call<O: Operation>(
        &self,
        caller: &Caller,
        request: &O,
    ) -> Result<O::Response, WireError> {
        let body = request.to_cbor()?;
        let reply = self.handle(caller, O::ID, &body);
        decode_reply::<O::Response>(&reply)?
    }

    pub fn handle(&self, caller: &Caller, op: OpId, body: &[u8]) -> Vec<u8> {
        crate::ops::dispatch(self, caller, op, body)
    }

    pub(crate) fn invoke<O, F>(&self, caller: &Caller, body: &[u8], route: Route, f: F) -> Vec<u8>
    where
        O: Operation,
        F: FnOnce(&Self, &mut State<S>, &Call<'_>, O) -> Res<O::Response>,
    {
        let result = self.run(caller, body, route, f);
        encode_reply(&result).unwrap_or_else(|_| {
            encode_reply::<O::Response>(&Err(WireError::new(ErrorCode::Internal)))
                .unwrap_or_default()
        })
    }

    fn run<O, F>(&self, caller: &Caller, body: &[u8], route: Route, f: F) -> Res<O::Response>
    where
        O: Operation,
        F: FnOnce(&Self, &mut State<S>, &Call<'_>, O) -> Res<O::Response>,
    {
        let request = decode_request::<O>(body)?;
        let call = Call {
            caller,
            now: self.clock.now(),
        };
        let mut guard = self.lock()?;
        let st = &mut *guard;
        if route.mode == Mode::Write {
            st.store.begin()?;
        }
        let result = f(self, st, &call, request);
        if route.mode == Mode::Write {
            if result.is_ok() {
                st.store.commit()?;
            } else {
                st.store.rollback()?;
            }
        }
        result
    }

    fn lock(&self) -> Res<std::sync::MutexGuard<'_, State<S>>> {
        match self.state.lock() {
            Ok(guard) => Ok(guard),
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                let _rolled = guard.store.rollback();
                guard.pending.clear();
                self.state.clear_poison();
                Ok(guard)
            }
        }
    }

    pub fn bearer_live(&self, token: &SessionToken, recovery: bool) -> bool {
        let now = self.clock.now();
        let hash = token.hash();
        let Ok(mut guard) = self.lock() else {
            return false;
        };
        let store = &mut guard.store;
        if recovery {
            let rows = store.recovery_sessions().range(
                &hasp_proto::wire::RecoveryId::from_bytes([0; 16]),
                &hasp_proto::wire::RecoveryId::from_bytes([0xff; 16]),
            );
            return rows.is_ok_and(|rows| {
                rows.iter().any(|(_, row)| {
                    row.token_hash == Some(hash)
                        && row.state == crate::store::RecoveryState::Released
                })
            });
        }
        let Ok(Some(sid)) = store.session_tokens().get(&hash) else {
            return false;
        };
        store
            .sessions()
            .get(&sid)
            .ok()
            .flatten()
            .is_some_and(|row| now < row.idle_expires && now < row.abs_expires)
    }

    pub(crate) fn admit(
        &self,
        call: &Call<'_>,
        class: RateClass,
        subject: Option<&[u8]>,
    ) -> Res<()> {
        self.limiter
            .admit(
                class,
                &RateKey {
                    peer: call.caller.peer,
                    subject,
                },
                call.now,
            )
            .map_err(|limited| WireError::retry_after(ErrorCode::RateLimited, limited.retry_after))
    }

    pub(crate) fn login_outcome(&self, call: &Call<'_>, subject: &[u8], ok: bool) {
        let key = RateKey {
            peer: call.caller.peer,
            subject: Some(subject),
        };
        if ok {
            self.limiter
                .record_success(RateClass::Login, &key, call.now);
        } else {
            self.limiter
                .record_failure(RateClass::Login, &key, call.now);
        }
    }

    pub(crate) fn session(&self, st: &mut State<S>, call: &Call<'_>) -> Res<SessionRow> {
        let token = call.caller.token.as_ref().ok_or(ErrorCode::Auth)?;
        let hash = token.hash();
        let sid = st
            .store
            .session_tokens()
            .get(&hash)?
            .ok_or(ErrorCode::Auth)?;
        let mut row = st.store.sessions().get(&sid)?.ok_or(ErrorCode::Auth)?;
        if call.now >= row.idle_expires || call.now >= row.abs_expires {
            remove_session(st, &row)?;
            return Err(ErrorCode::Auth.into());
        }
        let account = st
            .store
            .accounts()
            .get(&row.account_id)?
            .ok_or(ErrorCode::Auth)?;
        if account.state != crate::store::AccountState::Active {
            return Err(ErrorCode::Auth.into());
        }
        self.admit(call, RateClass::General, Some(row.session_id.as_bytes()))?;
        if call.now.saturating_sub(row.last_seen) >= SEEN_GRANULARITY {
            row.last_seen = call.now;
            row.idle_expires = call
                .now
                .saturating_add(self.config.idle_expiry)
                .min(row.abs_expires);
            st.store.sessions().put(row.session_id, row.clone())?;
        }
        Ok(row)
    }

    pub(crate) fn reauthed(&self, st: &mut State<S>, call: &Call<'_>) -> Res<SessionRow> {
        let row = self.session(st, call)?;
        if call.now >= row.reauth_until {
            return Err(ErrorCode::ReauthRequired.into());
        }
        Ok(row)
    }

    pub(crate) fn admin(&self, st: &mut State<S>, call: &Call<'_>) -> Res<SessionRow> {
        let row = self.session(st, call)?;
        let account = st
            .store
            .accounts()
            .get(&row.account_id)?
            .ok_or(ErrorCode::Auth)?;
        if !account.is_admin {
            return Err(ErrorCode::Authz.into());
        }
        Ok(row)
    }

    pub(crate) fn mint_session(
        &self,
        st: &mut State<S>,
        now: u64,
        new: &NewSession<'_>,
    ) -> Res<SessionGrantTimes> {
        let NewSession {
            account,
            device,
            sid,
            token,
        } = *new;
        if device.platform.len() > 64 || device.platform.is_empty() {
            return Err(ErrorCode::Format.into());
        }
        let abs_expires = now.saturating_add(self.config.absolute_expiry);
        let idle_expires = now.saturating_add(self.config.idle_expiry).min(abs_expires);
        let row = SessionRow {
            session_id: sid,
            account_id: account,
            token_hash: token.hash(),
            device_id: device.device_id,
            platform: device.platform.clone(),
            label: device.label.clone(),
            created: now,
            last_seen: now,
            idle_expires,
            abs_expires,
            reauth_until: 0,
        };
        st.store.session_tokens().put(row.token_hash, sid)?;
        st.store.sessions().put(sid, row)?;
        Ok(SessionGrantTimes {
            idle_expires,
            abs_expires,
        })
    }

    pub(crate) fn grant(
        &self,
        st: &mut State<S>,
        now: u64,
        account: AccountId,
        device: &hasp_proto::wire::DeviceInfo,
    ) -> Res<SessionGrant> {
        let sid = SessionId::random()?;
        let token = SessionToken::random()?;
        let new = NewSession {
            account,
            device,
            sid,
            token: &token,
        };
        let times = self.mint_session(st, now, &new)?;
        Ok(SessionGrant {
            session_id: sid,
            token,
            idle_expires: ts(times.idle_expires),
            abs_expires: ts(times.abs_expires),
        })
    }

    pub(crate) fn health(&self) -> hasp_proto::wire::HealthResponse {
        hasp_proto::wire::HealthResponse {
            min_protocol: ts(hasp_proto::wire::PROTOCOL_VERSION),
            max_protocol: ts(hasp_proto::wire::PROTOCOL_VERSION),
            server_version: env!("CARGO_PKG_VERSION").to_owned(),
            features: Vec::new(),
        }
    }

    pub fn sweep(&self) -> Result<(), WireError> {
        let now = self.clock.now();
        let mut guard = self.lock()?;
        let st = &mut *guard;
        st.store.begin()?;
        let result = crate::ops::sweep(self, st, now);
        if result.is_ok() {
            st.store.commit()?;
        } else {
            st.store.rollback()?;
        }
        result
    }

    pub fn writable(&self) -> bool {
        self.with_store(|store| store.begin().and_then(|()| store.rollback()).is_ok())
            .unwrap_or(false)
    }

    pub fn with_store<R>(&self, f: impl FnOnce(&mut S) -> R) -> Result<R, WireError> {
        let mut guard = self.lock()?;
        Ok(f(&mut guard.store))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct NewSession<'a> {
    pub(crate) account: AccountId,
    pub(crate) device: &'a hasp_proto::wire::DeviceInfo,
    pub(crate) sid: SessionId,
    pub(crate) token: &'a SessionToken,
}

pub(crate) struct SessionGrantTimes {
    pub(crate) idle_expires: u64,
    pub(crate) abs_expires: u64,
}

pub(crate) fn remove_session<S: Store>(st: &mut State<S>, row: &SessionRow) -> Res<()> {
    st.store.session_tokens().remove(&row.token_hash)?;
    st.store.sessions().remove(&row.session_id)?;
    Ok(())
}

pub(crate) fn revoke_account_sessions<S: Store>(
    st: &mut State<S>,
    account: &AccountId,
    keep: Option<&SessionId>,
) -> Res<()> {
    for (_, row) in st.store.sessions_of(account)? {
        if Some(&row.session_id) != keep {
            remove_session(st, &row)?;
        }
    }
    Ok(())
}

pub(crate) fn latest_record<S: Store>(
    st: &mut State<S>,
    account: &AccountId,
) -> Res<Option<(Signed<AccountRecord>, AccountRecord)>> {
    let from = (*account, Seq::ZERO);
    let to = (*account, Seq::new(Uint53::MAX).map_err(WireError::from)?);
    match st.store.account_records().last_in(&from, &to)? {
        Some((_, signed)) => {
            let record = signed.unverified()?;
            Ok(Some((signed, record)))
        }
        None => Ok(None),
    }
}

#[derive(Clone, Copy)]
pub(crate) struct NoticeDraft {
    pub(crate) kind: NoticeKind,
    pub(crate) vault_id: Option<VaultId>,
    pub(crate) at: Option<u64>,
}

impl NoticeDraft {
    pub(crate) fn new(kind: NoticeKind) -> Self {
        Self {
            kind,
            vault_id: None,
            at: None,
        }
    }

    pub(crate) fn vault(mut self, vault: VaultId) -> Self {
        self.vault_id = Some(vault);
        self
    }

    pub(crate) fn at(mut self, at: u64) -> Self {
        self.at = Some(at);
        self
    }
}

pub(crate) fn post_notice<S: Store>(
    st: &mut State<S>,
    account: &AccountId,
    draft: NoticeDraft,
    now: u64,
) -> Res<()> {
    let from = (*account, 0_u64);
    let to = (*account, u64::MAX);
    let next = st
        .store
        .notices()
        .last_in(&from, &to)?
        .map_or(1, |((_, id), _)| id.saturating_add(1));
    st.store.notices().put(
        (*account, next),
        NoticeRow {
            kind: draft.kind,
            created: now,
            vault_id: draft.vault_id,
            at: draft.at,
        },
    )?;
    Ok(())
}

pub(crate) fn notices_after<S: Store>(
    st: &mut State<S>,
    account: &AccountId,
    after: u64,
    limit: usize,
) -> Res<Vec<Notice>> {
    let from = (*account, after.saturating_add(1));
    let to = (*account, u64::MAX);
    Ok(st
        .store
        .notices()
        .range(&from, &to)?
        .into_iter()
        .take(limit)
        .map(|((_, id), row)| Notice {
            id: ts(id),
            kind: row.kind,
            created: ts(row.created),
            vault_id: row.vault_id,
            at: row.at.map(ts),
        })
        .collect())
}

pub(crate) fn account_bounds() -> (AccountId, AccountId) {
    (
        AccountId::from_bytes([0; 16]),
        AccountId::from_bytes([0xff; 16]),
    )
}
