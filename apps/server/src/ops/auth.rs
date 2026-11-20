use hasp_crypto::hmac_sha256;
use hasp_crypto::{
    OpaqueIdentities, OpaqueLoginBinding, opaque_check_record, opaque_login_start,
    opaque_register_response,
};
use hasp_proto::wire::{
    Ack, ErrorCode, Health, HealthResponse, LoginFinish, LoginFinishResponse, LoginHandle,
    LoginStart, LoginStartResponse, NoticeKind, OpaquePurpose, OpaqueResponse, Prelogin,
    PreloginResponse, ReauthFinish, ReauthFinishResponse, ReauthStart, RecoverPrelogin,
    RecoverPreloginResponse, RegisterFinish, RegisterStart, ReregisterFinish, ReregisterStart,
    ServerKey, ServerKeyResponse, SessionId, SignupToken, WireError, credential_id, opaque_context,
    session_token,
};
use hasp_proto::{
    AccountId, AccountRecord, AccountStatus, KdfWire, OwnKeys, PinState, VaultState, Wire,
    verify_account_record, verify_genesis,
};

use crate::rate::RateClass;
use crate::server::{
    Call, NewSession, NoticeDraft, PendingLogin, Res, Server, State, latest_record, post_notice,
    revoke_account_sessions, ts,
};
use crate::store::{AccountRow, AccountState, OpaqueRow, RecoveryState, Store, TokenRow};
use hasp_proto::wire::TokenKind;

struct VerifiedRegistration {
    now: u64,
    record: AccountRecord,
    state: VaultState,
}

pub(crate) const FLOOR: KdfWire = KdfWire {
    m: 65_536,
    t: 3,
    p: 4,
};
struct Handshake {
    account: AccountId,
    purpose: OpaquePurpose,
    session: Option<SessionId>,
}

const MAX_LOGIN: usize = 256;
const MAX_PENDING: usize = 10_000;

fn check_login(login: &str) -> Res<()> {
    if login.is_empty() || login.len() > MAX_LOGIN || login.trim() != login {
        return Err(ErrorCode::Format.into());
    }
    Ok(())
}

fn first<const N: usize>(bytes: &[u8; 32]) -> [u8; N] {
    let mut out = [0_u8; N];
    for (slot, byte) in out.iter_mut().zip(bytes) {
        *slot = *byte;
    }
    out
}

impl<S: Store> Server<S> {
    pub(crate) fn health_op(
        &self,
        _: &mut State<S>,
        _: &Call<'_>,
        _: Health,
    ) -> Res<HealthResponse> {
        Ok(self.health())
    }

    pub(crate) fn server_key_op(
        &self,
        _: &mut State<S>,
        _: &Call<'_>,
        _: ServerKey,
    ) -> Res<ServerKeyResponse> {
        Ok(ServerKeyResponse {
            public_key: self.server_public_key().to_vec().into(),
            origin: self.origin().to_owned(),
        })
    }

    pub(crate) fn account_kdf(&self, st: &mut State<S>, account: &AccountId) -> Res<KdfWire> {
        if let Some((_, record)) = latest_record(st, account)? {
            return Ok(record.kdf);
        }
        std::hint::black_box(AccountRecord::from_cbor(&self.decoy_record)?);
        Ok(FLOOR)
    }

    fn pseudo_id(&self, login: &str) -> (AccountId, [u8; 32]) {
        let mac = hmac_sha256(&self.prelogin_key, login.as_bytes());
        (AccountId::from_bytes(first::<16>(&mac)), mac)
    }

    fn find_by_login(&self, st: &mut State<S>, login: &str) -> Res<Option<AccountRow>> {
        match st.store.logins().get(&login.to_owned())? {
            Some(id) => Ok(st.store.accounts().get(&id)?),
            None => Ok(None),
        }
    }

    pub(crate) fn prelogin_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: Prelogin,
    ) -> Res<PreloginResponse> {
        self.admit(call, RateClass::Login, None)?;
        check_login(&req.login)?;
        let (pseudo_id, mac) = self.pseudo_id(&req.login);
        let real = self.find_by_login(st, &req.login)?;
        let probe = real.as_ref().map_or(pseudo_id, |row| row.account_id);
        let kdf = self.account_kdf(st, &probe)?;
        let (account_id, kdf, cred_gen) = match real {
            Some(row) => (row.account_id, kdf, row.cred_gen),
            None => (pseudo_id, FLOOR, 1 + u64::from(mac[16] % 3)),
        };
        Ok(PreloginResponse {
            account_id,
            kdf,
            cred_gen: ts(cred_gen),
            v: ts(hasp_proto::wire::PROTOCOL_VERSION),
        })
    }

    pub(crate) fn recover_prelogin_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: RecoverPrelogin,
    ) -> Res<RecoverPreloginResponse> {
        self.admit(call, RateClass::Recovery, None)?;
        check_login(&req.login)?;
        let (pseudo_id, mac) = self.pseudo_id(&req.login);
        let real = self.find_by_login(st, &req.login)?;
        let probe = real.as_ref().map_or(pseudo_id, |row| row.account_id);
        let rgen = latest_record(st, &probe)?.map_or(0, |(_, record)| record.rc_gen.get());
        let (account_id, rgen) = match real {
            Some(row) => (row.account_id, rgen),
            None => (pseudo_id, u64::from(mac[17] % 2)),
        };
        Ok(RecoverPreloginResponse {
            account_id,
            rgen: ts(rgen),
        })
    }

    fn check_token(
        &self,
        st: &mut State<S>,
        token: &SignupToken,
        now: u64,
        kind: TokenKind,
    ) -> Res<TokenRow> {
        let row = st
            .store
            .signup_tokens()
            .get(&token.hash())?
            .ok_or(ErrorCode::Auth)?;
        if row.used_by.is_some() || now >= row.expires || row.kind != kind {
            return Err(ErrorCode::Auth.into());
        }
        Ok(row)
    }

    fn reregister_target(
        &self,
        st: &mut State<S>,
        token: &SignupToken,
        now: u64,
    ) -> Res<(TokenRow, AccountRow)> {
        let row = self.check_token(st, token, now, TokenKind::Reregister)?;
        let target = row.target.ok_or(ErrorCode::Auth)?;
        let account = st
            .store
            .accounts()
            .get(&target)?
            .filter(|account| account.state == AccountState::Active)
            .ok_or(ErrorCode::Auth)?;
        Ok((row, account))
    }

    pub(crate) fn reregister_start_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: ReregisterStart,
    ) -> Res<OpaqueResponse> {
        self.admit(call, RateClass::Register, None)?;
        let (_, account) = self.reregister_target(st, &req.token, call.now)?;
        let response = opaque_register_response(
            &self.setup,
            req.request.as_slice(),
            &credential_id(&account.account_id)?,
        )
        .map_err(|_| ErrorCode::Format)?;
        Ok(OpaqueResponse {
            response: response.into(),
        })
    }

    pub(crate) fn reregister_finish_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: ReregisterFinish,
    ) -> Res<Ack> {
        self.admit(call, RateClass::Register, None)?;
        let (mut token, mut account) = self.reregister_target(st, &req.token, call.now)?;
        opaque_check_record(req.record.as_slice()).map_err(|_| ErrorCode::Format)?;
        let id = account.account_id;
        account.cred_gen = account.cred_gen.saturating_add(1);
        st.store.opaque_records().put(
            id,
            OpaqueRow {
                record: req.record.0,
                cred_gen: account.cred_gen,
            },
        )?;
        st.store.accounts().put(id, account)?;
        revoke_account_sessions(st, &id, None)?;
        token.used_by = Some(id);
        st.store.signup_tokens().put(req.token.hash(), token)?;
        Ok(Ack)
    }

    pub(crate) fn register_start_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: RegisterStart,
    ) -> Res<OpaqueResponse> {
        self.admit(call, RateClass::Register, None)?;
        self.check_token(st, &req.token, call.now, TokenKind::Signup)?;
        check_login(&req.login)?;
        if st.store.logins().get(&req.login)?.is_some()
            || st.store.accounts().get(&req.account_id)?.is_some()
        {
            return Err(ErrorCode::Conflict.into());
        }
        let response = opaque_register_response(
            &self.setup,
            req.request.as_slice(),
            &credential_id(&req.account_id)?,
        )
        .map_err(|_| ErrorCode::Format)?;
        Ok(OpaqueResponse {
            response: response.into(),
        })
    }

    pub(crate) fn register_finish_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: RegisterFinish,
    ) -> Res<Ack> {
        self.admit(call, RateClass::Register, None)?;
        let token = self.check_token(st, &req.token, call.now, TokenKind::Signup)?;
        check_login(&req.login)?;
        if st.store.logins().get(&req.login)?.is_some()
            || st.store.accounts().get(&req.account_id)?.is_some()
        {
            return Err(ErrorCode::Conflict.into());
        }
        let (record, state) = verify_registration(&req)?;
        if st.store.vaults().get(&state.roster.vault_id)?.is_some() {
            return Err(ErrorCode::Conflict.into());
        }
        let verified = VerifiedRegistration {
            now: call.now,
            record,
            state,
        };
        self.store_registration(st, &req, token, &verified)
    }

    fn store_registration(
        &self,
        st: &mut State<S>,
        req: &RegisterFinish,
        mut token: TokenRow,
        verified: &VerifiedRegistration,
    ) -> Res<Ack> {
        let VerifiedRegistration { now, record, state } = verified;
        st.store.accounts().put(
            record.account_id,
            AccountRow {
                account_id: record.account_id,
                login: req.login.clone(),
                notify_email: None,
                is_admin: token.makes_admin,
                state: AccountState::Active,
                cred_gen: 1,
                created: *now,
            },
        )?;
        st.store
            .logins()
            .put(req.login.clone(), record.account_id)?;
        st.store
            .account_records()
            .put((record.account_id, record.seq), req.account.clone())?;
        st.store.opaque_records().put(
            record.account_id,
            OpaqueRow {
                record: req.record.0.clone(),
                cred_gen: 1,
            },
        )?;
        st.store
            .keysets()
            .put(record.account_id, req.keyset.clone())?;
        token.used_by = Some(record.account_id);
        st.store.signup_tokens().put(req.token.hash(), token)?;
        let self_wraps = [hasp_proto::wire::SelfWrapEntry {
            epoch: state.epoch,
            wrap: req.self_wrap.clone(),
        }];
        let stored = super::vault::StoredCommit {
            now: *now,
            account: record.account_id,
            vault_id: state.roster.vault_id,
            base_seq: hasp_proto::Seq::ZERO,
            bundle: &req.vault,
            self_wraps: &self_wraps,
            digest: hasp_proto::Hash32::digest(&[&req.to_cbor()?]),
        };
        self.insert_vault(st, &stored, state)?;
        Ok(Ack)
    }

    fn binding_parts(
        &self,
        st: &mut State<S>,
        account: &AccountId,
        purpose: OpaquePurpose,
    ) -> Res<(Vec<u8>, Vec<u8>)> {
        let kdf = self.account_kdf(st, account)?;
        Ok((
            credential_id(account)?,
            opaque_context(purpose, account, &kdf)?,
        ))
    }

    fn start_opaque(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        handshake: Handshake,
        ke1: &[u8],
    ) -> Res<LoginStartResponse> {
        let Handshake {
            account,
            purpose,
            session,
        } = handshake;
        st.pending.retain(|_, pending| pending.expires > call.now);
        if st.pending.len() >= MAX_PENDING {
            return Err(WireError::retry_after(ErrorCode::RateLimited, 1));
        }
        let row = st.store.accounts().get(&account)?;
        let record = match row {
            Some(_) => st.store.opaque_records().get(&account)?,
            None => None,
        };
        let (credential, context) = self.binding_parts(st, &account, purpose)?;
        let binding = OpaqueLoginBinding {
            credential_id: &credential,
            context: &context,
            ids: OpaqueIdentities {
                client: account.as_bytes(),
                server: self.config.origin.as_bytes(),
            },
        };
        let (login, ke2) = opaque_login_start(
            &self.setup,
            record.as_ref().map(|r| r.record.as_slice()),
            ke1,
            &binding,
        )
        .map_err(|_| ErrorCode::Auth)?;
        let handle = LoginHandle::random()?;
        st.pending.insert(
            handle,
            PendingLogin {
                login,
                account: Some(account),
                session,
                expires: call.now.saturating_add(self.config.pending_login_ttl),
            },
        );
        Ok(LoginStartResponse {
            handle,
            ke2: ke2.into(),
        })
    }

    pub(crate) fn login_start_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: LoginStart,
    ) -> Res<LoginStartResponse> {
        self.admit(call, RateClass::Login, Some(req.account_id.as_bytes()))?;
        let handshake = Handshake {
            account: req.account_id,
            purpose: OpaquePurpose::Login,
            session: None,
        };
        self.start_opaque(st, call, handshake, req.ke1.as_slice())
    }

    pub(crate) fn login_finish_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: LoginFinish,
    ) -> Res<LoginFinishResponse> {
        let pending = st.pending.remove(&req.handle).ok_or(ErrorCode::Auth)?;
        let subject = pending.account.ok_or(ErrorCode::Auth)?;
        if pending.session.is_some() || call.now >= pending.expires {
            return Err(ErrorCode::Auth.into());
        }
        let Ok(key) = pending.login.finish(req.ke3.as_slice()) else {
            self.login_outcome(call, subject.as_bytes(), false);
            return Err(ErrorCode::Auth.into());
        };
        let Some(row) = st.store.accounts().get(&subject)? else {
            self.login_outcome(call, subject.as_bytes(), false);
            return Err(ErrorCode::Auth.into());
        };
        if row.state != AccountState::Active {
            return Err(ErrorCode::Auth.into());
        }
        let sid = SessionId::random()?;
        let token = session_token(key.expose(), &sid)?;
        let new = NewSession {
            account: subject,
            device: &req.device,
            sid,
            token: &token,
        };
        let times = self.mint_session(st, call.now, &new)?;
        self.abort_recoveries(st, &subject, call.now)?;
        self.login_outcome(call, subject.as_bytes(), true);
        Ok(LoginFinishResponse {
            session_id: sid,
            idle_expires: ts(times.idle_expires),
            abs_expires: ts(times.abs_expires),
        })
    }

    pub(crate) fn abort_recoveries(
        &self,
        st: &mut State<S>,
        account: &AccountId,
        now: u64,
    ) -> Res<()> {
        for (id, mut row) in st.store.recovery_sessions_of(account)? {
            if row.state == RecoveryState::Pending {
                row.state = RecoveryState::Aborted;
                st.store.recovery_sessions().put(id, row)?;
                post_notice(
                    st,
                    account,
                    NoticeDraft::new(NoticeKind::RecoveryAborted),
                    now,
                )?;
            }
        }
        Ok(())
    }

    pub(crate) fn reauth_start_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: ReauthStart,
    ) -> Res<LoginStartResponse> {
        let session = self.session(st, call)?;
        self.admit(call, RateClass::Login, Some(session.account_id.as_bytes()))?;
        let handshake = Handshake {
            account: session.account_id,
            purpose: OpaquePurpose::Reauth,
            session: Some(session.session_id),
        };
        self.start_opaque(st, call, handshake, req.ke1.as_slice())
    }

    pub(crate) fn reauth_finish_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: ReauthFinish,
    ) -> Res<ReauthFinishResponse> {
        let mut session = self.session(st, call)?;
        let pending = st.pending.remove(&req.handle).ok_or(ErrorCode::Auth)?;
        if pending.session != Some(session.session_id)
            || pending.account != Some(session.account_id)
            || call.now >= pending.expires
        {
            return Err(ErrorCode::Auth.into());
        }
        if pending.login.finish(req.ke3.as_slice()).is_err() {
            self.login_outcome(call, session.account_id.as_bytes(), false);
            return Err(ErrorCode::Auth.into());
        }
        self.login_outcome(call, session.account_id.as_bytes(), true);
        session.reauth_until = call.now.saturating_add(self.config.reauth_window);
        let until = session.reauth_until;
        st.store.sessions().put(session.session_id, session)?;
        Ok(ReauthFinishResponse {
            reauth_until: ts(until),
        })
    }
}

fn verify_registration(req: &RegisterFinish) -> Res<(AccountRecord, VaultState)> {
    let record = verify_account_record(&req.account, None, &PinState::new())?;
    if record.account_id != req.account_id
        || record.seq.get() != 1
        || record.status != AccountStatus::Active
        || record.rc_gen.get() != 0
    {
        return Err(ErrorCode::Format.into());
    }
    if req.keyset.account_id != req.account_id || req.keyset.generation.get() != 1 {
        return Err(ErrorCode::Format.into());
    }
    opaque_check_record(req.record.as_slice()).map_err(|_| ErrorCode::Format)?;
    let bundle = &req.vault;
    let commit = super::vault::proto_commit(bundle)?;
    let own = OwnKeys {
        account_id: record.account_id,
        ik_pk: record.ik_pk,
        kem_pk: record.kem_pk.clone(),
        retired_kem_pk_hashes: Vec::new(),
    };
    let state = verify_genesis(&commit, &own, &PinState::new())?;
    if state.roster.kind != hasp_proto::VaultKind::Private
        || state.roster.members.len() != 1
        || state.roster.owner().map(|m| m.account_id) != Some(record.account_id)
        || !bundle.shares.is_empty()
    {
        return Err(ErrorCode::Roster.into());
    }
    Ok((record, state))
}
