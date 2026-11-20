use super::common::{
    Ack, Blob, DeviceInfo, LoginHandle, MemberState, OpId, Operation, RcAuthKey, RecoveryId,
    SessionGrant, SessionId, SessionToken, SignupToken, TokenKind,
};
use super::vault::CommitBundle;
use crate::{
    AccountId, AccountRecord, Hash32, KdfWire, Keyset, RecoveryEnrolment, Role, SealedRaw, Signed,
    Uint53, VaultId, VaultKind,
};

message!(Health {});
message!(HealthResponse {
    0 min_protocol: Uint53,
    1 max_protocol: Uint53,
    2 server_version: String,
    3 features: Vec<String>,
});
operation!(Health => HealthResponse, Health);

message!(ServerKey {});
message!(ServerKeyResponse {
    0 public_key: Blob,
    1 origin: String,
});
operation!(ServerKey => ServerKeyResponse, ServerKey);

message!(Prelogin { 0 login: String });
message!(PreloginResponse {
    0 account_id: AccountId,
    1 kdf: KdfWire,
    2 cred_gen: Uint53,
    3 v: Uint53,
});
operation!(Prelogin => PreloginResponse, Prelogin);

message!(RecoverPrelogin { 0 login: String });
message!(RecoverPreloginResponse {
    0 account_id: AccountId,
    1 rgen: Uint53,
});
operation!(RecoverPrelogin => RecoverPreloginResponse, RecoverPrelogin);

message!(RegisterStart {
    0 token: SignupToken,
    1 login: String,
    2 account_id: AccountId,
    3 request: Blob,
});
message!(OpaqueResponse { 0 response: Blob });
operation!(RegisterStart => OpaqueResponse, RegisterStart);

message!(RegisterFinish {
    0 token: SignupToken,
    1 login: String,
    2 account_id: AccountId,
    3 record: Blob,
    4 account: Signed<AccountRecord>,
    5 keyset: Keyset,
    6 vault: CommitBundle,
    7 self_wrap: SealedRaw,
});
operation!(RegisterFinish => Ack, RegisterFinish);

message!(LoginStart {
    0 account_id: AccountId,
    1 ke1: Blob,
});
message!(LoginStartResponse {
    0 handle: LoginHandle,
    1 ke2: Blob,
});
operation!(LoginStart => LoginStartResponse, LoginStart);

message!(LoginFinish {
    0 handle: LoginHandle,
    1 ke3: Blob,
    2 device: DeviceInfo,
});
message!(LoginFinishResponse {
    0 session_id: SessionId,
    1 idle_expires: Uint53,
    2 abs_expires: Uint53,
});
operation!(LoginFinish => LoginFinishResponse, LoginFinish);

message!(ReauthStart { 0 ke1: Blob });
operation!(ReauthStart => LoginStartResponse, ReauthStart);

message!(ReauthFinish {
    0 handle: LoginHandle,
    1 ke3: Blob,
});
message!(ReauthFinishResponse { 0 reauth_until: Uint53 });
operation!(ReauthFinish => ReauthFinishResponse, ReauthFinish);

message!(Membership {
    0 vault_id: VaultId,
    1 kind: VaultKind,
    2 role: Role,
    3 state: MemberState,
});

message!(AccountGet {});
message!(AccountGetResponse {
    0 records: Vec<Signed<AccountRecord>>,
    1 keyset: Keyset,
    2 memberships: Vec<Membership>,
});
operation!(AccountGet => AccountGetResponse, AccountGet);

message!(AccountLookup { 0 login: String });
message!(AccountLookupResponse { 0 account: Option<Signed<AccountRecord>> });
operation!(AccountLookup => AccountLookupResponse, AccountLookup);

message!(ChangeCredentialStart { 0 request: Blob });
operation!(ChangeCredentialStart => OpaqueResponse, ChangeCredentialStart);

message!(ChangeCredentialFinish {
    0 record: Blob,
    1 keyset: Keyset,
    2 account: Option<Signed<AccountRecord>>,
});
operation!(ChangeCredentialFinish => Ack, ChangeCredentialFinish);

message!(SessionList {});
message!(SessionInfo {
    0 session_id: SessionId,
    1 device_id: crate::DeviceId,
    2 platform: String,
    3 label: Option<SealedRaw>,
    4 created: Uint53,
    5 last_seen: Uint53,
    6 idle_expires: Uint53,
    7 abs_expires: Uint53,
    8 current: bool,
});
message!(SessionListResponse { 0 sessions: Vec<SessionInfo> });
operation!(SessionList => SessionListResponse, SessionList);

message!(SessionRevoke { 0 session_id: SessionId });
operation!(SessionRevoke => Ack, SessionRevoke);

message!(RcSet {
    0 rc: Signed<RecoveryEnrolment>,
    1 rc_wrap: SealedRaw,
    2 h_auth: Hash32,
    3 account: Signed<AccountRecord>,
});
operation!(RcSet => Ack, RcSet);

message!(RecoverStart {
    0 account_id: AccountId,
    1 k_rc_auth: RcAuthKey,
});
message!(RecoverStartResponse {
    0 recovery_id: RecoveryId,
    1 release_at: Uint53,
});
operation!(RecoverStart => RecoverStartResponse, RecoverStart);

message!(RecoverAbort {
    0 recovery_id: Option<RecoveryId>,
    1 k_rc_auth: Option<RcAuthKey>,
});

impl RecoverAbort {
    pub fn by_session() -> Self {
        Self {
            recovery_id: None,
            k_rc_auth: None,
        }
    }

    pub fn by_recovery_code(recovery_id: RecoveryId, k_rc_auth: RcAuthKey) -> Self {
        Self {
            recovery_id: Some(recovery_id),
            k_rc_auth: Some(k_rc_auth),
        }
    }
}
operation!(RecoverAbort => Ack, RecoverAbort);

message!(RecoverFetch {
    0 recovery_id: RecoveryId,
    1 k_rc_auth: RcAuthKey,
});
message!(RecoverFetchResponse {
    0 token: SessionToken,
    1 enrolment: Signed<RecoveryEnrolment>,
    2 rc_wrap: SealedRaw,
    3 keyset: Keyset,
    4 records: Vec<Signed<AccountRecord>>,
});
operation!(RecoverFetch => RecoverFetchResponse, RecoverFetch);

message!(RecoverRegisterStart {
    0 recovery_id: RecoveryId,
    1 request: Blob,
});
operation!(RecoverRegisterStart => OpaqueResponse, RecoverRegisterStart);

message!(RecoverComplete {
    0 recovery_id: RecoveryId,
    1 record: Blob,
    2 keyset: Keyset,
    3 account: Signed<AccountRecord>,
    4 rc: Signed<RecoveryEnrolment>,
    5 rc_wrap: SealedRaw,
    6 h_auth: Hash32,
    7 device: DeviceInfo,
});
operation!(RecoverComplete => SessionGrant, RecoverComplete);

message!(ReregisterStart {
    0 token: SignupToken,
    1 request: Blob,
});
operation!(ReregisterStart => OpaqueResponse, ReregisterStart);

message!(ReregisterFinish {
    0 token: SignupToken,
    1 record: Blob,
});
operation!(ReregisterFinish => Ack, ReregisterFinish);

message!(AccountDelete { 0 account: Signed<AccountRecord> });
operation!(AccountDelete => Ack, AccountDelete);

message!(AdminTokenCreate { 0 kind: TokenKind });
message!(AdminTokenResponse {
    0 token: SignupToken,
    1 expires: Uint53,
});
operation!(AdminTokenCreate => AdminTokenResponse, AdminTokenCreate);

message!(AdminAccountList {});
message!(AdminAccount {
    0 account_id: AccountId,
    1 login: String,
    2 disabled: bool,
    3 is_admin: bool,
    4 created: Uint53,
});
message!(AdminAccountListResponse { 0 accounts: Vec<AdminAccount> });
operation!(AdminAccountList => AdminAccountListResponse, AdminAccountList);

message!(AdminAccountUpdate {
    0 account_id: AccountId,
    1 disabled: bool,
    2 is_admin: bool,
});
operation!(AdminAccountUpdate => Ack, AdminAccountUpdate);

message!(AdminAccountDelete { 0 account_id: AccountId });
operation!(AdminAccountDelete => Ack, AdminAccountDelete);
