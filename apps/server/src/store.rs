mod memory;
mod sqlite;

use std::sync::Arc;

use hasp_proto::wire::{InviteState, NoticeKind, TokenKind};
use hasp_proto::wire::{RecoveryId, SessionId};
use hasp_proto::{
    AccountId, AccountRecord, AttId, DeviceId, Dissolve, Epoch, Esid, Hash32, InviteId, ItemId,
    ItemWire, Keyset, LeaveRequest, Manifest, RecoveryEnrolment, Role, Roster, Rver, SealedRaw,
    Seq, Share, Signed, VaultId, VaultKind, Version,
};

pub use memory::MemoryStore;
pub use sqlite::{Durability, SchemaStatus, SqliteStore};
pub(crate) use sqlite::{
    InstanceLock, connect, connect_read_only, latest_schema, schema_status, vacuum_into,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ServerError {
    #[error("storage failure")]
    Store,
}

pub type StoreResult<T> = Result<T, ServerError>;

pub trait Table<K, V> {
    fn get(&self, key: &K) -> StoreResult<Option<V>>;
    fn put(&mut self, key: K, value: V) -> StoreResult<()>;
    fn remove(&mut self, key: &K) -> StoreResult<Option<V>>;
    fn range(&self, from: &K, to: &K) -> StoreResult<Vec<(K, V)>>;
    fn last_in(&self, from: &K, to: &K) -> StoreResult<Option<(K, V)>>;
    fn len(&self) -> StoreResult<usize>;
    fn is_empty(&self) -> StoreResult<bool> {
        Ok(self.len()? == 0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountState {
    Active,
    Disabled,
}

#[derive(Clone, Debug)]
pub struct AccountRow {
    pub account_id: AccountId,
    pub login: String,
    pub notify_email: Option<String>,
    pub is_admin: bool,
    pub state: AccountState,
    pub cred_gen: u64,
    pub created: u64,
}

#[derive(Clone, Debug)]
pub struct OpaqueRow {
    pub record: Vec<u8>,
    pub cred_gen: u64,
}

#[derive(Clone, Debug)]
pub struct TokenRow {
    pub creator: Option<AccountId>,
    pub target: Option<AccountId>,
    pub expires: u64,
    pub used_by: Option<AccountId>,
    pub kind: TokenKind,
    pub makes_admin: bool,
}

#[derive(Clone, Debug)]
pub struct SessionRow {
    pub session_id: SessionId,
    pub account_id: AccountId,
    pub token_hash: Hash32,
    pub device_id: DeviceId,
    pub platform: String,
    pub label: Option<SealedRaw>,
    pub created: u64,
    pub last_seen: u64,
    pub idle_expires: u64,
    pub abs_expires: u64,
    pub reauth_until: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrolState {
    Open,
    Approved,
    Aborted,
}

#[derive(Clone, Debug)]
pub struct EnrolRow {
    pub account_id: AccountId,
    pub session_id: SessionId,
    pub expires: u64,
    pub state: EnrolState,
    pub slots: Vec<(u64, Vec<u8>)>,
    pub attempts: u32,
}

#[derive(Clone, Debug)]
pub struct RecoveryRow {
    pub enrolment: Signed<RecoveryEnrolment>,
    pub rc_wrap: SealedRaw,
    pub h_auth: Hash32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryState {
    Pending,
    Released,
    Aborted,
    Done,
}

#[derive(Clone, Debug)]
pub struct RecoverySessionRow {
    pub account_id: AccountId,
    pub rgen: u64,
    pub started: u64,
    pub release_at: u64,
    pub state: RecoveryState,
    pub source: Option<String>,
    pub token_hash: Option<Hash32>,
}

#[derive(Clone, Debug)]
pub struct NoticeRow {
    pub kind: NoticeKind,
    pub created: u64,
    pub vault_id: Option<VaultId>,
    pub at: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultPhase {
    Active,
    Dissolved,
}

#[derive(Clone, Debug)]
pub struct VaultRow {
    pub kind: VaultKind,
    pub owner: AccountId,
    pub head_seq: Seq,
    pub head_hash: Hash32,
    pub rver: Rver,
    pub epoch: Epoch,
    pub state: VaultPhase,
    pub dissolve: Option<Signed<Dissolve>>,
    pub created: u64,
}

#[derive(Clone, Debug)]
pub struct RosterRow {
    pub roster: Signed<Roster>,
    pub seq: Seq,
}

#[derive(Clone, Debug)]
pub struct ManifestRow {
    pub manifest: Signed<Manifest>,
    pub author: AccountId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberStatus {
    Invited,
    Active,
    Leaving,
    Removed,
    Dissolved,
}

#[derive(Clone, Debug)]
pub struct MemberRow {
    pub role: Role,
    pub state: MemberStatus,
    pub rver: Rver,
    pub leave: Option<Signed<LeaveRequest>>,
}

#[derive(Clone, Debug)]
pub struct ShareRow {
    pub share: Signed<Share>,
    pub seq: Seq,
}

#[derive(Clone, Debug)]
pub struct ItemRow {
    pub wire: ItemWire,
    pub h_item: Hash32,
    pub tomb: bool,
    pub size: u64,
    pub seq: Seq,
    pub current: bool,
}

#[derive(Clone, Debug)]
pub struct InviteRow {
    pub vault_id: VaultId,
    pub inviter: AccountId,
    pub role: Role,
    pub expires: u64,
    pub state: InviteState,
    pub invitee: Option<AccountId>,
    pub accept: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachmentState {
    Uploading,
    Complete,
}

#[derive(Clone, Debug)]
pub struct AttachmentRow {
    pub vault_id: VaultId,
    pub size: u64,
    pub chunks: u64,
    pub state: AttachmentState,
    pub created: u64,
    pub refs: u64,
}

pub type ItemKey = (VaultId, ItemId, Version, Epoch);

pub trait Store: Send {
    fn begin(&mut self) -> StoreResult<()>;
    fn commit(&mut self) -> StoreResult<()>;
    fn rollback(&mut self) -> StoreResult<()>;

    fn accounts(&mut self) -> &mut dyn Table<AccountId, AccountRow>;
    fn logins(&mut self) -> &mut dyn Table<String, AccountId>;
    fn account_records(&mut self) -> &mut dyn Table<(AccountId, Seq), Signed<AccountRecord>>;
    fn opaque_records(&mut self) -> &mut dyn Table<AccountId, OpaqueRow>;
    fn keysets(&mut self) -> &mut dyn Table<AccountId, Keyset>;
    fn signup_tokens(&mut self) -> &mut dyn Table<Hash32, TokenRow>;
    fn sessions(&mut self) -> &mut dyn Table<SessionId, SessionRow>;
    fn session_tokens(&mut self) -> &mut dyn Table<Hash32, SessionId>;
    fn enrol_channels(&mut self) -> &mut dyn Table<Esid, EnrolRow>;
    fn recovery_enrolments(&mut self) -> &mut dyn Table<(AccountId, u64), RecoveryRow>;
    fn recovery_sessions(&mut self) -> &mut dyn Table<RecoveryId, RecoverySessionRow>;
    fn notices(&mut self) -> &mut dyn Table<(AccountId, u64), NoticeRow>;
    fn vaults(&mut self) -> &mut dyn Table<VaultId, VaultRow>;
    fn rosters(&mut self) -> &mut dyn Table<(VaultId, Rver), RosterRow>;
    fn manifests(&mut self) -> &mut dyn Table<(VaultId, Seq), ManifestRow>;
    fn members(&mut self) -> &mut dyn Table<(VaultId, AccountId), MemberRow>;
    fn memberships(&mut self) -> &mut dyn Table<(AccountId, VaultId), ()>;
    fn shares(&mut self) -> &mut dyn Table<(VaultId, Epoch, AccountId), ShareRow>;
    fn self_wraps(&mut self) -> &mut dyn Table<(AccountId, VaultId, Epoch), SealedRaw>;
    fn items(&mut self) -> &mut dyn Table<ItemKey, ItemRow>;
    fn invites(&mut self) -> &mut dyn Table<InviteId, InviteRow>;
    fn attachments(&mut self) -> &mut dyn Table<AttId, AttachmentRow>;
    fn attachment_chunks(&mut self) -> &mut dyn Table<(AttId, u64), Arc<Vec<u8>>>;
    fn commit_log(&mut self) -> &mut dyn Table<(VaultId, Seq), Hash32>;

    fn sessions_of(&mut self, account: &AccountId) -> StoreResult<Vec<(SessionId, SessionRow)>> {
        let rows = self.sessions().range(
            &SessionId::from_bytes([0; 16]),
            &SessionId::from_bytes([0xff; 16]),
        )?;
        Ok(rows
            .into_iter()
            .filter(|(_, row)| row.account_id == *account)
            .collect())
    }

    fn recovery_sessions_of(
        &mut self,
        account: &AccountId,
    ) -> StoreResult<Vec<(RecoveryId, RecoverySessionRow)>> {
        let rows = self.recovery_sessions().range(
            &RecoveryId::from_bytes([0; 16]),
            &RecoveryId::from_bytes([0xff; 16]),
        )?;
        Ok(rows
            .into_iter()
            .filter(|(_, row)| row.account_id == *account)
            .collect())
    }
}
