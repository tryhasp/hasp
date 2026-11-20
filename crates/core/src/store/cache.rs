use std::collections::BTreeMap;

use hasp_proto::{
    AccountId, AccountRecord, DeviceId, Epoch, Hash32, ItemId, ItemWire, Keyset, Leaf, Manifest,
    ProtoError, Role, Roster, Rver, SealedRaw, Seq, Signed, VaultId, VaultKind, VaultState,
    Version, Wire,
};

use super::{Batch, BatchOp, Store, StoreError};

const TAG_ACCOUNT: u8 = b'A';
const TAG_BLOB: u8 = b'B';
const TAG_VAULT: u8 = b'V';
const TAG_ITEM: u8 = b'I';
const TAG_WRAP: u8 = b'W';
const TAG_PENDING: u8 = b'P';
const TAG_QUARANTINE: u8 = b'Q';
const TAG_REPAIR: u8 = b'R';
const TAG_EVENT: u8 = b'E';
const TAG_INVITE: u8 = b'J';
const TAG_META: u8 = b'M';
const EVENT_COUNTER: &[u8] = b"event-counter";
const SERVER_BEHIND: &str = "server-behind/";

fn server_behind_name(vault: &VaultId) -> String {
    format!("{SERVER_BEHIND}{}", hasp_crypto::to_hex(vault.as_bytes()))
}

impl From<ProtoError> for StoreError {
    fn from(_: ProtoError) -> Self {
        Self::Record
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockClass {
    Hardware,
    PasswordOnly,
    Extension,
}

#[derive(Clone, Debug)]
pub struct AccountLocal {
    pub origin: String,
    pub login: String,
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub server_fp: [u8; 15],
    pub record: Signed<AccountRecord>,
    pub keyset: Keyset,
    pub max_seen_v: u64,
    pub min_v: u64,
    pub class: UnlockClass,
    pub local_salt: [u8; 16],
    pub local_gen: u64,
    pub notices_after: u64,
    pub platform: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Marks {
    pub seq: Seq,
    pub hash: Hash32,
    pub rver: Rver,
    pub roster_hash: Hash32,
    pub epoch: Epoch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalVaultStatus {
    Active,
    Left,
    Dissolved,
    Removed,
}

#[derive(Clone, Debug)]
pub struct VaultLocal {
    pub vault_id: VaultId,
    pub kind: VaultKind,
    pub role: Role,
    pub status: LocalVaultStatus,
    pub confirmed: bool,
    pub marks: Option<Marks>,
    pub head: Option<Head>,
    pub vk_commits: BTreeMap<u64, Hash32>,
}

#[derive(Clone, Debug)]
pub struct Head {
    pub seq: Seq,
    pub hash: Hash32,
    pub manifest: Signed<Manifest>,
    pub roster: Signed<Roster>,
    pub leaves: Vec<Leaf>,
}

impl Head {
    pub fn from_state(
        state: &VaultState,
        manifest: Signed<Manifest>,
        roster: Signed<Roster>,
    ) -> Self {
        Self {
            seq: state.seq,
            hash: state.hash,
            manifest,
            roster,
            leaves: state.leafset.iter().cloned().collect(),
        }
    }

    pub fn state(&self) -> Result<VaultState, StoreError> {
        let roster = self.roster.unverified()?;
        let leafset = hasp_proto::LeafSet::from_leaves(self.leaves.iter().cloned());
        if hasp_proto::leafset_root(&leafset)? != self.manifest.unverified()?.root {
            return Err(StoreError::Corrupt("leaf set does not match the head root"));
        }
        Ok(VaultState {
            seq: self.seq,
            hash: self.hash,
            rver: roster.rver,
            roster_hash: self.roster.hash(),
            epoch: roster.epoch,
            roster,
            leafset,
        })
    }
}

impl VaultLocal {
    pub fn new(vault_id: VaultId, kind: VaultKind, role: Role) -> Self {
        Self {
            vault_id,
            kind,
            role,
            status: LocalVaultStatus::Active,
            confirmed: false,
            marks: None,
            head: None,
            vk_commits: BTreeMap::new(),
        }
    }

    pub fn state(&self) -> Result<Option<VaultState>, StoreError> {
        self.head.as_ref().map(Head::state).transpose()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingKind {
    Put,
    Delete,
}

#[derive(Clone, Debug)]
pub struct PendingOp {
    pub vault_id: VaultId,
    pub item_id: ItemId,
    pub kind: PendingKind,
    pub base_ver: Version,
    pub wire: ItemWire,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantineInfo {
    pub vault_id: VaultId,
    pub check: String,
    pub seq: u64,
    pub author: Option<AccountId>,
    pub bad_hash: Option<Hash32>,
    pub last_good_seq: u64,
    pub last_good_hash: Option<Hash32>,
    pub at: u64,
    pub bad_bundle: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRepair {
    pub vault_id: VaultId,
    pub seq: u64,
    pub hash: Hash32,
    pub author: AccountId,
    pub at: u64,
    pub bundle: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    Conflict {
        vault_id: VaultId,
        item_id: ItemId,
        replaced_ver: u64,
        resurrected: bool,
    },
    Removed {
        vault_id: VaultId,
    },
    Dissolved {
        vault_id: VaultId,
    },
    Left {
        vault_id: VaultId,
    },
    LeaveRequested {
        vault_id: VaultId,
        account: AccountId,
    },
    Quarantined {
        vault_id: VaultId,
        check: String,
    },
    NeedsAttention {
        vault_id: VaultId,
        reason: String,
    },
    RetentionFallback {
        vault_id: VaultId,
        from_seq: u64,
        to_seq: u64,
    },
    Server {
        kind: u64,
        vault_id: Option<VaultId>,
        at: Option<u64>,
    },
    ServerBehind {
        vault_id: VaultId,
        server_seq: u64,
        local_seq: u64,
    },
    RollbackAccepted {
        vault_id: VaultId,
        from_seq: u64,
        to_seq: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub id: u64,
    pub at: u64,
    pub kind: EventKind,
}

#[derive(Debug)]
pub struct Cache<S: Store> {
    store: S,
}

fn key(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![tag];
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

fn item_key(vault: &VaultId, item: &ItemId, ver: Version, epoch: Epoch) -> Vec<u8> {
    key(
        TAG_ITEM,
        &[
            vault.as_bytes(),
            item.as_bytes(),
            &ver.get().to_be_bytes(),
            &epoch.get().to_be_bytes(),
        ],
    )
}

fn id16<const N: usize>(bytes: &[u8]) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::Record)
}

impl<S: Store> Cache<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Applies the batch unless it would lower a vault's stored head: two processes that share
    /// one database (the `AutoFill` extension) cannot make the older write win.
    pub fn commit(&mut self, batch: &Batch) -> Result<(), StoreError> {
        for op in batch.ops() {
            let BatchOp::Put(key, value) = op else {
                continue;
            };
            if key.first() != Some(&TAG_VAULT) {
                continue;
            }
            let Some(stored) = self.store.get(key)? else {
                continue;
            };
            let heads = (
                decode_vault(&stored)?.head.map(|head| head.seq),
                decode_vault(value)?.head.map(|head| head.seq),
            );
            if let (Some(held), Some(next)) = heads
                && next < held
            {
                return Err(StoreError::Stale);
            }
        }
        self.store.apply(batch)
    }

    /// Applies a batch that may lower a vault's head. Only an explicit, user-confirmed
    /// acceptance of an older server state calls this.
    pub(crate) fn commit_rebase(&mut self, batch: &Batch) -> Result<(), StoreError> {
        self.store.apply(batch)
    }

    /// The head `seq` the server last reported for a vault that is behind this device, if the
    /// device has not yet accepted or outgrown it.
    pub fn server_behind(&self, vault: &VaultId) -> Result<Option<u64>, StoreError> {
        self.meta(&server_behind_name(vault))?
            .map(|bytes| Ok(u64::from_be_bytes(id16(&bytes)?)))
            .transpose()
    }

    pub fn account(&self) -> Result<Option<AccountLocal>, StoreError> {
        self.store
            .get(&[TAG_ACCOUNT])?
            .map(|bytes| decode_account(&bytes))
            .transpose()
    }

    pub fn blob(&self, field: u8) -> Result<Option<SealedRaw>, StoreError> {
        self.store
            .get(&key(TAG_BLOB, &[&[field]]))?
            .map(|bytes| SealedRaw::from_cbor(&bytes).map_err(StoreError::from))
            .transpose()
    }

    pub fn vault(&self, vault: &VaultId) -> Result<Option<VaultLocal>, StoreError> {
        self.store
            .get(&key(TAG_VAULT, &[vault.as_bytes()]))?
            .map(|bytes| decode_vault(&bytes))
            .transpose()
    }

    pub fn vaults(&self) -> Result<Vec<VaultLocal>, StoreError> {
        self.store
            .scan(&[TAG_VAULT])?
            .into_iter()
            .map(|(_, bytes)| decode_vault(&bytes))
            .collect()
    }

    pub fn item_wire(
        &self,
        vault: &VaultId,
        item: &ItemId,
        ver: Version,
        epoch: Epoch,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.store.get(&item_key(vault, item, ver, epoch))
    }

    pub fn item_versions(
        &self,
        vault: &VaultId,
        item: &ItemId,
    ) -> Result<Vec<(Version, Epoch, Vec<u8>)>, StoreError> {
        self.store
            .scan(&key(TAG_ITEM, &[vault.as_bytes(), item.as_bytes()]))?
            .into_iter()
            .map(|(k, v)| {
                let tail = k.get(33..).ok_or(StoreError::Record)?;
                let (ver, epoch) = tail.split_at_checked(8).ok_or(StoreError::Record)?;
                let ver =
                    Version::new(u64::from_be_bytes(id16(ver)?)).map_err(|_| StoreError::Record)?;
                let epoch =
                    Epoch::new(u64::from_be_bytes(id16(epoch)?)).map_err(|_| StoreError::Record)?;
                Ok((ver, epoch, v))
            })
            .collect()
    }

    pub fn self_wraps(&self, vault: &VaultId) -> Result<Vec<(Epoch, SealedRaw)>, StoreError> {
        self.store
            .scan(&key(TAG_WRAP, &[vault.as_bytes()]))?
            .into_iter()
            .map(|(k, v)| {
                let tail = k.get(17..).ok_or(StoreError::Record)?;
                let epoch =
                    Epoch::new(u64::from_be_bytes(id16(tail)?)).map_err(|_| StoreError::Record)?;
                Ok((epoch, SealedRaw::from_cbor(&v)?))
            })
            .collect()
    }

    pub fn pending(&self, vault: &VaultId) -> Result<Vec<PendingOp>, StoreError> {
        self.store
            .scan(&key(TAG_PENDING, &[vault.as_bytes()]))?
            .into_iter()
            .map(|(_, bytes)| decode_pending(&bytes))
            .collect()
    }

    pub fn pending_item(
        &self,
        vault: &VaultId,
        item: &ItemId,
    ) -> Result<Option<PendingOp>, StoreError> {
        self.store
            .get(&key(TAG_PENDING, &[vault.as_bytes(), item.as_bytes()]))?
            .map(|bytes| decode_pending(&bytes))
            .transpose()
    }

    pub fn quarantine(&self, vault: &VaultId) -> Result<Option<QuarantineInfo>, StoreError> {
        self.store
            .get(&key(TAG_QUARANTINE, &[vault.as_bytes()]))?
            .map(|bytes| decode_quarantine(&bytes))
            .transpose()
    }

    pub fn pending_repair(&self, vault: &VaultId) -> Result<Option<PendingRepair>, StoreError> {
        self.store
            .get(&key(TAG_REPAIR, &[vault.as_bytes()]))?
            .map(|bytes| decode_repair(&bytes))
            .transpose()
    }

    pub fn invite(&self, vault: &VaultId) -> Result<Option<Vec<u8>>, StoreError> {
        self.store.get(&key(TAG_INVITE, &[vault.as_bytes()]))
    }

    pub fn meta(&self, name: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.store.get(&key(TAG_META, &[name.as_bytes()]))
    }

    pub fn events(&self) -> Result<Vec<Event>, StoreError> {
        self.store
            .scan(&[TAG_EVENT])?
            .into_iter()
            .map(|(_, bytes)| decode_event(&bytes))
            .collect()
    }

    pub fn next_event_id(&self) -> Result<u64, StoreError> {
        match self.meta(std::str::from_utf8(EVENT_COUNTER).map_err(|_| StoreError::Record)?)? {
            Some(bytes) => Ok(u64::from_be_bytes(id16(&bytes)?)),
            None => Ok(1),
        }
    }

    pub fn into_store(self) -> S {
        self.store
    }

    pub fn store(&self) -> &S {
        &self.store
    }
}

#[derive(Debug)]
pub struct Records;

impl Records {
    pub fn put_account(batch: &mut Batch, account: &AccountLocal) -> Result<(), StoreError> {
        batch.put(vec![TAG_ACCOUNT], encode_account(account)?);
        Ok(())
    }

    pub fn put_blob(batch: &mut Batch, field: u8, blob: &SealedRaw) -> Result<(), StoreError> {
        batch.put(key(TAG_BLOB, &[&[field]]), blob.to_cbor()?);
        Ok(())
    }

    pub fn delete_blob(batch: &mut Batch, field: u8) {
        batch.delete(key(TAG_BLOB, &[&[field]]));
    }

    pub fn put_vault(batch: &mut Batch, vault: &VaultLocal) -> Result<(), StoreError> {
        batch.put(
            key(TAG_VAULT, &[vault.vault_id.as_bytes()]),
            encode_vault(vault)?,
        );
        Ok(())
    }

    pub fn delete_vault(batch: &mut Batch, vault: &VaultId) {
        batch.delete(key(TAG_VAULT, &[vault.as_bytes()]));
        for tag in [TAG_ITEM, TAG_WRAP, TAG_PENDING, TAG_QUARANTINE, TAG_INVITE] {
            batch.delete_prefix(key(tag, &[vault.as_bytes()]));
        }
        Self::clear_server_behind(batch, vault);
    }

    pub fn put_item(
        batch: &mut Batch,
        vault: &VaultId,
        at: (&ItemId, Version, Epoch),
        wire: &[u8],
    ) {
        batch.put(item_key(vault, at.0, at.1, at.2), wire.to_vec());
    }

    pub fn delete_item_version(
        batch: &mut Batch,
        vault: &VaultId,
        item: &ItemId,
        ver: Version,
        epoch: Epoch,
    ) {
        batch.delete(item_key(vault, item, ver, epoch));
    }

    pub fn put_self_wrap(
        batch: &mut Batch,
        vault: &VaultId,
        epoch: Epoch,
        wrap: &SealedRaw,
    ) -> Result<(), StoreError> {
        batch.put(
            key(TAG_WRAP, &[vault.as_bytes(), &epoch.get().to_be_bytes()]),
            wrap.to_cbor()?,
        );
        Ok(())
    }

    pub fn put_pending(batch: &mut Batch, op: &PendingOp) -> Result<(), StoreError> {
        batch.put(
            key(
                TAG_PENDING,
                &[op.vault_id.as_bytes(), op.item_id.as_bytes()],
            ),
            encode_pending(op)?,
        );
        Ok(())
    }

    pub fn delete_pending(batch: &mut Batch, vault: &VaultId, item: &ItemId) {
        batch.delete(key(TAG_PENDING, &[vault.as_bytes(), item.as_bytes()]));
    }

    pub fn delete_pending_if(batch: &mut Batch, op: &PendingOp) -> Result<(), StoreError> {
        batch.delete_if(
            key(
                TAG_PENDING,
                &[op.vault_id.as_bytes(), op.item_id.as_bytes()],
            ),
            encode_pending(op)?,
        );
        Ok(())
    }

    pub fn put_quarantine(batch: &mut Batch, info: &QuarantineInfo) -> Result<(), StoreError> {
        batch.put(
            key(TAG_QUARANTINE, &[info.vault_id.as_bytes()]),
            encode_quarantine(info)?,
        );
        Ok(())
    }

    pub fn put_pending_repair(batch: &mut Batch, repair: &PendingRepair) -> Result<(), StoreError> {
        batch.put(
            key(TAG_REPAIR, &[repair.vault_id.as_bytes()]),
            encode_repair(repair)?,
        );
        Ok(())
    }

    pub fn clear_pending_repair(batch: &mut Batch, vault: &VaultId) {
        batch.delete(key(TAG_REPAIR, &[vault.as_bytes()]));
    }

    pub fn clear_quarantine(batch: &mut Batch, vault: &VaultId) {
        batch.delete(key(TAG_QUARANTINE, &[vault.as_bytes()]));
    }

    pub fn put_invite(batch: &mut Batch, vault: &VaultId, code: &[u8]) {
        batch.put(key(TAG_INVITE, &[vault.as_bytes()]), code.to_vec());
    }

    pub fn delete_invite(batch: &mut Batch, vault: &VaultId) {
        batch.delete(key(TAG_INVITE, &[vault.as_bytes()]));
    }

    pub fn put_server_behind(batch: &mut Batch, vault: &VaultId, server_seq: u64) {
        Self::put_meta(batch, &server_behind_name(vault), &server_seq.to_be_bytes());
    }

    pub fn clear_server_behind(batch: &mut Batch, vault: &VaultId) {
        batch.delete(key(TAG_META, &[server_behind_name(vault).as_bytes()]));
    }

    pub fn clear_items(batch: &mut Batch, vault: &VaultId) {
        batch.delete_prefix(key(TAG_ITEM, &[vault.as_bytes()]));
    }

    pub fn delete_meta(batch: &mut Batch, name: &str) {
        batch.delete(key(TAG_META, &[name.as_bytes()]));
    }

    pub fn put_meta(batch: &mut Batch, name: &str, value: &[u8]) {
        batch.put(key(TAG_META, &[name.as_bytes()]), value.to_vec());
    }

    pub fn put_event(batch: &mut Batch, event: &Event) -> Result<(), StoreError> {
        batch.put(
            key(TAG_EVENT, &[&event.id.to_be_bytes()]),
            encode_event(event)?,
        );
        let next = event.id.saturating_add(1);
        Self::put_meta(
            batch,
            std::str::from_utf8(EVENT_COUNTER).map_err(|_| StoreError::Record)?,
            &next.to_be_bytes(),
        );
        Ok(())
    }

    pub fn delete_event(batch: &mut Batch, id: u64) {
        batch.delete(key(TAG_EVENT, &[&id.to_be_bytes()]));
    }
}

mod codec;

use codec::{
    decode_account, decode_event, decode_pending, decode_quarantine, decode_repair, decode_vault,
    encode_account, encode_event, encode_pending, encode_quarantine, encode_repair, encode_vault,
};

#[cfg(test)]
mod tests;
