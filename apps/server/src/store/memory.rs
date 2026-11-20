use std::collections::BTreeMap;
use std::sync::Arc;

use hasp_proto::wire::{RecoveryId, SessionId};
use hasp_proto::{
    AccountId, AccountRecord, AttId, Epoch, Esid, Hash32, InviteId, Keyset, Rver, SealedRaw, Seq,
    Signed, VaultId,
};

use super::{
    AccountRow, AttachmentRow, EnrolRow, InviteRow, ItemKey, ItemRow, ManifestRow, MemberRow,
    NoticeRow, OpaqueRow, RecoveryRow, RecoverySessionRow, RosterRow, SessionRow, ShareRow, Store,
    StoreResult, Table, TokenRow, VaultRow,
};

#[derive(Clone, Debug)]
struct MemTable<K, V>(BTreeMap<K, V>);

impl<K, V> Default for MemTable<K, V> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl<K: Ord + Clone, V: Clone> Table<K, V> for MemTable<K, V> {
    fn get(&self, key: &K) -> StoreResult<Option<V>> {
        Ok(self.0.get(key).cloned())
    }

    fn put(&mut self, key: K, value: V) -> StoreResult<()> {
        self.0.insert(key, value);
        Ok(())
    }

    fn remove(&mut self, key: &K) -> StoreResult<Option<V>> {
        Ok(self.0.remove(key))
    }

    fn range(&self, from: &K, to: &K) -> StoreResult<Vec<(K, V)>> {
        if from > to {
            return Ok(Vec::new());
        }
        Ok(self
            .0
            .range(from..=to)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }

    fn last_in(&self, from: &K, to: &K) -> StoreResult<Option<(K, V)>> {
        if from > to {
            return Ok(None);
        }
        Ok(self
            .0
            .range(from..=to)
            .next_back()
            .map(|(k, v)| (k.clone(), v.clone())))
    }

    fn len(&self) -> StoreResult<usize> {
        Ok(self.0.len())
    }
}

#[derive(Clone, Debug, Default)]
struct Tables {
    accounts: MemTable<AccountId, AccountRow>,
    logins: MemTable<String, AccountId>,
    account_records: MemTable<(AccountId, Seq), Signed<AccountRecord>>,
    opaque_records: MemTable<AccountId, OpaqueRow>,
    keysets: MemTable<AccountId, Keyset>,
    signup_tokens: MemTable<Hash32, TokenRow>,
    sessions: MemTable<SessionId, SessionRow>,
    session_tokens: MemTable<Hash32, SessionId>,
    enrol_channels: MemTable<Esid, EnrolRow>,
    recovery_enrolments: MemTable<(AccountId, u64), RecoveryRow>,
    recovery_sessions: MemTable<RecoveryId, RecoverySessionRow>,
    notices: MemTable<(AccountId, u64), NoticeRow>,
    vaults: MemTable<VaultId, VaultRow>,
    rosters: MemTable<(VaultId, Rver), RosterRow>,
    manifests: MemTable<(VaultId, Seq), ManifestRow>,
    members: MemTable<(VaultId, AccountId), MemberRow>,
    memberships: MemTable<(AccountId, VaultId), ()>,
    shares: MemTable<(VaultId, Epoch, AccountId), ShareRow>,
    self_wraps: MemTable<(AccountId, VaultId, Epoch), SealedRaw>,
    items: MemTable<ItemKey, ItemRow>,
    invites: MemTable<InviteId, InviteRow>,
    attachments: MemTable<AttId, AttachmentRow>,
    attachment_chunks: MemTable<(AttId, u64), Arc<Vec<u8>>>,
    commit_log: MemTable<(VaultId, Seq), Hash32>,
}

/// A transaction is a snapshot of every table, so this suits tests and nothing larger.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    tables: Tables,
    snapshot: Option<Tables>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

macro_rules! accessor {
    ($name:ident, $key:ty, $value:ty) => {
        fn $name(&mut self) -> &mut dyn Table<$key, $value> {
            &mut self.tables.$name
        }
    };
}

impl Store for MemoryStore {
    fn begin(&mut self) -> StoreResult<()> {
        self.snapshot = Some(self.tables.clone());
        Ok(())
    }

    fn commit(&mut self) -> StoreResult<()> {
        self.snapshot = None;
        Ok(())
    }

    fn rollback(&mut self) -> StoreResult<()> {
        if let Some(snapshot) = self.snapshot.take() {
            self.tables = snapshot;
        }
        Ok(())
    }

    accessor!(accounts, AccountId, AccountRow);
    accessor!(logins, String, AccountId);
    accessor!(account_records, (AccountId, Seq), Signed<AccountRecord>);
    accessor!(opaque_records, AccountId, OpaqueRow);
    accessor!(keysets, AccountId, Keyset);
    accessor!(signup_tokens, Hash32, TokenRow);
    accessor!(sessions, SessionId, SessionRow);
    accessor!(session_tokens, Hash32, SessionId);
    accessor!(enrol_channels, Esid, EnrolRow);
    accessor!(recovery_enrolments, (AccountId, u64), RecoveryRow);
    accessor!(recovery_sessions, RecoveryId, RecoverySessionRow);
    accessor!(notices, (AccountId, u64), NoticeRow);
    accessor!(vaults, VaultId, VaultRow);
    accessor!(rosters, (VaultId, Rver), RosterRow);
    accessor!(manifests, (VaultId, Seq), ManifestRow);
    accessor!(members, (VaultId, AccountId), MemberRow);
    accessor!(memberships, (AccountId, VaultId), ());
    accessor!(shares, (VaultId, Epoch, AccountId), ShareRow);
    accessor!(self_wraps, (AccountId, VaultId, Epoch), SealedRaw);
    accessor!(items, ItemKey, ItemRow);
    accessor!(invites, InviteId, InviteRow);
    accessor!(attachments, AttId, AttachmentRow);
    accessor!(attachment_chunks, (AttId, u64), Arc<Vec<u8>>);
    accessor!(commit_log, (VaultId, Seq), Hash32);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_restores_every_table_and_commit_keeps_changes() {
        let mut store = MemoryStore::new();
        let id = InviteId::from_bytes([1; 16]);
        store
            .commit_log()
            .put(
                (VaultId::from_bytes([1; 16]), Seq::ZERO),
                Hash32::from_bytes([1; 32]),
            )
            .unwrap();
        store.begin().unwrap();
        store
            .commit_log()
            .put(
                (VaultId::from_bytes([2; 16]), Seq::ZERO),
                Hash32::from_bytes([2; 32]),
            )
            .unwrap();
        store.rollback().unwrap();
        assert_eq!(store.commit_log().len().unwrap(), 1);
        store.begin().unwrap();
        store
            .commit_log()
            .put(
                (VaultId::from_bytes([2; 16]), Seq::ZERO),
                Hash32::from_bytes([2; 32]),
            )
            .unwrap();
        store.commit().unwrap();
        store.rollback().unwrap();
        assert_eq!(store.commit_log().len().unwrap(), 2);
        assert!(store.invites().get(&id).unwrap().is_none());
    }

    #[test]
    fn ranges_are_inclusive_and_ordered() {
        let mut store = MemoryStore::new();
        let vault = VaultId::from_bytes([1; 16]);
        for n in 1..=5 {
            store
                .commit_log()
                .put(
                    (vault, Seq::new(n).unwrap()),
                    Hash32::from_bytes([u8::try_from(n).unwrap(); 32]),
                )
                .unwrap();
        }
        let from = (vault, Seq::new(2).unwrap());
        let to = (vault, Seq::new(4).unwrap());
        assert_eq!(store.commit_log().range(&from, &to).unwrap().len(), 3);
        assert_eq!(
            store
                .commit_log()
                .last_in(&from, &to)
                .unwrap()
                .unwrap()
                .0
                .1
                .get(),
            4
        );
        assert!(store.commit_log().range(&to, &from).unwrap().is_empty());
    }
}
