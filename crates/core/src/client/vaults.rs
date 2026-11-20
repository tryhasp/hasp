mod items;

use hasp_crypto::SecretKey;
use hasp_proto::payload::{self, Hidden, VaultMeta};
use hasp_proto::wire::{Commit, SelfWrapEntry};
use hasp_proto::{
    Aad, Epoch, ItemBody, ItemId, ItemOp, ItemWire, Manifest, Member, OpenedItem, Role, Roster,
    Rver, SealedRaw, Seq, SigLabel, Signed, VaultId, VaultKind, VerifiedRoster, Version, Wire,
    leafset_root, open_item, open_item_unverified, verify_roster, vk_commit,
};
use tokio_util::sync::CancellationToken;

use super::signup::seal_hidden;
use super::{Client, ctx};
use crate::CoreError;
use crate::session::Cancel;
use crate::store::{Batch, LocalVaultStatus, Records, Store, VaultLocal};
use crate::sync::{
    RollbackAccepted, accept_older_server_state, flush_vault, pull_vault_ids, record_events,
    sync_all,
};
use crate::transport::Transport;

const HIDDEN_KINDS: [&str; 3] = [
    payload::KIND_PIN,
    payload::KIND_DEVICE,
    payload::KIND_VAULT_SETTINGS,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultSummary {
    pub vault_id: VaultId,
    pub kind: VaultKind,
    pub role: Role,
    pub name: String,
    pub status: LocalVaultStatus,
    pub confirmed: bool,
    pub quarantined: bool,
    pub repair_pending: bool,
    pub server_behind: Option<u64>,
    pub epoch: u64,
    pub seq: u64,
    pub members: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemSummary {
    pub vault_id: VaultId,
    pub item_id: ItemId,
    pub overview: payload::Overview,
    pub version: u64,
    pub pending: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryEntry {
    pub version: u64,
    pub epoch: u64,
    pub title: String,
    pub client_modified: u64,
}

pub(crate) fn is_hidden(kind: &str) -> bool {
    HIDDEN_KINDS.contains(&kind)
}

pub(crate) struct Opened {
    pub overview: hasp_crypto::SecretBytes,
    pub details: hasp_crypto::SecretBytes,
    pub version: Version,
}

impl<T: Transport, S: Store> Client<T, S> {
    pub(crate) fn local_vault(&self, vault: &VaultId) -> Result<VaultLocal, CoreError> {
        self.cache.vault(vault)?.ok_or(CoreError::NotFound("vault"))
    }

    pub(crate) fn open_current(
        &self,
        local: &VaultLocal,
        item: &ItemId,
    ) -> Result<Option<Opened>, CoreError> {
        let Some(state) = local.state()? else {
            return Ok(None);
        };
        let Some(leaf) = state.leafset.get(item) else {
            return Ok(None);
        };
        self.opened
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let bytes = self
            .cache
            .item_wire(&local.vault_id, item, leaf.ver, leaf.epoch)?
            .ok_or(CoreError::NotFound(
                "item ciphertext withheld by the server",
            ))?;
        let wire = ItemWire::from_cbor(&bytes)?;
        let session = self.unlocked()?;
        let vk = session
            .vk(&local.vault_id, wire.epoch)
            .ok_or(CoreError::Refused("this vault's key is not available"))?;
        match open_item(&wire, &bytes, &state, vk)? {
            OpenedItem::Live {
                overview,
                details,
                ver,
                ..
            } => Ok(Some(Opened {
                overview,
                details,
                version: ver,
            })),
            OpenedItem::Tombstone { .. } => Ok(None),
        }
    }

    fn open_view(&self, local: &VaultLocal, item: &ItemId) -> Result<Option<Opened>, CoreError> {
        let Some(op) = self.cache.pending_item(&local.vault_id, item)? else {
            return self.open_current(local, item);
        };
        if matches!(op.wire.body, ItemBody::Tombstone) {
            return Ok(None);
        }
        self.opened
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let vk = self
            .unlocked()?
            .vk(&local.vault_id, op.wire.epoch)
            .ok_or(CoreError::Locked)?;
        let (overview, details) = open_item_unverified(&op.wire, vk)?;
        Ok(Some(Opened {
            overview,
            details,
            version: op.wire.ver,
        }))
    }

    pub(crate) fn vault_name(&self, local: &VaultLocal) -> String {
        let fallback = match local.kind {
            VaultKind::Private => "Private",
            VaultKind::Shared => "Shared",
        };
        let opened = self.open_current(local, &ItemId::VAULT_SETTINGS);
        match opened {
            Ok(Some(opened)) => match payload::decode_hidden(opened.details.expose()) {
                Ok(Hidden::Settings(meta)) => meta.name,
                _ => fallback.to_owned(),
            },
            _ => fallback.to_owned(),
        }
    }

    pub fn vaults(&self) -> Result<Vec<VaultSummary>, CoreError> {
        let mut out = Vec::new();
        for local in self.cache.vaults()? {
            let state = local.state()?;
            out.push(VaultSummary {
                vault_id: local.vault_id,
                kind: local.kind,
                role: local.role,
                name: self.vault_name(&local),
                status: local.status,
                confirmed: local.confirmed,
                quarantined: self.cache.quarantine(&local.vault_id)?.is_some(),
                repair_pending: self.cache.pending_repair(&local.vault_id)?.is_some(),
                server_behind: self.cache.server_behind(&local.vault_id)?,
                epoch: state.as_ref().map_or(0, |s| s.epoch.get()),
                seq: state.as_ref().map_or(0, |s| s.seq.get()),
                members: state.as_ref().map_or(0, |s| s.roster.members.len()),
            });
        }
        Ok(out)
    }

    pub fn private_vault(&self) -> Result<VaultId, CoreError> {
        self.cache
            .vaults()?
            .into_iter()
            .find(|v| v.kind == VaultKind::Private)
            .map(|v| v.vault_id)
            .ok_or(CoreError::NotFound("private vault"))
    }

    pub async fn flush(
        &mut self,
        vault: &VaultId,
        call: &CancellationToken,
    ) -> Result<usize, CoreError> {
        let cancel = self.begin(call);
        let mut kinds = Vec::new();
        let flushed = {
            let mut cx = ctx!(self, &cancel);
            flush_vault(&mut cx, *vault, &mut kinds).await
        };
        self.store_events(&cancel, kinds)?;
        flushed
    }

    pub(crate) fn store_events(
        &mut self,
        cancel: &Cancel,
        kinds: Vec<crate::store::EventKind>,
    ) -> Result<(), CoreError> {
        if kinds.is_empty() {
            return Ok(());
        }
        let mut batch = Batch::new();
        {
            let cx = ctx!(self, cancel);
            record_events(&cx, &mut batch, kinds)?;
        }
        self.cache.commit(&batch)?;
        Ok(())
    }

    pub async fn sync(
        &mut self,
        call: &CancellationToken,
    ) -> Result<crate::sync::SyncReport, CoreError> {
        let cancel = self.begin(call);
        self.refresh_account(&cancel).await?;
        let mut report = {
            let mut cx = ctx!(self, &cancel);
            sync_all(&mut cx).await?
        };
        if self.own_device_revoked()? {
            self.wipe_local()?;
            return Err(CoreError::DeviceRevoked);
        }
        let mut kinds = Vec::new();
        let vaults = self.cache.vaults()?;
        for vault in vaults {
            if self.cache.pending(&vault.vault_id)?.is_empty() {
                continue;
            }
            let outcome = {
                let mut cx = ctx!(self, &cancel);
                flush_vault(&mut cx, vault.vault_id, &mut kinds).await
            };
            match outcome {
                Ok(_) => {}
                Err(CoreError::Transport(error))
                    if matches!(error, crate::transport::TransportError::Unreachable) =>
                {
                    return Err(CoreError::Transport(error));
                }
                Err(CoreError::Cancelled) => return Err(CoreError::Cancelled),
                Err(error) => kinds.push(crate::store::EventKind::NeedsAttention {
                    vault_id: vault.vault_id,
                    reason: error.to_string(),
                }),
            }
        }
        self.store_events(&cancel, kinds.clone())?;
        report.events.extend(
            self.cache
                .events()?
                .into_iter()
                .filter(|event| kinds.contains(&event.kind))
                .take(kinds.len()),
        );
        Ok(report)
    }

    /// The head `seq` the server reports for a vault that is older than this device's verified
    /// head, after a sync that refused it as `E_ROLLBACK`. `None` when the server is not behind.
    pub fn server_behind(&self, vault: &VaultId) -> Result<Option<u64>, CoreError> {
        Ok(self.cache.server_behind(vault)?)
    }

    /// The user's confirmation that the server was restored to older data on purpose (P 7.14).
    /// The device adopts the server's verified chain for this vault. Local versions the server
    /// lacks are queued in the outbox and reach the server on the next sync, as ordinary commits.
    pub async fn accept_older_server_state(
        &mut self,
        vault: &VaultId,
        call: &CancellationToken,
    ) -> Result<RollbackAccepted, CoreError> {
        let cancel = self.begin(call);
        let mut cx = ctx!(self, &cancel);
        accept_older_server_state(&mut cx, *vault).await
    }

    pub fn events(&self) -> Result<Vec<crate::store::Event>, CoreError> {
        Ok(self.cache.events()?)
    }

    pub fn clear_event(&mut self, id: u64) -> Result<(), CoreError> {
        let mut batch = Batch::new();
        Records::delete_event(&mut batch, id);
        self.cache.commit(&batch)?;
        Ok(())
    }

    pub async fn create_vault(
        &mut self,
        name: &str,
        call: &CancellationToken,
    ) -> Result<VaultId, CoreError> {
        let cancel = self.begin(call);
        let vault_id = VaultId::from_bytes(self.platform.array()?);
        let commit = self.genesis_commit(vault_id, name)?;
        {
            let cx = ctx!(self, &cancel);
            cx.call(&commit).await?;
        }
        let mut fresh = VaultLocal::new(vault_id, VaultKind::Shared, Role::Owner);
        fresh.confirmed = true;
        let mut batch = Batch::new();
        Records::put_vault(&mut batch, &fresh)?;
        self.cache.commit(&batch)?;
        let mut cx = ctx!(self, &cancel);
        pull_vault_ids(&mut cx, vault_id).await?;
        Ok(vault_id)
    }

    fn genesis_commit(&self, vault_id: VaultId, name: &str) -> Result<Commit, CoreError> {
        let now = self.platform.clock.now();
        let vk = SecretKey::random()?;
        let identity = &self.unlocked()?.identity;
        let record = self
            .cache
            .account()?
            .ok_or(CoreError::Locked)?
            .record
            .unverified()?;
        let roster = Roster {
            vault_id,
            rver: Rver::new(1)?,
            epoch: Epoch::ZERO,
            prev: None,
            kind: VaultKind::Shared,
            members: vec![Member {
                account_id: record.account_id,
                ik_pk: record.ik_pk,
                kem_pk: record.kem_pk.clone(),
                role: Role::Owner,
                added_rver: Rver::new(1)?,
            }],
            vk_commit: vk_commit(&vk, &vault_id, Epoch::ZERO)?,
        };
        let signed_roster = Signed::sign(SigLabel::Roster, &roster, &identity.signing)?;
        let settings = seal_hidden(
            &vk,
            vault_id,
            ItemId::VAULT_SETTINGS,
            &Hidden::Settings(VaultMeta {
                name: name.to_owned(),
                icon: String::new(),
                description: String::new(),
            }),
            now,
        )?;
        let mut leafset = hasp_proto::LeafSet::new();
        leafset.apply(&ItemOp::from_wire_bytes(&settings.to_cbor()?)?)?;
        let manifest = Manifest {
            vault_id,
            seq: Seq::new(1)?,
            prev: None,
            epoch: Epoch::ZERO,
            rver: Rver::new(1)?,
            roster_hash: signed_roster.hash(),
            root: leafset_root(&leafset)?,
            author: record.account_id,
            repair: false,
        };
        let manifest = Signed::sign(SigLabel::Manifest, &manifest, &identity.signing)?;
        let wrap = SealedRaw::seal(
            &identity.k_self,
            vk.expose(),
            &Aad::self_wrap(record.account_id, vault_id, Epoch::ZERO),
        )?;
        Ok(Commit {
            vault_id,
            base_seq: Seq::ZERO,
            bundle: hasp_proto::wire::CommitBundle {
                manifest,
                roster: Some(signed_roster),
                shares: Vec::new(),
                ops: vec![settings],
            },
            self_wraps: vec![SelfWrapEntry {
                epoch: Epoch::ZERO,
                wrap,
            }],
        })
    }

    pub async fn sync_vault(&mut self, vault: &VaultId) -> Result<(), CoreError> {
        let cancel = self.begin(&CancellationToken::new());
        let mut cx = ctx!(self, &cancel);
        pull_vault_ids(&mut cx, *vault).await?;
        Ok(())
    }

    pub async fn refresh(&mut self, call: &CancellationToken) -> Result<(), CoreError> {
        let cancel = self.begin(call);
        let mut cx = ctx!(self, &cancel);
        sync_all(&mut cx).await?;
        Ok(())
    }

    pub(crate) fn verified_roster(
        &self,
        local: &VaultLocal,
        record: &Signed<Roster>,
    ) -> Result<VerifiedRoster, CoreError> {
        let session = self.unlocked()?;
        let state = local.state()?.ok_or(CoreError::NotFound("vault state"))?;
        Ok(verify_roster(
            record,
            Some(&state.verified_roster()),
            &session.identity.own,
            &session.pins,
        )?)
    }
}
