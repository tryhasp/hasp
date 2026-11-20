use hasp_proto::wire::RepairPublish;
use hasp_proto::{SigLabel, Signed, Wire};
use tokio_util::sync::CancellationToken;

use crate::CoreError;
use crate::client::{Client, ctx};
use crate::store::{Batch, PendingRepair, Records, Store};
use crate::sync::pull_vault_ids;
use crate::transport::Transport;

impl<T: Transport, S: Store> Client<T, S> {
    /// Owner repair of a wedged vault (protocol 5.6, 7.15): a manifest at the quarantined
    /// sequence with `prev` at the last good head. The user must confirm on this client; members
    /// confirm on theirs. Returns the repair manifest hash the owner shows to members.
    pub fn repair_prepare(
        &self,
        vault: &hasp_proto::VaultId,
    ) -> Result<hasp_proto::wire::CommitBundle, CoreError> {
        let info = self
            .cache
            .quarantine(vault)?
            .ok_or(CoreError::NotFound("quarantine"))?;
        let local = self.local_vault(vault)?;
        let state = local.state()?.ok_or(CoreError::NotFound("vault state"))?;
        self.require_owner(&state)?;
        let manifest = hasp_proto::Manifest {
            vault_id: *vault,
            seq: hasp_proto::Seq::new(info.seq)?,
            prev: Some(state.hash),
            epoch: state.epoch,
            rver: state.rver,
            roster_hash: state.roster_hash,
            root: hasp_proto::leafset_root(&state.leafset)?,
            author: self.unlocked()?.identity.account_id,
            repair: true,
        };
        Ok(hasp_proto::wire::CommitBundle {
            manifest: Signed::sign(
                SigLabel::Manifest,
                &manifest,
                &self.unlocked()?.identity.signing,
            )?,
            roster: None,
            shares: Vec::new(),
            ops: Vec::new(),
        })
    }

    /// Applies a repair manifest after explicit user confirmation, then lifts the quarantine.
    pub fn repair_apply(
        &mut self,
        vault: &hasp_proto::VaultId,
        repair: &hasp_proto::wire::CommitBundle,
        confirmed: bool,
    ) -> Result<(), CoreError> {
        if !confirmed {
            return Err(CoreError::Refused(
                "the repair needs confirmation on this device",
            ));
        }
        let mut local = self.local_vault(vault)?;
        let state = local.state()?.ok_or(CoreError::NotFound("vault state"))?;
        let quarantined = self
            .cache
            .quarantine(vault)?
            .map(|info| hasp_proto::wire::CommitBundle::from_cbor(&info.bad_bundle))
            .transpose()?
            .map(|bundle| crate::sync::proto_commit(&bundle))
            .transpose()?;
        let commit = crate::sync::proto_commit(repair)?;
        let next = hasp_proto::verify_repair(&state, quarantined.as_ref(), &commit)?;
        let mut batch = Batch::new();
        crate::sync::persist_commits(
            &self.cache,
            &mut batch,
            &mut local,
            &next,
            std::slice::from_ref(repair),
        )?;
        Records::clear_quarantine(&mut batch, vault);
        Records::clear_pending_repair(&mut batch, vault);
        self.cache.commit(&batch)?;
        Ok(())
    }

    /// Owner side of protocol 7.15: signs the repair at the quarantined sequence, publishes it
    /// to the server and applies it locally. The caller passes `confirmed` only after the owner
    /// reviewed the dropped suffix on this device.
    pub async fn repair_publish(
        &mut self,
        vault: &hasp_proto::VaultId,
        confirmed: bool,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        if !confirmed {
            return Err(CoreError::Refused(
                "the repair needs confirmation on this device",
            ));
        }
        let cancel = self.begin(call);
        let bundle = self.repair_prepare(vault)?;
        {
            let cx = ctx!(self, &cancel);
            cx.call(&RepairPublish {
                vault_id: *vault,
                bundle: bundle.clone(),
            })
            .await?;
        }
        self.repair_apply(vault, &bundle, true)
    }

    /// Repairs the owner published that this device pulled and has not confirmed yet. Each one
    /// blocks writes and further pulls of its vault until `repair_confirm` or a new sync after
    /// the owner replaces it.
    pub fn pending_repairs(&self) -> Result<Vec<PendingRepair>, CoreError> {
        let mut out = Vec::new();
        for local in self.cache.vaults()? {
            out.extend(self.cache.pending_repair(&local.vault_id)?);
        }
        Ok(out)
    }

    pub fn repair_confirm(
        &mut self,
        vault: &hasp_proto::VaultId,
        confirmed: bool,
    ) -> Result<(), CoreError> {
        let pending = self
            .cache
            .pending_repair(vault)?
            .ok_or(CoreError::NotFound("pending repair"))?;
        let bundle = hasp_proto::wire::CommitBundle::from_cbor(&pending.bundle)?;
        self.repair_apply(vault, &bundle, confirmed)
    }

    /// Lifts a quarantine and pulls the vault again from the last good head. A vault that is
    /// still wedged is quarantined again; one the owner repaired shows a pending repair.
    pub async fn quarantine_retry(
        &mut self,
        vault: &hasp_proto::VaultId,
        call: &CancellationToken,
    ) -> Result<crate::sync::VaultSync, CoreError> {
        let cancel = self.begin(call);
        let info = self
            .cache
            .quarantine(vault)?
            .ok_or(CoreError::NotFound("quarantine"))?;
        let mut batch = Batch::new();
        Records::clear_quarantine(&mut batch, vault);
        self.cache.commit(&batch)?;
        let outcome = {
            let mut cx = ctx!(self, &cancel);
            pull_vault_ids(&mut cx, *vault).await
        };
        if outcome.is_err() && self.cache.quarantine(vault)?.is_none() {
            let mut batch = Batch::new();
            Records::put_quarantine(&mut batch, &info)?;
            self.cache.commit(&batch)?;
        }
        outcome
    }
}
