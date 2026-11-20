use hasp_crypto::SecretKey;
use hasp_proto::wire::{Leave, VaultDissolve};
use hasp_proto::{
    AccountId, Dissolve, ItemBody, LeaveRequest, Member, OsEntropy, Roster, ShareKey, SigLabel,
    Signed, VaultKind, VaultState, Wire, rewrap_item, seal_share, vk_commit,
};
use tokio_util::sync::CancellationToken;

use crate::CoreError;
use crate::client::{Client, ctx};
use crate::store::{Batch, EventKind, LocalVaultStatus, Records, Store, VaultLocal};
use crate::sync::{CommitDraft, ensure_writable, pull_vault_ids, self_wrap_entry, submit_commit};
use crate::transport::Transport;
use hasp_proto::{ItemWire, Share};

impl<T: Transport, S: Store> Client<T, S> {
    pub async fn remove_member(
        &mut self,
        vault: &hasp_proto::VaultId,
        account: &AccountId,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        self.rotate(vault, Some(*account), call).await
    }

    pub async fn bump_epoch(
        &mut self,
        vault: &hasp_proto::VaultId,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        self.rotate(vault, None, call).await
    }

    async fn rotate(
        &mut self,
        vault: &hasp_proto::VaultId,
        remove: Option<AccountId>,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        let cancel = self.begin(call);
        self.sync_for_write(vault, &cancel).await?;
        let mut local = self.local_vault(vault)?;
        let state = local.state()?.ok_or(CoreError::NotFound("vault state"))?;
        self.require_owner(&state)?;
        let me = self.unlocked()?.identity.account_id;
        if remove == Some(me) {
            return Err(CoreError::Refused("the owner dissolves the vault instead"));
        }
        let new_epoch = state.epoch.checked_next()?;
        let new_vk = SecretKey::random()?;
        let (signed, shares) = self.sign_rotated_roster(&local, &state, remove, &new_vk)?;
        let ops = self.rewrapped_items(vault, &state, &new_vk, new_epoch)?;
        let mut cx = ctx!(self, &cancel);
        let self_wrap = self_wrap_entry(&cx, vault, new_epoch, &new_vk)?;
        ensure_writable(&cx, &local)?;
        let draft = CommitDraft {
            ops,
            roster: Some(signed),
            shares,
            self_wraps: vec![self_wrap],
        };
        submit_commit(&mut cx, &mut local, draft, &[], &[(new_epoch, new_vk)]).await?;
        if let Some(gone) = remove {
            let events = cx.cache.events()?;
            let mut batch = Batch::new();
            for event in events {
                if matches!(event.kind, EventKind::LeaveRequested { vault_id, account } if vault_id == *vault && account == gone)
                {
                    Records::delete_event(&mut batch, event.id);
                }
            }
            cx.cache.commit(&batch)?;
        }
        Ok(())
    }

    fn sign_rotated_roster(
        &self,
        local: &VaultLocal,
        state: &VaultState,
        remove: Option<AccountId>,
        new_vk: &SecretKey,
    ) -> Result<(Signed<Roster>, Vec<Signed<Share>>), CoreError> {
        let new_epoch = state.epoch.checked_next()?;
        let vault = state.roster.vault_id;
        let me = self.unlocked()?.identity.account_id;
        let members: Vec<Member> = state
            .roster
            .members
            .iter()
            .filter(|m| Some(m.account_id) != remove)
            .cloned()
            .collect();
        if remove.is_some() && members.len() == state.roster.members.len() {
            return Err(CoreError::NotFound("member"));
        }
        let roster = Roster {
            vault_id: vault,
            rver: state.rver.checked_next()?,
            epoch: new_epoch,
            prev: Some(state.roster_hash),
            kind: VaultKind::Shared,
            members,
            vk_commit: vk_commit(new_vk, &vault, new_epoch)?,
        };
        let session = self.unlocked()?;
        let signed = Signed::sign(SigLabel::Roster, &roster, &session.identity.signing)?;
        let verified = self.verified_roster(local, &signed)?;
        let mut shares = Vec::new();
        for member in roster.members.iter().filter(|m| m.account_id != me) {
            shares.push(seal_share(
                &verified,
                &ShareKey {
                    owner_key: &session.identity.signing,
                    vk: new_vk,
                    to: &member.account_id,
                },
            )?);
        }
        Ok((signed, shares))
    }

    fn rewrapped_items(
        &self,
        vault: &hasp_proto::VaultId,
        state: &VaultState,
        new_vk: &SecretKey,
        new_epoch: hasp_proto::Epoch,
    ) -> Result<Vec<ItemWire>, CoreError> {
        let old_vk = self
            .unlocked()?
            .vk(vault, state.epoch)
            .ok_or(CoreError::Locked)?;
        let mut ops = Vec::new();
        for leaf in state.leafset.iter() {
            if leaf.flag == hasp_proto::LeafFlag::Tombstone {
                continue;
            }
            let bytes = self
                .cache
                .item_wire(vault, &leaf.item_id, leaf.ver, leaf.epoch)?
                .ok_or(CoreError::NotFound("item ciphertext"))?;
            let wire = ItemWire::from_cbor(&bytes)?;
            if !matches!(wire.body, ItemBody::Live { .. }) {
                continue;
            }
            ops.push(rewrap_item(
                &mut OsEntropy,
                old_vk,
                new_vk,
                &wire,
                new_epoch,
            )?);
        }
        Ok(ops)
    }

    pub fn pending_leaves(&self, vault: &hasp_proto::VaultId) -> Result<Vec<AccountId>, CoreError> {
        let local = self.local_vault(vault)?;
        let state = local.state()?;
        Ok(self
            .cache
            .events()?
            .into_iter()
            .filter_map(|event| match event.kind {
                EventKind::LeaveRequested { vault_id, account }
                    if vault_id == *vault
                        && state
                            .as_ref()
                            .is_some_and(|s| s.roster.member(&account).is_some()) =>
                {
                    Some(account)
                }
                _ => None,
            })
            .collect())
    }

    pub async fn leave_vault(
        &mut self,
        vault: &hasp_proto::VaultId,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        let cancel = self.begin(call);
        {
            let mut cx = ctx!(self, &cancel);
            pull_vault_ids(&mut cx, *vault).await?;
        }
        let mut local = self.local_vault(vault)?;
        let state = local.state()?.ok_or(CoreError::NotFound("vault state"))?;
        if state.roster.kind != VaultKind::Shared {
            return Err(CoreError::Refused("the Private vault cannot be left"));
        }
        let session = self.unlocked()?;
        let request = LeaveRequest {
            vault_id: *vault,
            account_id: session.identity.account_id,
            rver: state.rver,
            epoch: state.epoch,
        };
        let signed = Signed::sign(SigLabel::Leave, &request, &session.identity.signing)?;
        {
            let cx = ctx!(self, &cancel);
            cx.call(&Leave { request: signed }).await?;
        }
        local.status = LocalVaultStatus::Left;
        let mut batch = Batch::new();
        Records::put_vault(&mut batch, &local)?;
        self.cache.commit(&batch)?;
        self.store_events(&cancel, vec![EventKind::Left { vault_id: *vault }])
    }

    pub async fn dissolve_vault(
        &mut self,
        vault: &hasp_proto::VaultId,
        confirm_name: &str,
        password: &secrecy::SecretString,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        let cancel = self.begin(call);
        {
            let mut cx = ctx!(self, &cancel);
            pull_vault_ids(&mut cx, *vault).await?;
        }
        let mut local = self.local_vault(vault)?;
        let state = local.state()?.ok_or(CoreError::NotFound("vault state"))?;
        self.require_owner(&state)?;
        if state.roster.kind != VaultKind::Shared {
            return Err(CoreError::Refused(
                "the Private vault goes with the account",
            ));
        }
        if self.vault_name(&local) != confirm_name {
            return Err(CoreError::Refused("the typed name does not match"));
        }
        self.reauth(password, &cancel).await?;
        let record = Dissolve {
            vault_id: *vault,
            rver: state.rver,
            epoch: state.epoch,
            seq: state.seq,
            head: state.hash,
        };
        let signed = Signed::sign(
            SigLabel::Dissolve,
            &record,
            &self.unlocked()?.identity.signing,
        )?;
        {
            let cx = ctx!(self, &cancel);
            cx.call(&VaultDissolve { record: signed }).await?;
        }
        local.status = LocalVaultStatus::Dissolved;
        let mut batch = Batch::new();
        Records::put_vault(&mut batch, &local)?;
        self.cache.commit(&batch)?;
        Ok(())
    }
}
