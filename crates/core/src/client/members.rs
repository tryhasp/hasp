mod repair;
mod rotation;

use hasp_crypto::VerifyingKey;
use hasp_proto::payload::{self, Hidden, PinLevelWire, PinRecord};
use hasp_proto::wire::{Blob, InviteAccept, InviteCreate, InviteGet, InviteList};
use hasp_proto::{
    AccountId, AccountRecord, Hash32, InviteCode, InviteId, ItemId, Member, Pin, PinCheck,
    PinLevel, ProtoError, Role, Roster, ShareKey, SigLabel, Signed, VaultKind, VaultState, Wire,
    fingerprint, format_fingerprint, parse_fingerprint, pin_check, seal_share,
    verify_account_record,
};
use tokio_util::sync::CancellationToken;

use super::{Client, ctx};
use crate::CoreError;
use crate::session::Cancel;
use crate::store::{Batch, Records, Store, VaultLocal};
use crate::sync::{
    CommitDraft, Edit, ensure_writable, flush_vault, pull_vault_ids, queue_put, submit_commit,
};
use crate::transport::Transport;
use hasp_proto::Share;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteOffer {
    pub invite_id: InviteId,
    pub code: String,
    pub qr: Vec<u8>,
    pub expires: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingInvitee {
    pub invite_id: InviteId,
    pub role: Role,
    pub account_id: AccountId,
    pub fingerprint: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedInvite {
    pub vault_id: hasp_proto::VaultId,
    pub role: Role,
    pub my_fingerprint: String,
}

#[derive(Clone, Copy, Debug)]
pub struct Admission<'a> {
    pub invite: &'a InviteId,
    pub role: Role,
    pub check: &'a FingerprintCheck,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FingerprintCheck {
    Compared(String),
    NotCompared,
}

fn invite_role_key(invite: &InviteId) -> String {
    let hex: String = invite
        .as_bytes()
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
        .collect();
    format!("invite-role/{hex}")
}

fn proto_pin_level(level: PinLevel) -> PinLevelWire {
    match level {
        PinLevel::Unverified | PinLevel::Tofu => PinLevelWire::Tofu,
        PinLevel::Verified => PinLevelWire::Verified,
    }
}

impl<T: Transport, S: Store> Client<T, S> {
    pub async fn invite_create(
        &mut self,
        vault: &hasp_proto::VaultId,
        role: Role,
        call: &CancellationToken,
    ) -> Result<InviteOffer, CoreError> {
        let cancel = self.begin(call);
        let account = self.cache.account()?.ok_or(CoreError::Locked)?;
        let record = account.record.unverified()?;
        let reply = {
            let cx = ctx!(self, &cancel);
            cx.call(&InviteCreate {
                vault_id: *vault,
                role,
            })
            .await?
        };
        let code = InviteCode {
            invite_id: reply.invite_id,
            fp_owner: fingerprint(&record.ik_pk, &record.kem_pk),
            origin: account.origin,
        };
        let mut batch = Batch::new();
        Records::put_meta(
            &mut batch,
            &invite_role_key(&reply.invite_id),
            &role.to_cbor()?,
        );
        self.cache.commit(&batch)?;
        Ok(InviteOffer {
            invite_id: reply.invite_id,
            code: code.to_text()?,
            qr: code.to_cbor()?,
            expires: reply.expires.get(),
        })
    }

    pub async fn invite_accept(
        &mut self,
        code_text: &str,
        call: &CancellationToken,
    ) -> Result<AcceptedInvite, CoreError> {
        let cancel = self.begin(call);
        let code = InviteCode::parse(code_text)?;
        let account = self.cache.account()?.ok_or(CoreError::Locked)?;
        if code.origin != account.origin {
            return Err(CoreError::Refused("the invite is for another server"));
        }
        let view = {
            let cx = ctx!(self, &cancel);
            cx.call(&InviteGet {
                invite_id: code.invite_id,
            })
            .await?
        };
        let pins = self.unlocked()?.pins.clone();
        let inviter = verify_account_record(&view.inviter, None, &pins)?;
        if fingerprint(&inviter.ik_pk, &inviter.kem_pk) != code.fp_owner {
            return Err(ProtoError::Invite.into());
        }
        self.write_pin(&inviter, PinLevel::Verified, &cancel)
            .await?;
        let mut batch = Batch::new();
        Records::put_invite(&mut batch, &view.vault_id, &code.to_cbor()?);
        self.cache.commit(&batch)?;
        {
            let cx = ctx!(self, &cancel);
            cx.call(&InviteAccept {
                invite_id: code.invite_id,
                accept: Blob(account.account_id.to_cbor()?),
            })
            .await?;
        }
        let me = account.record.unverified()?;
        Ok(AcceptedInvite {
            vault_id: view.vault_id,
            role: view.role,
            my_fingerprint: format_fingerprint(&fingerprint(&me.ik_pk, &me.kem_pk)),
        })
    }

    async fn write_pin(
        &mut self,
        record: &AccountRecord,
        level: PinLevel,
        cancel: &Cancel,
    ) -> Result<(), CoreError> {
        let private = self.private_vault()?;
        let local = self.local_vault(&private)?;
        let now = self.platform.clock.now();
        let hidden = Hidden::Pin(PinRecord {
            account_id: record.account_id,
            ik_pk: *record.ik_pk.as_bytes(),
            kem_pk_hash: Hash32::digest(&[record.kem_pk.as_bytes()]),
            level: proto_pin_level(level),
            first_seen: now,
        });
        let overview = payload::encode_overview(&hidden.overview(now))?;
        let details = payload::encode_hidden(&hidden)?;
        let mut kinds = Vec::new();
        {
            let mut cx = ctx!(self, cancel);
            queue_put(
                &mut cx,
                &local,
                &Edit {
                    item_id: ItemId::pin(&record.account_id),
                    overview: &overview,
                    details: &details,
                    att_ids: Vec::new(),
                },
            )?;
            cx.session.pins.insert(
                record.account_id,
                Pin::new(record.ik_pk, &record.kem_pk, level),
            );
            flush_vault(&mut cx, private, &mut kinds).await?;
        }
        self.store_events(cancel, kinds)
    }

    pub async fn pending_invitees(
        &mut self,
        vault: &hasp_proto::VaultId,
        call: &CancellationToken,
    ) -> Result<Vec<PendingInvitee>, CoreError> {
        let cancel = self.begin(call);
        let list = {
            let cx = ctx!(self, &cancel);
            cx.call(&InviteList { vault_id: *vault }).await?
        };
        let pins = self.unlocked()?.pins.clone();
        let mut out = Vec::new();
        for entry in list.invites {
            let Some(rec) = &entry.invitee else { continue };
            if entry.state != hasp_proto::wire::InviteState::Accepted {
                continue;
            }
            let record = verify_account_record(rec, None, &pins)?;
            let role = self
                .own_invite_role(&entry.invite_id)?
                .unwrap_or(entry.role);
            out.push(PendingInvitee {
                invite_id: entry.invite_id,
                role,
                account_id: record.account_id,
                fingerprint: format_fingerprint(&fingerprint(&record.ik_pk, &record.kem_pk)),
            });
        }
        Ok(out)
    }

    pub async fn add_member(
        &mut self,
        vault: &hasp_proto::VaultId,
        invite: &InviteId,
        check: &FingerprintCheck,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        let role = self
            .own_invite_role(invite)?
            .ok_or(CoreError::Refused("this device did not create the invite"))?;
        let admission = Admission {
            invite,
            role,
            check,
        };
        self.add_member_as(vault, &admission, call).await
    }

    /// Adds the invitee with a role the owner chose. The server's invite row is never read for
    /// the role, so a server that edits it cannot raise the access an invitee receives.
    pub async fn add_member_as(
        &mut self,
        vault: &hasp_proto::VaultId,
        admission: &Admission<'_>,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        let Admission {
            invite,
            role,
            check,
        } = *admission;
        if role == Role::Owner {
            return Err(CoreError::Refused("a vault has one owner"));
        }
        let cancel = self.begin(call);
        self.sync_for_write(vault, &cancel).await?;
        let record = self.accepted_invitee(vault, invite, &cancel).await?;
        let level = self.checked_pin_level(&record, check)?;
        let mut local = self.local_vault(vault)?;
        let state = local.state()?.ok_or(CoreError::NotFound("vault state"))?;
        self.require_owner(&state)?;
        let (signed, share) = self.sign_roster_with_member(&local, &state, &record, role)?;
        let draft = CommitDraft {
            roster: Some(signed),
            shares: vec![share],
            ..CommitDraft::default()
        };
        {
            let mut cx = ctx!(self, &cancel);
            ensure_writable(&cx, &local)?;
            submit_commit(&mut cx, &mut local, draft, &[], &[]).await?;
        }
        self.write_pin(&record, level, &cancel).await
    }

    async fn accepted_invitee(
        &mut self,
        vault: &hasp_proto::VaultId,
        invite: &InviteId,
        cancel: &Cancel,
    ) -> Result<AccountRecord, CoreError> {
        let list = {
            let cx = ctx!(self, cancel);
            cx.call(&InviteList { vault_id: *vault }).await?
        };
        let entry = list
            .invites
            .into_iter()
            .find(|e| e.invite_id == *invite)
            .ok_or(CoreError::NotFound("invite"))?;
        let rec = entry.invitee.ok_or(CoreError::NotFound("invitee"))?;
        let pins = self.unlocked()?.pins.clone();
        Ok(verify_account_record(&rec, None, &pins)?)
    }

    fn checked_pin_level(
        &self,
        record: &AccountRecord,
        check: &FingerprintCheck,
    ) -> Result<PinLevel, CoreError> {
        let level = match check {
            FingerprintCheck::Compared(text) => {
                if parse_fingerprint(text)? != fingerprint(&record.ik_pk, &record.kem_pk) {
                    return Err(ProtoError::Pin.into());
                }
                PinLevel::Verified
            }
            FingerprintCheck::NotCompared => PinLevel::Tofu,
        };
        let pins = &self.unlocked()?.pins;
        if pin_check(pins, &record.account_id, &record.ik_pk, &record.kem_pk)
            == PinCheck::KeyChanged
        {
            return Err(ProtoError::Pin.into());
        }
        Ok(level)
    }

    fn sign_roster_with_member(
        &self,
        local: &VaultLocal,
        state: &VaultState,
        record: &AccountRecord,
        role: Role,
    ) -> Result<(Signed<Roster>, Signed<Share>), CoreError> {
        let mut members = state.roster.members.clone();
        let rver = state.rver.checked_next()?;
        members.push(Member {
            account_id: record.account_id,
            ik_pk: record.ik_pk,
            kem_pk: record.kem_pk.clone(),
            role,
            added_rver: rver,
        });
        members.sort_by_key(|m| m.account_id);
        let roster = Roster {
            vault_id: state.roster.vault_id,
            rver,
            epoch: state.epoch,
            prev: Some(state.roster_hash),
            kind: VaultKind::Shared,
            members,
            vk_commit: state.roster.vk_commit,
        };
        let session = self.unlocked()?;
        let signed = Signed::sign(SigLabel::Roster, &roster, &session.identity.signing)?;
        let verified = self.verified_roster(local, &signed)?;
        let vk = session
            .vk(&roster.vault_id, state.epoch)
            .ok_or(CoreError::Locked)?;
        let share = seal_share(
            &verified,
            &ShareKey {
                owner_key: &session.identity.signing,
                vk,
                to: &record.account_id,
            },
        )?;
        Ok((signed, share))
    }

    pub async fn change_role(
        &mut self,
        vault: &hasp_proto::VaultId,
        account: &AccountId,
        role: Role,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        if role == Role::Owner {
            return Err(CoreError::Refused("ownership transfer is not supported"));
        }
        let cancel = self.begin(call);
        self.sync_for_write(vault, &cancel).await?;
        let mut local = self.local_vault(vault)?;
        let state = local.state()?.ok_or(CoreError::NotFound("vault state"))?;
        self.require_owner(&state)?;
        let mut members = state.roster.members.clone();
        let member = members
            .iter_mut()
            .find(|m| m.account_id == *account)
            .ok_or(CoreError::NotFound("member"))?;
        member.role = role;
        let roster = Roster {
            rver: state.rver.checked_next()?,
            prev: Some(state.roster_hash),
            members,
            ..state.roster.clone()
        };
        let signed = Signed::sign(
            SigLabel::Roster,
            &roster,
            &self.unlocked()?.identity.signing,
        )?;
        let draft = CommitDraft {
            roster: Some(signed),
            ..CommitDraft::default()
        };
        let mut cx = ctx!(self, &cancel);
        ensure_writable(&cx, &local)?;
        submit_commit(&mut cx, &mut local, draft, &[], &[]).await
    }

    fn own_invite_role(&self, invite: &InviteId) -> Result<Option<Role>, CoreError> {
        self.cache
            .meta(&invite_role_key(invite))?
            .map(|bytes| Role::from_cbor(&bytes).map_err(CoreError::from))
            .transpose()
    }

    fn require_owner(&self, state: &VaultState) -> Result<(), CoreError> {
        let me = self.unlocked()?.identity.account_id;
        if state.roster.owner().is_some_and(|o| o.account_id == me) {
            Ok(())
        } else {
            Err(ProtoError::Authz.into())
        }
    }

    async fn sync_for_write(
        &mut self,
        vault: &hasp_proto::VaultId,
        cancel: &Cancel,
    ) -> Result<(), CoreError> {
        let mut kinds = Vec::new();
        let mut cx = ctx!(self, cancel);
        pull_vault_ids(&mut cx, *vault).await?;
        let local = cx.cache.vault(vault)?.ok_or(CoreError::NotFound("vault"))?;
        if !cx.cache.pending(vault)?.is_empty() {
            flush_vault(&mut cx, *vault, &mut kinds).await?;
        }
        ensure_writable(&cx, &local)?;
        Ok(())
    }

    pub fn trusted_key(
        &self,
        account: &AccountId,
    ) -> Result<Option<(VerifyingKey, bool)>, CoreError> {
        Ok(self
            .unlocked()?
            .pins
            .get(account)
            .map(|pin| (pin.ik_pk, pin.level == PinLevel::Verified)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberInfo {
    pub account_id: AccountId,
    pub role: Role,
    pub fingerprint: String,
    pub is_self: bool,
}

impl<T: Transport, S: Store> Client<T, S> {
    pub fn members(&self, vault: &hasp_proto::VaultId) -> Result<Vec<MemberInfo>, CoreError> {
        let own = self.account_id()?;
        let state = self
            .local_vault(vault)?
            .state()?
            .ok_or(CoreError::NotFound("vault state"))?;
        Ok(state
            .roster
            .members
            .iter()
            .map(|member| MemberInfo {
                account_id: member.account_id,
                role: member.role,
                fingerprint: format_fingerprint(&fingerprint(&member.ik_pk, &member.kem_pk)),
                is_self: member.account_id == own,
            })
            .collect())
    }
}
