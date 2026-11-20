use hasp_crypto::{SecretKey, X25519Secret, ct_eq};
use hasp_proto::wire::{
    AccountGet, Blob, DeviceInfo, EnrolApprove, EnrolMsgGet, EnrolMsgPut, EnrolOpen, EnrolSlot,
};
use hasp_proto::{
    Aad, AccountId, DeviceId, Esid, Hash32, Reader, SealedRaw, Wire, Writer, fingerprint,
};
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

use super::codec::{
    Transcript, channel_keys, commit_of, mac, pair, payload_bytes, read_payload, read_secret_key,
    snapshot_bytes, unpair,
};
use super::{
    EXPIRY_S, EnrolInvite, EnrolRequest, EnrolState, Initiator, Joiner, MAX_ATTEMPTS, QR_VERSION,
};
use crate::CoreError;
use crate::client::auth::check_server_key;
use crate::client::signin::{Adoption, SnapshotVault};
use crate::client::{Client, ctx};
use crate::keys::copy_key;
use crate::session::Cancel;
use crate::store::{Marks, Store};
use crate::transport::Transport;

struct PendingInitiator {
    esid: Esid,
    e: SecretKey,
    c_b: Hash32,
    a_pub: [u8; 32],
    device: (DeviceId, String),
}

impl<T: Transport, S: Store> Client<T, S> {
    pub(super) async fn msg_put(
        &self,
        esid: &Esid,
        slot: EnrolSlot,
        data: Vec<u8>,
        cancel: &Cancel,
    ) -> Result<(), CoreError> {
        cancel.check()?;
        self.transport
            .call(
                None,
                &EnrolMsgPut {
                    esid: *esid,
                    slot,
                    data: Blob(data),
                },
            )
            .await?;
        Ok(())
    }

    pub(super) async fn msg_get(
        &self,
        esid: &Esid,
        slot: EnrolSlot,
        cancel: &Cancel,
    ) -> Result<Vec<u8>, CoreError> {
        cancel.check()?;
        let reply = self
            .transport
            .call(None, &EnrolMsgGet { esid: *esid, slot })
            .await?;
        reply
            .data
            .map(|blob| blob.0)
            .ok_or(CoreError::Pending { retry_after: 1 })
    }

    pub(super) fn snapshot_of_device(&self) -> Result<(Vec<u8>, bool), CoreError> {
        let account = self.cache.account()?.ok_or(CoreError::Locked)?;
        let mut vaults = Vec::new();
        for vault in self.cache.vaults()? {
            let (Some(head), true) = (&vault.head, vault.confirmed) else {
                continue;
            };
            let state = head.state()?;
            vaults.push(SnapshotVault {
                vault_id: vault.vault_id,
                kind: vault.kind,
                role: vault.role,
                marks: Marks {
                    seq: head.seq,
                    hash: head.hash,
                    rver: state.rver,
                    roster_hash: state.roster_hash,
                    epoch: state.epoch,
                },
            });
        }
        let record = account.record.unverified()?;
        let bytes = snapshot_bytes(
            &vaults,
            record.seq.get(),
            account.keyset.generation.get(),
            account.max_seen_v,
        )?;
        Ok((bytes, crate::sync::device_confirmed_pub(&self.cache)?))
    }

    pub async fn enrol_open(&mut self, call: &CancellationToken) -> Result<EnrolInvite, CoreError> {
        let cancel = self.begin(call);
        let account = self.cache.account()?.ok_or(CoreError::Locked)?;
        let record = account.record.unverified()?;
        self.unlocked()?;
        let esid = Esid::from_bytes(self.platform.array()?);
        let e = SecretKey::random()?;
        let opened = {
            let cx = ctx!(self, &cancel);
            cx.call(&EnrolOpen { esid }).await?
        };
        let mut w = Writer::new();
        w.map(7)?;
        w.key(0)?;
        w.uint(QR_VERSION)?;
        w.key(1)?;
        w.text(&account.origin)?;
        w.key(2)?;
        w.bytes(account.account_id.as_bytes())?;
        w.key(3)?;
        w.bytes(esid.as_bytes())?;
        w.key(4)?;
        w.bytes(e.expose())?;
        w.key(5)?;
        w.bytes(&fingerprint(&record.ik_pk, &record.kem_pk))?;
        w.key(6)?;
        w.bytes(&account.server_fp)?;
        let now = self.platform.clock.now();
        self.enrol = Some(EnrolState::Initiator(Initiator {
            esid,
            e,
            expires: now.saturating_add(EXPIRY_S),
            c_b: None,
            device: None,
            a: None,
            a_pub: None,
            attempts: 0,
        }));
        let _ = opened;
        Ok(EnrolInvite {
            esid,
            qr: w.into_bytes(),
            expires: now.saturating_add(EXPIRY_S),
        })
    }

    pub async fn enrol_poll_request(
        &mut self,
        call: &CancellationToken,
    ) -> Result<Option<EnrolRequest>, CoreError> {
        let cancel = self.begin(call);
        let now = self.platform.clock.now();
        let Some(EnrolState::Initiator(init)) = &self.enrol else {
            return Err(CoreError::Refused("no enrolment is open"));
        };
        if now >= init.expires {
            self.enrol = None;
            return Err(CoreError::Refused("the enrolment expired"));
        }
        if let Some((_, platform)) = &init.device {
            return Ok(Some(EnrolRequest {
                platform: platform.clone(),
            }));
        }
        let (esid, e) = (init.esid, copy_key(&init.e));
        let raw = match self.msg_get(&esid, EnrolSlot::Request, &cancel).await {
            Ok(raw) => raw,
            Err(CoreError::Pending { .. }) => return Ok(None),
            Err(other) => return Err(other),
        };
        let (body, tag) = unpair(&raw)?;
        let expected = mac(&e, &[&body, esid.as_bytes()]);
        if !ct_eq(&expected, &tag) {
            return Err(CoreError::Credentials);
        }
        let mut r = Reader::new(&body);
        let (c_b, device_id, platform) = r.map(|r, n| {
            if n != 3 {
                return Err(hasp_proto::ProtoError::Format);
            }
            r.key(0)?;
            let c_b: Hash32 = r.value()?;
            r.key(1)?;
            let platform = r.text()?.to_owned();
            r.key(2)?;
            let device_id: DeviceId = r.value()?;
            Ok((c_b, device_id, platform))
        })?;
        r.finish()?;
        let a = X25519Secret::generate()?;
        let a_pub = a.public_key();
        let offer = pair(&a_pub, &mac(&e, &[&a_pub, esid.as_bytes(), c_b.as_bytes()]))?;
        self.msg_put(&esid, EnrolSlot::Offer, offer, &cancel)
            .await?;
        if let Some(EnrolState::Initiator(init)) = &mut self.enrol {
            init.c_b = Some(c_b);
            init.device = Some((device_id, platform.clone()));
            init.a = Some(a);
            init.a_pub = Some(a_pub);
        }
        Ok(Some(EnrolRequest { platform }))
    }

    /// Three wrong codes or the expiry invalidate the channel.
    pub async fn enrol_confirm(
        &mut self,
        typed_code: &str,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        let cancel = self.begin(call);
        let account = self.cache.account()?.ok_or(CoreError::Locked)?;
        let pending = self.pending_initiator()?;
        let b_pub = self.verified_reveal(&pending, &cancel).await?;
        let shared = match &self.enrol {
            Some(EnrolState::Initiator(Initiator { a: Some(a), .. })) => {
                a.diffie_hellman(&b_pub)?
            }
            _ => return Err(CoreError::Refused("no enrolment is open")),
        };
        let digest = Transcript {
            origin: &account.origin,
            account: &account.account_id,
            esid: &pending.esid,
            c_b: &pending.c_b,
            a: &pending.a_pub,
            b: &b_pub,
        }
        .digest()?;
        let (k_ch, code) = channel_keys(&pending.e, &shared, &digest)?;
        self.check_typed_code(&code, typed_code, &pending.esid, &cancel)
            .await?;
        let grant = {
            let cx = ctx!(self, &cancel);
            cx.call(&EnrolApprove {
                esid: pending.esid,
                device: DeviceInfo {
                    device_id: pending.device.0,
                    platform: pending.device.1,
                    label: None,
                },
            })
            .await?
        };
        let (snapshot, confirmed) = self.snapshot_of_device()?;
        let session = self.unlocked()?;
        let plain = payload_bytes(
            &session.identity.ak,
            &grant.token,
            &snapshot,
            &account.login,
            confirmed,
        )?;
        let sealed = SealedRaw::seal(&k_ch, &plain, &Aad::enrolment(digest))?;
        self.msg_put(
            &pending.esid,
            EnrolSlot::Payload,
            sealed.to_cbor()?,
            &cancel,
        )
        .await?;
        self.enrol = None;
        Ok(())
    }

    /// Ends the open enrolment channel so the joining device stops waiting at once.
    pub async fn enrol_abort(&mut self, call: &CancellationToken) -> Result<(), CoreError> {
        let cancel = self.begin(call);
        let Some(EnrolState::Initiator(init)) = self.enrol.take() else {
            return Ok(());
        };
        let cx = ctx!(self, &cancel);
        cx.call(&hasp_proto::wire::EnrolAbort { esid: init.esid })
            .await?;
        Ok(())
    }

    fn pending_initiator(&mut self) -> Result<PendingInitiator, CoreError> {
        let now = self.platform.clock.now();
        let Some(EnrolState::Initiator(init)) = &self.enrol else {
            return Err(CoreError::Refused("no enrolment is open"));
        };
        if now >= init.expires {
            self.enrol = None;
            return Err(CoreError::Refused("the enrolment expired"));
        }
        let (Some(c_b), Some(a_pub), Some(device)) = (init.c_b, init.a_pub, init.device.clone())
        else {
            return Err(CoreError::Pending { retry_after: 1 });
        };
        Ok(PendingInitiator {
            esid: init.esid,
            e: copy_key(&init.e),
            c_b,
            a_pub,
            device,
        })
    }

    async fn verified_reveal(
        &mut self,
        pending: &PendingInitiator,
        cancel: &Cancel,
    ) -> Result<[u8; 32], CoreError> {
        let raw = self
            .msg_get(&pending.esid, EnrolSlot::Reveal, cancel)
            .await?;
        let (b_pub_bytes, tag) = unpair(&raw)?;
        let b_pub: [u8; 32] = b_pub_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::Credentials)?;
        let esid = pending.esid;
        if !ct_eq(&mac(&pending.e, &[&b_pub, esid.as_bytes()]), &tag)
            || commit_of(&b_pub, &esid)? != pending.c_b
        {
            self.enrol = None;
            return Err(CoreError::Credentials);
        }
        Ok(b_pub)
    }

    async fn check_typed_code(
        &mut self,
        code: &str,
        typed_code: &str,
        esid: &Esid,
        cancel: &Cancel,
    ) -> Result<(), CoreError> {
        if ct_eq(code.as_bytes(), typed_code.trim().as_bytes()) {
            return Ok(());
        }
        let abort = if let Some(EnrolState::Initiator(init)) = &mut self.enrol {
            init.attempts = init.attempts.saturating_add(1);
            init.attempts >= MAX_ATTEMPTS
        } else {
            true
        };
        if abort {
            self.enrol = None;
            let cx = ctx!(self, cancel);
            cx.call(&hasp_proto::wire::EnrolAbort { esid: *esid })
                .await?;
        }
        Err(CoreError::Refused("the code does not match"))
    }

    pub async fn enrol_join(
        &mut self,
        qr: &[u8],
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        let cancel = self.begin(call);
        if self.cache.account()?.is_some() {
            return Err(CoreError::Refused("this device already holds an account"));
        }
        let mut r = Reader::new(qr);
        let (origin, account_id, esid, e, fp, sf) = r.map(|r, n| {
            if n != 7 {
                return Err(hasp_proto::ProtoError::Format);
            }
            r.key(0)?;
            if r.uint()?.get() != QR_VERSION {
                return Err(hasp_proto::ProtoError::Version);
            }
            r.key(1)?;
            let origin = r.text()?.to_owned();
            r.key(2)?;
            let account_id: AccountId = r.value()?;
            r.key(3)?;
            let esid: Esid = r.value()?;
            r.key(4)?;
            let e = read_secret_key(r)?;
            r.key(5)?;
            let fp: [u8; 15] = r.fixed()?;
            r.key(6)?;
            let sf: [u8; 15] = r.fixed()?;
            Ok((origin, account_id, esid, e, fp, sf))
        })?;
        r.finish()?;
        check_server_key(&self.transport, &cancel, &origin, &sf).await?;
        let b = X25519Secret::generate()?;
        let b_pub = b.public_key();
        let c_b = commit_of(&b_pub, &esid)?;
        let device_id = DeviceId::from_bytes(self.platform.array()?);
        let mut w = Writer::new();
        w.map(3)?;
        w.key(0)?;
        c_b.encode(&mut w)?;
        w.key(1)?;
        w.text(&self.config.platform_name)?;
        w.key(2)?;
        device_id.encode(&mut w)?;
        let body = w.into_bytes();
        let tag = mac(&e, &[&body, esid.as_bytes()]);
        self.msg_put(&esid, EnrolSlot::Request, pair(&body, &tag)?, &cancel)
            .await?;
        self.enrol = Some(EnrolState::Joiner(Box::new(Joiner {
            origin,
            account_id,
            esid,
            e,
            fp,
            sf,
            b,
            b_pub,
            c_b,
            device_id,
            k_ch: None,
        })));
        Ok(())
    }

    pub async fn enrol_reveal(&mut self, call: &CancellationToken) -> Result<String, CoreError> {
        let cancel = self.begin(call);
        let Some(EnrolState::Joiner(joiner)) = &self.enrol else {
            return Err(CoreError::Refused("no enrolment is joined"));
        };
        let (esid, e, c_b, b_pub, origin, account_id) = (
            joiner.esid,
            copy_key(&joiner.e),
            joiner.c_b,
            joiner.b_pub,
            joiner.origin.clone(),
            joiner.account_id,
        );
        let raw = self.msg_get(&esid, EnrolSlot::Offer, &cancel).await?;
        let (a_bytes, tag) = unpair(&raw)?;
        let a_pub: [u8; 32] = a_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::Credentials)?;
        if !ct_eq(&mac(&e, &[&a_pub, esid.as_bytes(), c_b.as_bytes()]), &tag) {
            self.enrol = None;
            return Err(CoreError::Credentials);
        }
        let reveal = pair(&b_pub, &mac(&e, &[&b_pub, esid.as_bytes()]))?;
        self.msg_put(&esid, EnrolSlot::Reveal, reveal, &cancel)
            .await?;
        let shared = match &self.enrol {
            Some(EnrolState::Joiner(j)) => j.b.diffie_hellman(&a_pub)?,
            _ => return Err(CoreError::Refused("no enrolment is joined")),
        };
        let digest = Transcript {
            origin: &origin,
            account: &account_id,
            esid: &esid,
            c_b: &c_b,
            a: &a_pub,
            b: &b_pub,
        }
        .digest()?;
        let (k_ch, code) = channel_keys(&e, &shared, &digest)?;
        if let Some(EnrolState::Joiner(j)) = &mut self.enrol {
            j.k_ch = Some((k_ch, digest));
        }
        Ok(code)
    }

    pub async fn enrol_finish(
        &mut self,
        password: Option<&SecretString>,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        let cancel = self.begin(call);
        let Some(EnrolState::Joiner(joiner)) = &self.enrol else {
            return Err(CoreError::Refused("no enrolment is joined"));
        };
        let Some((k_ch, digest)) = &joiner.k_ch else {
            return Err(CoreError::Refused("reveal the code first"));
        };
        let (esid, fp, sf, origin, device_id) = (
            joiner.esid,
            joiner.fp,
            joiner.sf,
            joiner.origin.clone(),
            joiner.device_id,
        );
        let k_ch = copy_key(k_ch);
        let digest = *digest;
        let raw = self.msg_get(&esid, EnrolSlot::Payload, &cancel).await?;
        let sealed = SealedRaw::from_cbor(&raw)?;
        let plain = sealed
            .open(&k_ch, &Aad::enrolment(digest))
            .map_err(|_| CoreError::Credentials)?;
        let payload = read_payload(plain.expose())?;
        let account = self
            .transport
            .call(Some(&payload.token), &AccountGet {})
            .await?;
        self.enrol = None;
        self.adopt(
            Adoption {
                origin,
                login: payload.login,
                device_id,
                server_fp: sf,
                token: payload.token,
                ak: payload.ak,
                password: password
                    .map(|p| SecretString::from(secrecy::ExposeSecret::expose_secret(p))),
                opk: None,
                confirmed: payload.confirmed,
                snapshot: payload.snapshot.vaults,
                expected_fp: Some(fp),
                account_seq_floor: payload.snapshot.account_seq,
                keyset_gen_floor: payload.snapshot.keyset_gen,
                class: None,
            },
            &account.records,
            account.keyset,
            &cancel,
        )
        .await
    }
}
