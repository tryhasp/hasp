use hasp_crypto::SecretKey;
use hasp_proto::wire::{AccountGet, DeviceInfo, EnrolApprove, EnrolOpen};
use hasp_proto::{Aad, DeviceId, Esid, LocalField, Reader, SealedRaw, Wire, Writer, fingerprint};
use tokio_util::sync::CancellationToken;

use super::Channel;
use super::codec::{payload_bytes, read_payload, read_secret_key};
use crate::CoreError;
use crate::client::signin::Adoption;
use crate::client::{Client, ctx};
use crate::keys::{copy_key, secret_from_slice};
use crate::store::{Batch, Records, Store, UnlockClass};
use crate::transport::Transport;
use zeroize::Zeroizing;

const PAIRING_CODE_LABEL: &[u8] = b"hasp/v1/ext-pair-code";
const UNLOCK_CODE_LABEL: &[u8] = b"hasp/v1/ext-unlock-code";
pub const UNLOCK_NONCE_LEN: usize = 16;
const CODE_MODULUS: u32 = 1_000_000;

fn code_of(label: &[u8], device: &DeviceId, nonce: &[u8]) -> String {
    let digest = hasp_crypto::sha256(&[label, device.as_bytes(), nonce]);
    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % CODE_MODULUS;
    format!("{:03} {:03}", value / 1000, value % 1000)
}

/// The six digits the user compares when a browser extension asks to pair. Both ends derive them
/// from the fresh device id the extension put in its `enrol_request`, so a process that sends a
/// request of its own shows a different code than the extension the user is looking at.
pub fn pairing_code(device: &DeviceId) -> String {
    code_of(PAIRING_CODE_LABEL, device, &[])
}

/// The six digits for one `unlock` request: the extension makes a fresh `nonce`, shows the code in
/// its own window and sends the nonce; the desktop shows the code in the approval prompt. A
/// process that is not the extension cannot know the nonce the real extension is showing.
pub fn unlock_code(device: &DeviceId, nonce: &[u8; UNLOCK_NONCE_LEN]) -> String {
    code_of(UNLOCK_CODE_LABEL, device, nonce)
}

/// The pairing code of a CBOR `enrol_request`, for the extension to show while it waits.
pub fn pairing_code_of_request(request: &[u8]) -> Result<String, CoreError> {
    let mut r = Reader::new(request);
    let device = r.map(|r, n| {
        if n != 4 {
            return Err(hasp_proto::ProtoError::Format);
        }
        r.key(0)?;
        r.text()?;
        r.key(1)?;
        let device: DeviceId = r.value()?;
        r.key(2)?;
        r.text()?;
        r.key(3)?;
        r.text()?;
        Ok(device)
    })?;
    r.finish()?;
    Ok(pairing_code(&device))
}

impl<T: Transport, S: Store> Client<T, S> {
    pub async fn serve_extension_pairing<C: Channel>(
        &mut self,
        channel: &C,
        call: &CancellationToken,
    ) -> Result<(DeviceId, SecretKey), CoreError> {
        let cancel = self.begin(call);
        let account = self.cache.account()?.ok_or(CoreError::Locked)?;
        self.unlocked()?;
        let request = channel
            .recv()
            .await
            .map_err(|_| CoreError::Refused("channel"))?;
        let mut r = Reader::new(&request);
        let (device_id, platform, browser) = r.map(|r, n| {
            if n != 4 {
                return Err(hasp_proto::ProtoError::Format);
            }
            r.key(0)?;
            if r.text()? != "enrol_request" {
                return Err(hasp_proto::ProtoError::Format);
            }
            r.key(1)?;
            let device_id: DeviceId = r.value()?;
            r.key(2)?;
            let platform = r.text()?.to_owned();
            r.key(3)?;
            let browser = r.text()?.to_owned();
            Ok((device_id, platform, browser))
        })?;
        r.finish()?;
        let code = pairing_code(&device_id);
        self.platform
            .biometric
            .authenticate(&format!("Connect {browser} extension. Code {code}"))?;
        let esid = Esid::from_bytes(self.platform.array()?);
        let grant = {
            let cx = ctx!(self, &cancel);
            cx.call(&EnrolOpen { esid }).await?;
            cx.call(&EnrolApprove {
                esid,
                device: DeviceInfo {
                    device_id,
                    platform,
                    label: None,
                },
            })
            .await?
        };
        let k_ext = SecretKey::random()?;
        let (snapshot, confirmed) = self.snapshot_of_device()?;
        let session = self.unlocked()?;
        let plain = payload_bytes(
            &session.identity.ak,
            &grant.token,
            &snapshot,
            &account.login,
            confirmed,
        )?;
        let mut w = Writer::new();
        w.map(5)?;
        w.key(0)?;
        w.bytes(&plain)?;
        w.key(1)?;
        w.bytes(k_ext.expose())?;
        w.key(2)?;
        w.text(&account.origin)?;
        w.key(3)?;
        w.bytes(&account.server_fp)?;
        let record = account.record.unverified()?;
        w.key(4)?;
        w.bytes(&fingerprint(&record.ik_pk, &record.kem_pk))?;
        channel
            .send(w.into_bytes())
            .await
            .map_err(|_| CoreError::Refused("channel"))?;
        Ok((device_id, k_ext))
    }

    pub async fn pair_with_desktop<C: Channel>(
        &mut self,
        channel: &C,
        browser: &str,
        call: &CancellationToken,
    ) -> Result<SecretKey, CoreError> {
        let cancel = self.begin(call);
        if self.cache.account()?.is_some() {
            return Err(CoreError::Refused("this device already holds an account"));
        }
        let device_id = DeviceId::from_bytes(self.platform.array()?);
        let mut w = Writer::new();
        w.map(4)?;
        w.key(0)?;
        w.text("enrol_request")?;
        w.key(1)?;
        device_id.encode(&mut w)?;
        w.key(2)?;
        w.text(&self.config.platform_name)?;
        w.key(3)?;
        w.text(browser)?;
        channel
            .send(w.into_bytes())
            .await
            .map_err(|_| CoreError::Refused("channel"))?;
        let reply = channel
            .recv()
            .await
            .map_err(|_| CoreError::Refused("channel"))?;
        let mut r = Reader::new(&reply);
        let (inner, k_ext, origin, sf, fp) = r.map(|r, n| {
            if n != 5 {
                return Err(hasp_proto::ProtoError::Format);
            }
            r.key(0)?;
            let inner = Zeroizing::new(r.bytes()?.to_vec());
            r.key(1)?;
            let k_ext = read_secret_key(r)?;
            r.key(2)?;
            let origin = r.text()?.to_owned();
            r.key(3)?;
            let sf: [u8; 15] = r.fixed()?;
            r.key(4)?;
            let fp: [u8; 15] = r.fixed()?;
            Ok((inner, k_ext, origin, sf, fp))
        })?;
        r.finish()?;
        let payload = read_payload(&inner)?;
        let account = self
            .transport
            .call(Some(&payload.token), &AccountGet {})
            .await?;
        let token = payload.token.clone();
        let ak = copy_key(&payload.ak);
        self.adopt(
            Adoption {
                origin,
                login: payload.login,
                device_id,
                server_fp: sf,
                token: payload.token,
                ak: payload.ak,
                password: None,
                opk: None,
                confirmed: payload.confirmed,
                snapshot: payload.snapshot.vaults,
                expected_fp: Some(fp),
                account_seq_floor: payload.snapshot.account_seq,
                keyset_gen_floor: payload.snapshot.keyset_gen,
                class: Some(UnlockClass::Extension),
            },
            &account.records,
            account.keyset,
            &cancel,
        )
        .await?;
        self.write_ext_blobs(&k_ext, &ak, &token)?;
        Ok(k_ext)
    }

    fn write_ext_blobs(
        &mut self,
        k_ext: &SecretKey,
        ak: &SecretKey,
        token: &hasp_proto::wire::SessionToken,
    ) -> Result<(), CoreError> {
        let mut local = self.cache.account()?.ok_or(CoreError::Locked)?;
        local.local_gen = local.local_gen.saturating_add(1);
        let generation = hasp_proto::Uint53::new(local.local_gen)?;
        let seal = |field: LocalField, plain: &[u8]| {
            SealedRaw::seal(
                k_ext,
                plain,
                &Aad::device_local(local.account_id, field, local.device_id, generation),
            )
        };
        let mut batch = Batch::new();
        Records::put_blob(
            &mut batch,
            crate::client::unlock::field_code(LocalField::ExtAk),
            &seal(LocalField::ExtAk, ak.expose())?,
        )?;
        Records::put_blob(
            &mut batch,
            crate::client::unlock::field_code(LocalField::ExtSession),
            &seal(LocalField::ExtSession, token.as_bytes())?,
        )?;
        Records::put_account(&mut batch, &local)?;
        self.cache.commit(&batch)?;
        Ok(())
    }

    /// Protocol 7.16: the desktop released `K_ext` after user presence; the extension opens its
    /// sealed blobs and keeps the keys in memory only.
    pub async fn unlock_extension(
        &mut self,
        k_ext: &SecretKey,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        let cancel = self.begin(call);
        let local = self.cache.account()?.ok_or(CoreError::Locked)?;
        if local.class != UnlockClass::Extension {
            return Err(CoreError::Refused("this device is not a paired extension"));
        }
        let generation = hasp_proto::Uint53::new(local.local_gen)?;
        let open = |field: LocalField| -> Result<hasp_crypto::SecretBytes, CoreError> {
            self.cache
                .blob(crate::client::unlock::field_code(field))?
                .ok_or(CoreError::Credentials)?
                .open(
                    k_ext,
                    &Aad::device_local(local.account_id, field, local.device_id, generation),
                )
                .map_err(|_| CoreError::Credentials)
        };
        let ak = secret_from_slice(&open(LocalField::ExtAk)?)?;
        let token_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
            open(LocalField::ExtSession)?
                .expose()
                .try_into()
                .map_err(|_| CoreError::Credentials)?,
        );
        let token = hasp_proto::wire::SessionToken::from_bytes(*token_bytes);
        let keys = Self::open_keys(&local, &ak)?;
        let sk = hasp_proto::SecretAscii::from_ascii(keys.sk_ascii.expose())?;
        self.finish_unlock(
            crate::client::unlock::Unlocking {
                local: &local,
                ak,
                sk: &sk,
                token: Some(token),
                password: None,
            },
            &cancel,
        )
        .await
    }
}
