use hasp_crypto::{SecretKey, hkdf_extract, hmac_sha256};
use hasp_proto::{
    AccountId, CtxValue, Epoch, Esid, Hash32, Kdf, Reader, Role, Rver, Seq, VaultId, VaultKind,
    Wire, Writer, derive,
};
use zeroize::Zeroizing;

use super::super::signin::SnapshotVault;
use crate::CoreError;
use crate::keys::enrol_mac_key;
use crate::store::Marks;

pub(super) fn commit_of(b_pub: &[u8; 32], esid: &Esid) -> Result<Hash32, CoreError> {
    let mut w = Writer::new();
    w.array(3)?;
    w.text(Kdf::EnrolCommit.name())?;
    w.bytes(b_pub)?;
    w.bytes(esid.as_bytes())?;
    Ok(Hash32::digest(&[&w.into_bytes()]))
}

pub(super) struct Transcript<'a> {
    pub(super) origin: &'a str,
    pub(super) account: &'a AccountId,
    pub(super) esid: &'a Esid,
    pub(super) c_b: &'a Hash32,
    pub(super) a: &'a [u8; 32],
    pub(super) b: &'a [u8; 32],
}

impl Transcript<'_> {
    pub(super) fn digest(&self) -> Result<Hash32, CoreError> {
        let mut w = Writer::new();
        w.array(6)?;
        w.text(self.origin)?;
        w.bytes(self.account.as_bytes())?;
        w.bytes(self.esid.as_bytes())?;
        w.bytes(self.c_b.as_bytes())?;
        w.bytes(self.a)?;
        w.bytes(self.b)?;
        Ok(Hash32::digest(&[&w.into_bytes()]))
    }
}

pub(super) fn channel_keys(
    e: &SecretKey,
    shared: &SecretKey,
    transcript: &Hash32,
) -> Result<(SecretKey, String), CoreError> {
    let kc = hkdf_extract(e.expose(), shared.expose()).into_secret();
    let ctx = [CtxValue::Bytes(transcript.as_bytes().to_vec())];
    let k_ch = derive(&kc, Kdf::EnrolKey, &ctx)?;
    let code_key = derive(&kc, Kdf::EnrolCode, &ctx)?;
    let head: [u8; 4] = code_key
        .expose()
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .ok_or(CoreError::Internal("code"))?;
    Ok((k_ch, format!("{:06}", u32::from_be_bytes(head) % 1_000_000)))
}

pub(super) fn mac(e: &SecretKey, parts: &[&[u8]]) -> [u8; 32] {
    let key = enrol_mac_key(e);
    let mut message = Vec::new();
    for part in parts {
        message.extend_from_slice(part);
    }
    hmac_sha256(&key, &message)
}

pub(super) fn pair(first: &[u8], second: &[u8]) -> Result<Vec<u8>, CoreError> {
    let mut w = Writer::new();
    w.array(2)?;
    w.bytes(first)?;
    w.bytes(second)?;
    Ok(w.into_bytes())
}

pub(super) fn unpair(bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32]), CoreError> {
    let mut r = Reader::new(bytes);
    let out = r.array(|r, n| {
        if n != 2 {
            return Err(hasp_proto::ProtoError::Format);
        }
        Ok((r.bytes()?.to_vec(), r.fixed::<32>()?))
    })?;
    r.finish()?;
    Ok(out)
}

pub(super) fn snapshot_bytes(
    vaults: &[SnapshotVault],
    account_seq: u64,
    keyset_gen: u64,
    max_seen_v: u64,
) -> Result<Vec<u8>, CoreError> {
    let mut w = Writer::new();
    w.map(4)?;
    w.key(0)?;
    w.array(vaults.len())?;
    for v in vaults {
        w.array(8)?;
        v.vault_id.encode(&mut w)?;
        v.kind.encode(&mut w)?;
        v.role.encode(&mut w)?;
        v.marks.rver.encode(&mut w)?;
        v.marks.roster_hash.encode(&mut w)?;
        v.marks.epoch.encode(&mut w)?;
        v.marks.seq.encode(&mut w)?;
        v.marks.hash.encode(&mut w)?;
    }
    w.key(1)?;
    w.uint(account_seq)?;
    w.key(2)?;
    w.uint(keyset_gen)?;
    w.key(3)?;
    w.uint(max_seen_v)?;
    Ok(w.into_bytes())
}

pub(super) struct Snapshot {
    pub(super) vaults: Vec<SnapshotVault>,
    pub(super) account_seq: u64,
    pub(super) keyset_gen: u64,
}

pub(super) fn read_snapshot(r: &mut Reader<'_>) -> Result<Snapshot, hasp_proto::ProtoError> {
    r.map(|r, n| {
        if n != 4 {
            return Err(hasp_proto::ProtoError::Format);
        }
        r.key(0)?;
        let vaults = r.array(|r, n| {
            let mut out = Vec::with_capacity(n);
            for _ in 0..n {
                out.push(r.array(|r, n| {
                    if n != 8 {
                        return Err(hasp_proto::ProtoError::Format);
                    }
                    let vault_id: VaultId = r.value()?;
                    let kind: VaultKind = r.value()?;
                    let role: Role = r.value()?;
                    let rver: Rver = r.value()?;
                    let roster_hash: Hash32 = r.value()?;
                    let epoch: Epoch = r.value()?;
                    let seq: Seq = r.value()?;
                    let hash: Hash32 = r.value()?;
                    Ok(SnapshotVault {
                        vault_id,
                        kind,
                        role,
                        marks: Marks {
                            seq,
                            hash,
                            rver,
                            roster_hash,
                            epoch,
                        },
                    })
                })?);
            }
            Ok(out)
        })?;
        r.key(1)?;
        let account_seq = r.uint()?.get();
        r.key(2)?;
        let keyset_gen = r.uint()?.get();
        r.key(3)?;
        r.uint()?;
        Ok(Snapshot {
            vaults,
            account_seq,
            keyset_gen,
        })
    })
}

pub(super) struct PayloadIn {
    pub(super) ak: SecretKey,
    pub(super) token: hasp_proto::wire::SessionToken,
    pub(super) snapshot: Snapshot,
    pub(super) login: String,
    pub(super) confirmed: bool,
}

pub(super) fn payload_bytes(
    ak: &SecretKey,
    token: &hasp_proto::wire::SessionToken,
    snapshot: &[u8],
    login: &str,
    confirmed: bool,
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let mut w = Writer::new();
    w.map(5)?;
    w.key(0)?;
    w.bytes(ak.expose())?;
    w.key(1)?;
    token.encode(&mut w)?;
    w.key(2)?;
    w.bytes(snapshot)?;
    w.key(3)?;
    w.text(login)?;
    w.key(4)?;
    w.bool(confirmed);
    Ok(Zeroizing::new(w.into_bytes()))
}

pub(super) fn read_payload(bytes: &[u8]) -> Result<PayloadIn, CoreError> {
    let mut r = Reader::new(bytes);
    let out = r.map(|r, n| {
        if n != 5 {
            return Err(hasp_proto::ProtoError::Format);
        }
        r.key(0)?;
        let ak = read_secret_key(r)?;
        r.key(1)?;
        let token = r.value()?;
        r.key(2)?;
        let snapshot_raw = r.bytes()?;
        let mut sr = Reader::new(snapshot_raw);
        let snapshot = read_snapshot(&mut sr)?;
        sr.finish()?;
        r.key(3)?;
        let login = r.text()?.to_owned();
        r.key(4)?;
        let confirmed = r.bool()?;
        Ok(PayloadIn {
            ak,
            token,
            snapshot,
            login,
            confirmed,
        })
    })?;
    r.finish()?;
    Ok(out)
}

pub(super) fn read_secret_key(r: &mut Reader<'_>) -> Result<SecretKey, hasp_proto::ProtoError> {
    let raw = Zeroizing::new(r.fixed::<32>()?);
    Ok(SecretKey::from_bytes(*raw))
}
