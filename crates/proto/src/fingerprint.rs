use hasp_crypto::{KemPublicKey, VerifyingKey};

use crate::ProtoError;
use crate::hexenc::{crockford_decode, crockford_encode, grouped};
use crate::id::{Hash32, VaultId};
use crate::label::{CtxValue, Kdf, info};
use crate::record::invite::FINGERPRINT_LEN;
use crate::uint::{Epoch, Rver, Seq};

const FINGERPRINT_GROUP: usize = 4;
const HEAD_CODE_BYTES: usize = 5;
const HEAD_CODE_GROUP: usize = 4;

pub fn fingerprint(ik_pk: &VerifyingKey, kem_pk: &KemPublicKey) -> [u8; FINGERPRINT_LEN] {
    let preimage = info(
        Kdf::Fp.name(),
        &[
            CtxValue::Bytes(ik_pk.as_bytes().to_vec()),
            CtxValue::Bytes(kem_pk.as_bytes().to_vec()),
        ],
    );
    let mut out = [0; FINGERPRINT_LEN];
    if let Ok(preimage) = preimage {
        let digest = Hash32::digest(&[&preimage]);
        out.copy_from_slice(
            digest
                .as_bytes()
                .get(..FINGERPRINT_LEN)
                .unwrap_or(&[0; FINGERPRINT_LEN]),
        );
    }
    out
}

pub fn format_fingerprint(fp: &[u8; FINGERPRINT_LEN]) -> String {
    grouped(&crockford_encode(fp), FINGERPRINT_GROUP)
}

pub fn parse_fingerprint(text: &str) -> Result<[u8; FINGERPRINT_LEN], ProtoError> {
    let flat: String = text
        .chars()
        .filter(|ch| *ch != '-' && !ch.is_whitespace())
        .collect();
    crockford_decode(&flat)?
        .try_into()
        .map_err(|_| ProtoError::Format)
}

pub fn head_code(
    vault: &VaultId,
    rver: Rver,
    epoch: Epoch,
    seq: Seq,
    manifest_hash: &Hash32,
) -> Result<String, ProtoError> {
    let preimage = info(
        Kdf::HeadCode.name(),
        &[
            CtxValue::Id16(*vault.as_bytes()),
            CtxValue::Uint(rver.uint()),
            CtxValue::Uint(epoch.uint()),
            CtxValue::Uint(seq.uint()),
            CtxValue::Bytes(manifest_hash.as_bytes().to_vec()),
        ],
    )?;
    let digest = Hash32::digest(&[&preimage]);
    let head = digest
        .as_bytes()
        .get(..HEAD_CODE_BYTES)
        .ok_or(ProtoError::Internal("digest"))?;
    Ok(grouped(&crockford_encode(head), HEAD_CODE_GROUP))
}
