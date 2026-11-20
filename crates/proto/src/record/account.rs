use hasp_crypto::{KemPublicKey, VerifyingKey};

use crate::ProtoError;
use crate::aad::Rtype;
use crate::cbor::{Reader, Wire, Writer};
use crate::id::{AccountId, Hash32};
use crate::record::{begin, read_exact};
use crate::uint::{Seq, Uint53};

const ACCOUNT_ENTRIES: usize = 13;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfWire {
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

impl Wire for KdfWire {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.map(3)?;
        w.key(0)?;
        w.uint(u64::from(self.m))?;
        w.key(1)?;
        w.uint(u64::from(self.t))?;
        w.key(2)?;
        w.uint(u64::from(self.p))
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        r.map(|r, n| {
            if n != 3 {
                return Err(ProtoError::Format);
            }
            let mut next = |key| -> Result<u32, ProtoError> {
                r.key(key)?;
                u32::try_from(r.uint()?.get()).map_err(|_| ProtoError::Format)
            };
            Ok(Self {
                m: next(0)?,
                t: next(1)?,
                p: next(2)?,
            })
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountStatus {
    Active,
    Deleted,
}

impl Wire for AccountStatus {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.uint(match self {
            Self::Active => 1,
            Self::Deleted => 2,
        })
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        match r.uint()?.get() {
            1 => Ok(Self::Active),
            2 => Ok(Self::Deleted),
            _ => Err(ProtoError::Format),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRecord {
    pub account_id: AccountId,
    pub seq: Seq,
    pub prev: Option<Hash32>,
    pub ik_pk: VerifyingKey,
    pub kem_pk: KemPublicKey,
    pub kdf: KdfWire,
    pub status: AccountStatus,
    pub rc_gen: Uint53,
    pub min_v: Uint53,
    pub created: Uint53,
}

impl Wire for AccountRecord {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        begin(w, Rtype::Account, ACCOUNT_ENTRIES)?;
        w.field(2, &self.account_id)?;
        w.field(3, &self.seq)?;
        w.field(4, &self.prev)?;
        w.field(5, &self.ik_pk)?;
        w.field(6, &self.kem_pk)?;
        w.field(7, &self.kdf)?;
        w.field(8, &self.status)?;
        w.field(9, &self.rc_gen)?;
        w.field(10, &self.min_v)?;
        w.key(11)?;
        w.null();
        w.field(12, &self.created)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        read_exact(r, Rtype::Account, ACCOUNT_ENTRIES, |r| {
            let account_id = r.field(2)?;
            let seq = r.field(3)?;
            let prev = r.field(4)?;
            let ik_pk = r.field(5)?;
            let kem_pk = r.field(6)?;
            let kdf = r.field(7)?;
            let status = r.field(8)?;
            let rc_gen = r.field(9)?;
            let min_v = r.field(10)?;
            r.key(11)?;
            r.null()?;
            let created = r.field(12)?;
            Ok(Self {
                account_id,
                seq,
                prev,
                ik_pk,
                kem_pk,
                kdf,
                status,
                rc_gen,
                min_v,
                created,
            })
        })
    }
}
