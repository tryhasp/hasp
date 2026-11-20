use crate::ProtoError;
use crate::cbor::{Reader, Wire, Writer};
use crate::hexenc::{crockford_decode, crockford_encode};
use crate::id::InviteId;

pub const FINGERPRINT_LEN: usize = 15;
const INVITE_PREFIX: &str = "INV1-";
const INVITE_ENTRIES: usize = 4;
const FORMAT_VERSION: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteCode {
    pub invite_id: InviteId,
    pub fp_owner: [u8; FINGERPRINT_LEN],
    pub origin: String,
}

impl InviteCode {
    pub fn to_text(&self) -> Result<String, ProtoError> {
        Ok(format!(
            "{INVITE_PREFIX}{}",
            crockford_encode(&self.to_cbor()?)
        ))
    }

    pub fn parse(text: &str) -> Result<Self, ProtoError> {
        let text = text.trim().to_ascii_uppercase();
        let body = text.strip_prefix(INVITE_PREFIX).ok_or(ProtoError::Format)?;
        Self::from_cbor(&crockford_decode(body)?)
    }
}

impl Wire for InviteCode {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.map(INVITE_ENTRIES)?;
        w.key(0)?;
        w.uint(FORMAT_VERSION)?;
        w.field(1, &self.invite_id)?;
        w.field(2, &self.fp_owner)?;
        w.field(3, &self.origin)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        r.map(|r, n| {
            if n != INVITE_ENTRIES {
                return Err(ProtoError::Format);
            }
            r.key(0)?;
            if r.uint()?.get() != FORMAT_VERSION {
                return Err(ProtoError::Version);
            }
            Ok(Self {
                invite_id: r.field(1)?,
                fp_owner: r.field(2)?,
                origin: r.field(3)?,
            })
        })
    }
}
