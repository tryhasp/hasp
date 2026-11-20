use hasp_proto::{Epoch, Hash32, Reader, Rver, Seq, Version, Wire, Writer};

use crate::store::{ServerError, StoreResult};

pub(super) fn int(value: u64) -> StoreResult<i64> {
    i64::try_from(value).map_err(|_| ServerError::Store)
}

pub(super) fn uint(value: i64) -> StoreResult<u64> {
    u64::try_from(value).map_err(|_| ServerError::Store)
}

pub(super) fn flag(value: i64) -> bool {
    value != 0
}

pub(super) fn array<const N: usize>(bytes: &[u8]) -> StoreResult<[u8; N]> {
    bytes.try_into().map_err(|_| ServerError::Store)
}

pub(super) fn hash(bytes: &[u8]) -> StoreResult<Hash32> {
    array::<32>(bytes).map(Hash32::from_bytes)
}

pub(super) fn seq(value: i64) -> StoreResult<Seq> {
    Seq::new(uint(value)?).map_err(|_| ServerError::Store)
}

pub(super) fn epoch(value: i64) -> StoreResult<Epoch> {
    Epoch::new(uint(value)?).map_err(|_| ServerError::Store)
}

pub(super) fn rver(value: i64) -> StoreResult<Rver> {
    Rver::new(uint(value)?).map_err(|_| ServerError::Store)
}

pub(super) fn version(value: i64) -> StoreResult<Version> {
    Version::new(uint(value)?).map_err(|_| ServerError::Store)
}

pub(super) fn text(bytes: Vec<u8>) -> StoreResult<String> {
    String::from_utf8(bytes).map_err(|_| ServerError::Store)
}

pub(super) fn enc<T: Wire>(value: &T) -> StoreResult<Vec<u8>> {
    value.to_cbor().map_err(|_| ServerError::Store)
}

pub(super) fn dec<T: Wire>(bytes: &[u8]) -> StoreResult<T> {
    T::from_cbor(bytes).map_err(|_| ServerError::Store)
}

pub(super) fn dec_opt<T: Wire>(bytes: Option<&[u8]>) -> StoreResult<Option<T>> {
    bytes.map(dec).transpose()
}

pub(super) fn enc_opt<T: Wire>(value: Option<&T>) -> StoreResult<Option<Vec<u8>>> {
    value.map(enc).transpose()
}

pub(super) fn enc_slots(slots: &[(u64, Vec<u8>)]) -> StoreResult<Vec<u8>> {
    let mut w = Writer::new();
    w.array(slots.len()).map_err(|_| ServerError::Store)?;
    for (index, data) in slots {
        w.array(2).map_err(|_| ServerError::Store)?;
        w.uint(*index).map_err(|_| ServerError::Store)?;
        w.bytes(data).map_err(|_| ServerError::Store)?;
    }
    Ok(w.into_bytes())
}

pub(super) fn dec_slots(bytes: &[u8]) -> StoreResult<Vec<(u64, Vec<u8>)>> {
    let mut r = Reader::new(bytes);
    let slots = r
        .array(|r, count| {
            let mut out = Vec::with_capacity(count.min(16));
            for _ in 0..count {
                let pair = r.array(|r, n| {
                    if n != 2 {
                        return Err(hasp_proto::ProtoError::Format);
                    }
                    Ok((r.uint()?.get(), r.bytes()?.to_vec()))
                })?;
                out.push(pair);
            }
            Ok(out)
        })
        .map_err(|_| ServerError::Store)?;
    r.finish().map_err(|_| ServerError::Store)?;
    Ok(slots)
}

pub(super) fn key_int(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

macro_rules! coded {
    ($to:ident, $from:ident, $ty:ty { $($variant:ident = $code:literal),+ $(,)? }) => {
        pub(super) fn $to(value: $ty) -> i64 {
            match value {
                $(<$ty>::$variant => $code),+
            }
        }

        pub(super) fn $from(code: i64) -> StoreResult<$ty> {
            match code {
                $($code => Ok(<$ty>::$variant),)+
                _ => Err(ServerError::Store),
            }
        }
    };
}

coded!(account_state_code, account_state, crate::store::AccountState {
    Active = 1,
    Disabled = 2,
});
coded!(enrol_state_code, enrol_state, crate::store::EnrolState {
    Open = 1,
    Approved = 2,
    Aborted = 3,
});
coded!(recovery_state_code, recovery_state, crate::store::RecoveryState {
    Pending = 1,
    Released = 2,
    Aborted = 3,
    Done = 4,
});
coded!(phase_code, phase, crate::store::VaultPhase {
    Active = 1,
    Dissolved = 2,
});
coded!(member_status_code, member_status, crate::store::MemberStatus {
    Invited = 1,
    Active = 2,
    Leaving = 3,
    Removed = 4,
    Dissolved = 5,
});
coded!(attachment_state_code, attachment_state, crate::store::AttachmentState {
    Uploading = 1,
    Complete = 2,
});
coded!(role_code, role, hasp_proto::Role {
    Viewer = 1,
    Editor = 2,
    Owner = 3,
});
coded!(vault_kind_code, vault_kind, hasp_proto::VaultKind {
    Private = 1,
    Shared = 2,
});

pub(super) fn token_kind(code: i64) -> StoreResult<hasp_proto::wire::TokenKind> {
    hasp_proto::wire::TokenKind::from_code(uint(code)?).ok_or(ServerError::Store)
}

pub(super) fn notice_kind(code: i64) -> StoreResult<hasp_proto::wire::NoticeKind> {
    hasp_proto::wire::NoticeKind::from_code(uint(code)?).ok_or(ServerError::Store)
}

pub(super) fn invite_state(code: i64) -> StoreResult<hasp_proto::wire::InviteState> {
    hasp_proto::wire::InviteState::from_code(uint(code)?).ok_or(ServerError::Store)
}
