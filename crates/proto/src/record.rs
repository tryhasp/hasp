pub(crate) mod account;
pub(crate) mod dissolve;
pub(crate) mod invite;
pub(crate) mod item;
pub(crate) mod keyset;
pub(crate) mod leave;
pub(crate) mod manifest;
pub(crate) mod recovery;
pub(crate) mod roster;
pub(crate) mod share;

use crate::ProtoError;
use crate::aad::Rtype;
use crate::cbor::{Reader, Writer};

const FORMAT_VERSION: u64 = 1;

pub(crate) fn begin(w: &mut Writer, rtype: Rtype, entries: usize) -> Result<(), ProtoError> {
    w.map(entries)?;
    w.key(0)?;
    w.uint(FORMAT_VERSION)?;
    w.key(1)?;
    w.uint(u64::from(rtype.code()))
}

pub(crate) fn read<T>(
    r: &mut Reader<'_>,
    rtype: Rtype,
    body: impl FnOnce(&mut Reader<'_>, usize) -> Result<T, ProtoError>,
) -> Result<T, ProtoError> {
    r.map(|r, entries| {
        r.key(0)?;
        if r.uint()?.get() != FORMAT_VERSION {
            return Err(ProtoError::Version);
        }
        r.key(1)?;
        if r.uint()?.get() != u64::from(rtype.code()) {
            return Err(ProtoError::Format);
        }
        body(r, entries)
    })
}

pub(crate) fn read_exact<T>(
    r: &mut Reader<'_>,
    rtype: Rtype,
    entries: usize,
    body: impl FnOnce(&mut Reader<'_>) -> Result<T, ProtoError>,
) -> Result<T, ProtoError> {
    read(r, rtype, |r, n| {
        if n != entries {
            return Err(ProtoError::Format);
        }
        body(r)
    })
}
