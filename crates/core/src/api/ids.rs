use hasp_proto::wire::SessionId;
use hasp_proto::{AttId, DeviceId, ItemId, VaultId};

use crate::CoreError;

const BAD: CoreError = CoreError::Refused("malformed identifier");

fn bytes(text: &str) -> Result<[u8; 16], CoreError> {
    hasp_crypto::from_hex(text)
        .and_then(|raw| raw.try_into().ok())
        .ok_or(BAD)
}

pub(crate) fn vault(text: &str) -> Result<VaultId, CoreError> {
    bytes(text).map(VaultId::from_bytes)
}

pub(crate) fn item(text: &str) -> Result<ItemId, CoreError> {
    bytes(text).map(ItemId::from_bytes)
}

pub(crate) fn attachment(text: &str) -> Result<AttId, CoreError> {
    bytes(text).map(AttId::from_bytes)
}

pub(crate) fn device(text: &str) -> Result<DeviceId, CoreError> {
    bytes(text).map(DeviceId::from_bytes)
}

pub(crate) fn session(text: &str) -> Result<SessionId, CoreError> {
    bytes(text).map(SessionId::from_bytes)
}

pub(crate) fn hex(raw: &[u8]) -> String {
    hasp_crypto::to_hex(raw)
}
