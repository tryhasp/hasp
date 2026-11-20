use super::{
    AccountId, Hash32, ItemState, Overview, PAYLOAD_VERSION, ProtoError, Reader, Wire, Writer,
    Zeroizing, check_version, expect_count,
};

pub const KIND_PIN: &str = "pin";
pub const KIND_DEVICE: &str = "device";
pub const KIND_VAULT_SETTINGS: &str = "vault-settings";
pub const KIND_RECOVERY: &str = "recovery-code";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultMeta {
    pub name: String,
    pub icon: String,
    pub description: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinLevelWire {
    Tofu,
    Verified,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinRecord {
    pub account_id: AccountId,
    pub ik_pk: [u8; 32],
    pub kem_pk_hash: Hash32,
    pub level: PinLevelWire,
    pub first_seen: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRecord {
    pub label: String,
    pub platform: String,
    pub first_seen: u64,
    pub status: DeviceStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hidden {
    Settings(VaultMeta),
    Pin(PinRecord),
    Device(DeviceRecord),
}

impl Hidden {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Settings(_) => KIND_VAULT_SETTINGS,
            Self::Pin(_) => KIND_PIN,
            Self::Device(_) => KIND_DEVICE,
        }
    }

    pub fn overview(&self, now: u64) -> Overview {
        Overview {
            kind: self.kind().to_owned(),
            title: String::new(),
            subtitle: String::new(),
            tags: Vec::new(),
            favourite: None,
            state: ItemState::Active,
            client_modified: now,
            created: now,
            expires_at: None,
        }
    }
}

impl Wire for Hidden {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.map(3)?;
        w.key(0)?;
        w.uint(u64::from(PAYLOAD_VERSION))?;
        w.key(1)?;
        w.text(self.kind())?;
        w.key(2)?;
        match self {
            Self::Settings(meta) => {
                w.array(3)?;
                w.text(&meta.name)?;
                w.text(&meta.icon)?;
                w.text(&meta.description)
            }
            Self::Pin(pin) => {
                w.array(5)?;
                pin.account_id.encode(w)?;
                w.bytes(&pin.ik_pk)?;
                pin.kem_pk_hash.encode(w)?;
                w.uint(match pin.level {
                    PinLevelWire::Tofu => 1,
                    PinLevelWire::Verified => 2,
                })?;
                w.uint(pin.first_seen)
            }
            Self::Device(device) => {
                w.array(4)?;
                w.text(&device.label)?;
                w.text(&device.platform)?;
                w.uint(device.first_seen)?;
                w.uint(match device.status {
                    DeviceStatus::Active => 1,
                    DeviceStatus::Revoked => 2,
                })
            }
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        r.map(|r, n| {
            expect_count(n, 3)?;
            r.key(0)?;
            check_version(r)?;
            r.key(1)?;
            let kind = r.text()?.to_owned();
            r.key(2)?;
            match kind.as_str() {
                KIND_VAULT_SETTINGS => r.array(|r, n| {
                    expect_count(n, 3)?;
                    Ok(Self::Settings(VaultMeta {
                        name: r.text()?.to_owned(),
                        icon: r.text()?.to_owned(),
                        description: r.text()?.to_owned(),
                    }))
                }),
                KIND_PIN => r.array(|r, n| {
                    expect_count(n, 5)?;
                    let account_id = AccountId::decode(r)?;
                    let ik_pk = r.fixed()?;
                    let kem_pk_hash = Hash32::decode(r)?;
                    let level = match r.uint()?.get() {
                        1 => PinLevelWire::Tofu,
                        2 => PinLevelWire::Verified,
                        _ => return Err(ProtoError::Format),
                    };
                    let first_seen = r.uint()?.get();
                    Ok(Self::Pin(PinRecord {
                        account_id,
                        ik_pk,
                        kem_pk_hash,
                        level,
                        first_seen,
                    }))
                }),
                KIND_DEVICE => r.array(|r, n| {
                    expect_count(n, 4)?;
                    let label = r.text()?.to_owned();
                    let platform = r.text()?.to_owned();
                    let first_seen = r.uint()?.get();
                    let status = match r.uint()?.get() {
                        1 => DeviceStatus::Active,
                        2 => DeviceStatus::Revoked,
                        _ => return Err(ProtoError::Format),
                    };
                    Ok(Self::Device(DeviceRecord {
                        label,
                        platform,
                        first_seen,
                        status,
                    }))
                }),
                _ => Err(ProtoError::Format),
            }
        })
    }
}

pub fn encode_hidden(hidden: &Hidden) -> Result<Zeroizing<Vec<u8>>, ProtoError> {
    hidden.to_cbor().map(Zeroizing::new)
}

pub fn decode_hidden(bytes: &[u8]) -> Result<Hidden, ProtoError> {
    Hidden::from_cbor(bytes)
}
