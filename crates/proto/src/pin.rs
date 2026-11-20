use std::collections::BTreeMap;

use hasp_crypto::{KemPublicKey, VerifyingKey};

use crate::id::{AccountId, Hash32};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinLevel {
    Unverified,
    Tofu,
    Verified,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    pub ik_pk: VerifyingKey,
    pub kem_pk_hash: Hash32,
    pub level: PinLevel,
}

impl Pin {
    pub fn new(ik_pk: VerifyingKey, kem_pk: &KemPublicKey, level: PinLevel) -> Self {
        Self {
            ik_pk,
            kem_pk_hash: kem_hash(kem_pk),
            level,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinCheck {
    New,
    Ok,
    Unverified,
    KeyChanged,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PinState {
    pins: BTreeMap<AccountId, Pin>,
}

impl PinState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, account: AccountId, pin: Pin) -> Option<Pin> {
        self.pins.insert(account, pin)
    }

    pub fn get(&self, account: &AccountId) -> Option<&Pin> {
        self.pins.get(account)
    }
}

pub fn pin_check(
    pins: &PinState,
    account: &AccountId,
    ik_pk: &VerifyingKey,
    kem_pk: &KemPublicKey,
) -> PinCheck {
    match pins.get(account) {
        None => PinCheck::New,
        Some(pin) if pin.ik_pk == *ik_pk && pin.kem_pk_hash == kem_hash(kem_pk) => {
            match pin.level {
                PinLevel::Unverified => PinCheck::Unverified,
                PinLevel::Tofu | PinLevel::Verified => PinCheck::Ok,
            }
        }
        Some(_) => PinCheck::KeyChanged,
    }
}

pub(crate) fn kem_hash(kem_pk: &KemPublicKey) -> Hash32 {
    Hash32::digest(&[kem_pk.as_bytes()])
}
