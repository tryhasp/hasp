use std::collections::BTreeMap;

use hasp_crypto::{KemSecretKey, SecretKey, SigningKey};
use hasp_proto::wire::SessionToken;
use hasp_proto::{AccountId, AccountRecord, Epoch, KeysetKeys, OwnKeys, PinState, VaultId};
use tokio_util::sync::CancellationToken;

use crate::CoreError;
use crate::keys::{ak_keys, copy_key};

pub(crate) struct Identity {
    pub account_id: AccountId,
    pub signing: SigningKey,
    pub kem: KemSecretKey,
    pub ak: SecretKey,
    pub k_self: SecretKey,
    pub own: OwnKeys,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Identity(..)")
    }
}

impl Identity {
    pub(crate) fn from_keys(
        record: &AccountRecord,
        ak: SecretKey,
        keys: &KeysetKeys,
    ) -> Result<Self, CoreError> {
        let signing = SigningKey::from_seed(&keys.ik_seed);
        let kem = KemSecretKey::from_seed(&keys.kem_seed)?;
        if signing.verifying_key() != record.ik_pk || kem.public_key() != record.kem_pk {
            return Err(CoreError::Credentials);
        }
        let derived = ak_keys(&ak)?;
        Ok(Self {
            account_id: record.account_id,
            own: OwnKeys {
                account_id: record.account_id,
                ik_pk: record.ik_pk,
                kem_pk: record.kem_pk.clone(),
                retired_kem_pk_hashes: Vec::new(),
            },
            signing,
            kem,
            ak,
            k_self: derived.self_wrap,
        })
    }
}

#[derive(Debug)]
pub(crate) struct Session {
    pub identity: Identity,
    pub token: SessionToken,
    pub opk: Option<SecretKey>,
    pub vks: BTreeMap<(VaultId, Epoch), SecretKey>,
    pub pins: PinState,
}

impl Session {
    pub(crate) fn vk(&self, vault: &VaultId, epoch: Epoch) -> Option<&SecretKey> {
        self.vks.get(&(*vault, epoch))
    }

    pub(crate) fn put_vk(&mut self, vault: VaultId, epoch: Epoch, vk: &SecretKey) {
        self.vks.insert((vault, epoch), copy_key(vk));
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Cancel {
    pub client: CancellationToken,
    pub call: CancellationToken,
}

impl Cancel {
    pub(crate) fn check(&self) -> Result<(), CoreError> {
        if self.client.is_cancelled() || self.call.is_cancelled() {
            Err(CoreError::Cancelled)
        } else {
            Ok(())
        }
    }
}
