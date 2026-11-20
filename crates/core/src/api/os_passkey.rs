use hasp_crypto::Es256Key;
use hasp_proto::base64url;
use secrecy::{ExposeSecret, SecretSlice};

use super::engine::Engine;
use super::passkey::{
    CREDENTIAL_ID_LEN, Found, MAX_ID, MAX_USER_HANDLE, Placement, allowed, validity,
};
use super::provider::passkeys_in;
use super::{OsAssertion, OsAssertionRequest, OsRegistration, OsRegistrationRequest, ids};
use crate::CoreError;
use crate::model::item::Passkey;
use crate::store::Store;
use crate::transport::Transport;
use crate::webauthn::{self, AttestedCredential, ES256, FLAG_BE, FLAG_BS, FLAG_UP};

const CLIENT_DATA_HASH_LEN: usize = 32;

fn flags(uv: u8) -> u8 {
    FLAG_UP | FLAG_BE | FLAG_BS | uv
}

fn canonical(text: &str) -> Result<String, CoreError> {
    Ok(base64url::encode(&webauthn::decode_b64(text, 1, MAX_ID)?))
}

impl<T: Transport, S: Store> Engine<T, S> {
    /// The assertion path of an OS credential provider (`ASPasskeyCredentialRequest`). The
    /// system verified the app or site against the relying party and hands over the SHA-256
    /// `clientDataHash` instead of `clientDataJSON`; the signature covers
    /// `authenticatorData || clientDataHash`. Flags, counter and key use are the browser path's.
    pub async fn provider_passkey_assert(
        &self,
        request: OsAssertionRequest,
    ) -> Result<OsAssertion, CoreError> {
        let rp_id = webauthn::check_relying_party(self.matcher.psl(), &request.rp_id)?;
        let hash = webauthn::decode_b64(
            &request.client_data_hash,
            CLIENT_DATA_HASH_LEN,
            CLIENT_DATA_HASH_LEN,
        )?;
        let uv_flag = validity(request.user_verification, request.user_verified)?;
        let mut client = self.client.lock().await;
        let index = Self::index_of(&mut client)?;
        let mut matches = passkeys_in(&index, &rp_id, &request.allow);
        if let Some(wanted) = &request.credential_id {
            let wanted = canonical(wanted)?;
            matches.retain(|c| c.credential_id == wanted);
        }
        if let Some(item) = &request.item {
            matches.retain(|c| c.item == *item);
        }
        if let Some(vault) = &request.vault {
            matches.retain(|c| c.vault == *vault);
        }
        let chosen = match matches.len() {
            0 => return Err(CoreError::NotFound("passkey")),
            1 => matches.remove(0),
            _ => return Err(CoreError::Refused("several passkeys match; pick one")),
        };
        let (vault, item) = (ids::vault(&chosen.vault)?, ids::item(&chosen.item)?);
        let loaded = client.item(&vault, &item)?;
        let position = loaded
            .details()
            .passkeys
            .iter()
            .position(|p| base64url::encode(&p.credential_id) == chosen.credential_id)
            .ok_or(CoreError::NotFound("passkey"))?;
        let passkey = &loaded.details().passkeys[position];
        let key = Es256Key::from_pkcs8(passkey.private_key.expose_secret())?;
        let auth_data = webauthn::authenticator_data(&rp_id, flags(uv_flag), None)?;
        let signature = key.sign(&webauthn::signed_payload_with_hash(&auth_data, &hash));
        let user_handle = base64url::encode(&passkey.user_handle);
        let now = client.now();
        let found = Found {
            vault,
            item,
            title: chosen.title.clone(),
            index: position,
        };
        Self::touch_passkey(&mut client, &found, now);
        Ok(OsAssertion {
            vault: chosen.vault,
            item: chosen.item,
            rp_id,
            credential_id: chosen.credential_id,
            authenticator_data: base64url::encode(&auth_data),
            signature: base64url::encode(&signature),
            user_handle,
            client_data_hash: request.client_data_hash,
        })
    }

    /// The registration path of an OS credential provider. Attestation is `none` with a zero
    /// AAGUID, ES256 only, counter 0; an excluded credential of the same relying party is a
    /// conflict, and a credential for the same user handle replaces the old one in its item.
    pub async fn provider_passkey_register(
        &self,
        request: OsRegistrationRequest,
    ) -> Result<OsRegistration, CoreError> {
        let rp_id = webauthn::check_relying_party(self.matcher.psl(), &request.rp_id)?;
        webauthn::decode_b64(
            &request.client_data_hash,
            CLIENT_DATA_HASH_LEN,
            CLIENT_DATA_HASH_LEN,
        )?;
        if !request.algorithms.is_empty() && !request.algorithms.contains(&ES256) {
            return Err(CoreError::Refused("no supported passkey algorithm"));
        }
        let user_handle = webauthn::decode_b64(&request.user_handle, 1, MAX_USER_HANDLE)?;
        let uv_flag = validity(request.user_verification, request.user_verified)?;
        let mut client = self.client.lock().await;
        let index = Self::index_of(&mut client)?;
        let existing = passkeys_in(&index, &rp_id, &[]);
        let credential_excluded = !request.exclude.is_empty()
            && existing.iter().any(|c| {
                base64url::decode(&c.credential_id)
                    .is_some_and(|raw| allowed(&request.exclude, &raw))
            });
        if credential_excluded {
            return Err(CoreError::Conflict("a passkey for this account exists"));
        }
        let handle_text = base64url::encode(&user_handle);
        let replaced = index
            .entries
            .iter()
            .filter(|e| e.is_active())
            .find(|e| {
                e.passkeys
                    .iter()
                    .any(|p| p.rp_id == rp_id && p.user_handle == handle_text)
            })
            .map(|e| (ids::vault(&e.vault), ids::item(&e.item)));
        let replaced = match replaced {
            Some((Ok(vault), Ok(item))) => Some((vault, item)),
            _ => None,
        };
        let key = Es256Key::generate()?;
        let credential_id = hasp_crypto::random_array::<CREDENTIAL_ID_LEN>()?;
        let public = key.public_sec1();
        let passkey = Passkey {
            credential_id: credential_id.to_vec(),
            rp_id: rp_id.clone(),
            user_handle,
            user_name: request.user_name.clone(),
            display_name: request.user_display_name.clone(),
            algorithm: ES256,
            private_key: SecretSlice::from(key.to_pkcs8()?.expose().to_vec()),
            created: client.now(),
            last_used: None,
            backup_eligible: true,
            backed_up: true,
        };
        let auth_data = webauthn::authenticator_data(
            &rp_id,
            flags(uv_flag),
            Some(&AttestedCredential {
                credential_id: &credential_id,
                public_sec1: &public,
            }),
        )?;
        let attestation_object = webauthn::attestation_object_none(&auth_data)?;
        let placement = Placement {
            vault: request.vault.as_deref(),
            item: request.item.as_deref(),
            user_name: &request.user_name,
            rp_name: &request.rp_name,
        };
        let (vault, item) = self.store_passkey(&mut client, &placement, passkey, replaced)?;
        self.emit(super::EventKind::VaultChanged);
        Ok(OsRegistration {
            vault: ids::hex(vault.as_bytes()),
            item: ids::hex(item.as_bytes()),
            rp_id,
            credential_id: base64url::encode(&credential_id),
            attestation_object: base64url::encode(&attestation_object),
            authenticator_data: base64url::encode(&auth_data),
            public_key: base64url::encode(&webauthn::spki(&public)),
            public_key_algorithm: ES256,
        })
    }
}
