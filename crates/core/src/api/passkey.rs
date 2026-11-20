use hasp_crypto::Es256Key;
use hasp_proto::base64url;
use secrecy::{ExposeSecret, SecretSlice};

use super::convert::parts_from_draft;
use super::engine::Engine;
use super::{
    EventKind, FrameContext, PasskeyAssertion, PasskeyCandidate, PasskeyCreateRequest,
    PasskeyCreated, PasskeyGetRequest, PasskeyQuery, UserVerification, ids,
};
use crate::CoreError;
use crate::client::Client;
use crate::matcher::origin::Origin;
use crate::model::item::{Item, Passkey};
use crate::store::Store;
use crate::transport::Transport;
use crate::webauthn::{
    self, AttestedCredential, Ceremony, ES256, FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV,
};

pub(super) const CREDENTIAL_ID_LEN: usize = 32;
const MAX_CHALLENGE: usize = 1024;
pub(super) const MAX_ID: usize = 1023;
pub(super) const MAX_USER_HANDLE: usize = 64;

pub(super) struct Placement<'a> {
    pub(super) vault: Option<&'a str>,
    pub(super) item: Option<&'a str>,
    pub(super) user_name: &'a str,
    pub(super) rp_name: &'a str,
}

pub(super) struct Found {
    pub(super) vault: hasp_proto::VaultId,
    pub(super) item: hasp_proto::ItemId,
    pub(super) title: String,
    pub(super) index: usize,
}

fn checked_origin(frame: &FrameContext, origin: &str) -> Result<Origin, CoreError> {
    if frame.sandboxed {
        return Err(CoreError::Refused("sandboxed frames cannot use passkeys"));
    }
    if frame.cross_origin_frame {
        return Err(CoreError::Refused(
            "cross-origin frames cannot use passkeys",
        ));
    }
    Origin::parse(origin).map_err(|_| CoreError::Refused("the page origin is not valid"))
}

pub(super) fn validity(requirement: UserVerification, verified: bool) -> Result<u8, CoreError> {
    if requirement == UserVerification::Required && !verified {
        return Err(CoreError::Refused("user verification is required"));
    }
    Ok(if verified { FLAG_UV } else { 0 })
}

pub(super) fn allowed(allow: &[String], credential_id: &[u8]) -> bool {
    allow.is_empty()
        || allow.iter().any(|entry| {
            base64url::decode(entry).is_some_and(|raw| hasp_crypto::ct_eq(&raw, credential_id))
        })
}

fn candidate_of(found: &Found, passkey: &Passkey, vault: &str) -> PasskeyCandidate {
    PasskeyCandidate {
        vault: vault.to_owned(),
        item: ids::hex(found.item.as_bytes()),
        credential_id: base64url::encode(&passkey.credential_id),
        rp_id: passkey.rp_id.clone(),
        user_name: passkey.user_name.clone(),
        display_name: passkey.display_name.clone(),
        title: found.title.clone(),
        created: passkey.created,
        last_used: passkey.last_used,
    }
}

impl<T: Transport, S: Store> Engine<T, S> {
    fn matching_passkeys(
        client: &Client<T, S>,
        rp_id: &str,
        allow: &[String],
    ) -> Result<Vec<(Found, Passkey)>, CoreError> {
        let mut out = Vec::new();
        for (summary, item) in Self::active_items(client)? {
            let title = item.overview().title.clone();
            for (index, passkey) in item.into_parts().passkeys.into_iter().enumerate() {
                if passkey.rp_id == rp_id && allowed(allow, &passkey.credential_id) {
                    out.push((
                        Found {
                            vault: summary.vault_id,
                            item: summary.item_id,
                            title: title.clone(),
                            index,
                        },
                        passkey,
                    ));
                }
            }
        }
        Ok(out)
    }

    /// The passkeys a page may use, for the pick list. The RP ID comes from the verified origin
    /// and the registrable-suffix rule, never from the page alone.
    pub async fn passkey_candidates(
        &self,
        query: PasskeyQuery,
    ) -> Result<Vec<PasskeyCandidate>, CoreError> {
        let origin = checked_origin(&query.frame, &query.origin)?;
        let rp_id = webauthn::resolve_rp_id(self.matcher.psl(), &origin, query.rp_id.as_deref())?;
        let client = self.client.lock().await;
        client.require_unlocked()?;
        Ok(Self::matching_passkeys(&client, &rp_id, &query.allow)?
            .iter()
            .map(|(found, passkey)| candidate_of(found, passkey, &ids::hex(found.vault.as_bytes())))
            .collect())
    }

    /// WebAuthn `create` for a page, after the extension showed its origin-bound confirm.
    /// Attestation is `none`; the credential is synced (backup eligible and backed up) and the
    /// signature counter stays 0 (a counter cannot stay monotonic across devices).
    pub async fn passkey_create(
        &self,
        request: PasskeyCreateRequest,
    ) -> Result<PasskeyCreated, CoreError> {
        let origin = checked_origin(&request.frame, &request.origin)?;
        let rp_id = webauthn::resolve_rp_id(self.matcher.psl(), &origin, request.rp_id.as_deref())?;
        if !request.algorithms.is_empty() && !request.algorithms.contains(&ES256) {
            return Err(CoreError::Refused("no supported passkey algorithm"));
        }
        webauthn::decode_b64(&request.challenge, 1, MAX_CHALLENGE)?;
        let user_handle = webauthn::decode_b64(&request.user_handle, 1, MAX_USER_HANDLE)?;
        let uv_flag = validity(request.user_verification, request.user_verified)?;
        let mut client = self.client.lock().await;
        client.require_unlocked()?;
        let existing = Self::matching_passkeys(&client, &rp_id, &[])?;
        let excluded = !request.exclude.is_empty()
            && existing
                .iter()
                .any(|(_, passkey)| allowed(&request.exclude, &passkey.credential_id));
        if excluded {
            return Err(CoreError::Conflict("a passkey for this account exists"));
        }
        let key = Es256Key::generate()?;
        let credential_id = hasp_crypto::random_array::<CREDENTIAL_ID_LEN>()?;
        let public = key.public_sec1();
        let now = client.now();
        let passkey = Passkey {
            credential_id: credential_id.to_vec(),
            rp_id: rp_id.clone(),
            user_handle: user_handle.clone(),
            user_name: request.user_name.clone(),
            display_name: request.user_display_name.clone(),
            algorithm: ES256,
            private_key: SecretSlice::from(key.to_pkcs8()?.expose().to_vec()),
            created: now,
            last_used: None,
            backup_eligible: true,
            backed_up: true,
        };
        let auth_data = webauthn::authenticator_data(
            &rp_id,
            FLAG_UP | FLAG_BE | FLAG_BS | uv_flag,
            Some(&AttestedCredential {
                credential_id: &credential_id,
                public_sec1: &public,
            }),
        )?;
        let client_data = webauthn::client_data_json(
            Ceremony::Create,
            &request.challenge,
            &webauthn::origin_text(&origin),
        )?;
        let attestation_object = webauthn::attestation_object_none(&auth_data)?;
        let replaced = existing
            .iter()
            .find(|(_, old)| old.rp_id == passkey.rp_id && old.user_handle == passkey.user_handle)
            .map(|(found, _)| (found.vault, found.item));
        let placement = Placement {
            vault: request.vault.as_deref(),
            item: request.item.as_deref(),
            user_name: &request.user_name,
            rp_name: &request.rp_name,
        };
        let (vault, item) = self.store_passkey(&mut client, &placement, passkey, replaced)?;
        self.emit(EventKind::VaultChanged);
        Ok(PasskeyCreated {
            vault: ids::hex(vault.as_bytes()),
            item: ids::hex(item.as_bytes()),
            rp_id,
            credential_id: base64url::encode(&credential_id),
            client_data_json: base64url::encode(client_data.as_bytes()),
            attestation_object: base64url::encode(&attestation_object),
            authenticator_data: base64url::encode(&auth_data),
            public_key: base64url::encode(&webauthn::spki(&public)),
            public_key_algorithm: ES256,
        })
    }

    pub(super) fn store_passkey(
        &self,
        client: &mut Client<T, S>,
        request: &Placement<'_>,
        passkey: Passkey,
        replaced: Option<(hasp_proto::VaultId, hasp_proto::ItemId)>,
    ) -> Result<(hasp_proto::VaultId, hasp_proto::ItemId), CoreError> {
        if let Some(item_text) = request.item {
            let vault_text = request
                .vault
                .ok_or(CoreError::Refused("an item needs its vault"))?;
            let (vault, item_id) = (ids::vault(vault_text)?, ids::item(item_text)?);
            let mut parts = client.item(&vault, &item_id)?.into_parts();
            parts.passkeys.retain(|old| {
                !(old.rp_id == passkey.rp_id && old.user_handle == passkey.user_handle)
            });
            parts.passkeys.push(passkey);
            parts.client_modified = client.now();
            client.edit_item(&vault, &item_id, &self.finish(parts)?)?;
            return Ok((vault, item_id));
        }
        if let Some((replaced_vault, replaced_item)) = replaced {
            let mut parts = client.item(&replaced_vault, &replaced_item)?.into_parts();
            parts.passkeys.retain(|old| {
                !(old.rp_id == passkey.rp_id && old.user_handle == passkey.user_handle)
            });
            parts.passkeys.push(passkey);
            parts.client_modified = client.now();
            client.edit_item(&replaced_vault, &replaced_item, &self.finish(parts)?)?;
            return Ok((replaced_vault, replaced_item));
        }
        let vault = match request.vault {
            Some(text) => ids::vault(text)?,
            None => client.private_vault()?,
        };
        let mut draft = self.blank_draft("login")?;
        for field in draft.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
            if field.purpose.as_deref() == Some("username") {
                field.value = super::Secret::new(request.user_name.as_bytes().to_vec());
            }
        }
        draft.title = if request.rp_name.is_empty() {
            passkey.rp_id.clone()
        } else {
            request.rp_name.to_owned()
        };
        draft.urls.push(super::UrlDraft {
            id: None,
            url: format!("https://{}", passkey.rp_id),
            mode: "domain".to_owned(),
            kind: "sign-in".to_owned(),
        });
        let mut parts = parts_from_draft(draft, None, client.now())?;
        parts.passkeys.push(passkey);
        let item = client.create_item(&vault, &self.finish(parts)?)?;
        Ok((vault, item))
    }

    /// WebAuthn `get`: signs `authenticatorData || SHA-256(clientDataJSON)` with the stored key.
    /// `last_used` is updated when the vault is writable; the counter stays 0.
    pub async fn passkey_get(
        &self,
        request: PasskeyGetRequest,
    ) -> Result<PasskeyAssertion, CoreError> {
        let origin = checked_origin(&request.frame, &request.origin)?;
        let rp_id = webauthn::resolve_rp_id(self.matcher.psl(), &origin, request.rp_id.as_deref())?;
        webauthn::decode_b64(&request.challenge, 1, MAX_CHALLENGE)?;
        let uv_flag = validity(request.user_verification, request.user_verified)?;
        let mut client = self.client.lock().await;
        client.require_unlocked()?;
        let mut matches = Self::matching_passkeys(&client, &rp_id, &request.allow)?;
        if let Some(wanted) = &request.credential_id {
            let wanted = webauthn::decode_b64(wanted, 1, MAX_ID)?;
            matches.retain(|(_, passkey)| hasp_crypto::ct_eq(&passkey.credential_id, &wanted));
        }
        if let Some(item) = &request.item {
            let item = ids::item(item)?;
            matches.retain(|(found, _)| found.item == item);
        }
        if let Some(vault) = &request.vault {
            let vault = ids::vault(vault)?;
            matches.retain(|(found, _)| found.vault == vault);
        }
        let (found, passkey) = match matches.len() {
            0 => return Err(CoreError::NotFound("passkey")),
            1 => matches
                .pop()
                .ok_or(CoreError::Internal("passkey selection"))?,
            _ => return Err(CoreError::Refused("several passkeys match; pick one")),
        };
        let key = Es256Key::from_pkcs8(passkey.private_key.expose_secret())?;
        let auth_data =
            webauthn::authenticator_data(&rp_id, FLAG_UP | FLAG_BE | FLAG_BS | uv_flag, None)?;
        let client_data = webauthn::client_data_json(
            Ceremony::Get,
            &request.challenge,
            &webauthn::origin_text(&origin),
        )?;
        let signature = key.sign(&webauthn::signed_payload(&auth_data, &client_data));
        let now = client.now();
        Self::touch_passkey(&mut client, &found, now);
        Ok(PasskeyAssertion {
            vault: ids::hex(found.vault.as_bytes()),
            item: ids::hex(found.item.as_bytes()),
            rp_id,
            credential_id: base64url::encode(&passkey.credential_id),
            client_data_json: base64url::encode(client_data.as_bytes()),
            authenticator_data: base64url::encode(&auth_data),
            signature: base64url::encode(&signature),
            user_handle: base64url::encode(&passkey.user_handle),
        })
    }

    pub(super) fn touch_passkey(client: &mut Client<T, S>, found: &Found, now: u64) {
        let Ok(item) = client.item(&found.vault, &found.item) else {
            return;
        };
        let mut parts = item.into_parts();
        let Some(passkey) = parts.passkeys.get_mut(found.index) else {
            return;
        };
        passkey.last_used = Some(now);
        let Ok(updated) = Item::new(parts) else {
            return;
        };
        let _best_effort = client.edit_item(&found.vault, &found.item, &updated);
    }
}
