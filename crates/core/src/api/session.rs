use secrecy::SecretString;
use zeroize::{Zeroize, Zeroizing};

use super::engine::{Engine, event};
use super::ids;
use super::lock::PASSWORD_DUE_HINT;
use super::{
    AccountStatus, DeviceView, EngineEvent, EventKind, ExtensionRelease, KitPreview, LockState,
    PasswordSession, Secret, SignInRequest, SignUpKit, SignUpRequest, SyncSummary, UnlockMode,
};
use crate::CoreError;
use crate::client::{
    Channel, ClientState, EmergencyKit, SignIn, SignUp, UNLOCK_NONCE_LEN, unlock_code,
};
use crate::platform::PlatformError;
use crate::store::{Store, UnlockClass};
use crate::sync::VaultSyncState;
use crate::transport::{Transport, TransportError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HintEvent {
    Vault(hasp_proto::VaultId),
    Notice,
    SessionRevoked,
}

const LAST_PASSWORD: &str = "last-password-unlock";
const CLOCK_MARK: &str = "clock-high-water";
const CLOCK_SKEW_S: u64 = 600;
const SECONDS_PER_DAY: u64 = 86_400;
const EXT_KEY_PREFIX: &str = "ext_key/";
const EXT_VALID_S: u64 = 600;
const SESSION_BLOB_VERSION: u8 = 1;
const SESSION_BLOB_LEN: usize = 33;

fn parse_fingerprint(text: &str) -> Result<[u8; 15], CoreError> {
    hasp_proto::parse_fingerprint(text.trim())
        .map_err(|_| CoreError::Refused("the server fingerprint does not parse"))
}

fn text(secret: &Secret) -> Result<Zeroizing<String>, CoreError> {
    String::from_utf8(secret.as_bytes().to_vec())
        .map(Zeroizing::new)
        .map_err(|_| CoreError::Refused("not valid text"))
}

fn secret_string(secret: &Secret) -> Result<SecretString, CoreError> {
    Ok(SecretString::from(text(secret)?.as_str().to_owned()))
}

impl<T: Transport, S: Store> Engine<T, S> {
    pub async fn status(&self) -> Result<AccountStatus, CoreError> {
        let client = self.client.lock().await;
        let state = client.state()?;
        let account_known = state != ClientState::Empty;
        let mode = client.unlock_class()?.map(|class| match class {
            UnlockClass::Hardware => UnlockMode::Hardware,
            UnlockClass::PasswordOnly => UnlockMode::PasswordOnly,
            UnlockClass::Extension => UnlockMode::Extension,
        });
        Ok(AccountStatus {
            state: match state {
                ClientState::Empty => LockState::Empty,
                ClientState::Locked => LockState::Locked,
                ClientState::Unlocked => LockState::Unlocked,
            },
            login: if account_known {
                Some(client.login()?)
            } else {
                None
            },
            origin: client.origin()?,
            unlock_mode: mode,
            biometric_ready: client.biometric_ready(),
            retry_after: client.lockout_remaining(),
            device_confirmed: state == ClientState::Unlocked && client.device_confirmed()?,
            fingerprint: if account_known {
                Some(client.fingerprint()?)
            } else {
                None
            },
            password_required: account_known && Self::password_due(&client),
        })
    }

    pub fn parse_kit_qr(blob: &[u8]) -> Result<KitPreview, CoreError> {
        let kit = EmergencyKit::parse_qr(blob)?;
        Ok(KitPreview {
            origin: kit.origin,
            login: kit.login,
            server_fingerprint: hasp_proto::format_fingerprint(&kit.server_fp),
        })
    }

    pub async fn sign_in(&self, request: SignInRequest) -> Result<(), CoreError> {
        let secret_key = text(&request.secret_key)?;
        let password = secret_string(&request.password)?;
        let mut client = self.client.lock().await;
        client
            .sign_in(
                &SignIn {
                    origin: &request.origin,
                    login: &request.login,
                    secret_key: &secret_key,
                    password: &password,
                    kit_server_fp: Some(parse_fingerprint(&request.server_fingerprint)?),
                },
                &Self::token(),
            )
            .await?;
        Self::after_password_unlock(&mut client)?;
        self.emit(EventKind::Unlocked);
        Ok(())
    }

    /// The fingerprint of the key the server at `origin` presents, for the user to compare with
    /// the kit (sign-in) or `haspd init` (sign-up) before anything is sent.
    pub async fn server_fingerprint(&self, origin: &str) -> Result<String, CoreError> {
        let client = self.client.lock().await;
        let fingerprint = client.server_fingerprint(origin, &Self::token()).await?;
        Ok(hasp_proto::format_fingerprint(&fingerprint))
    }

    /// Protocol 7.1 as the CLI runs it: the typed server fingerprint is compared before any
    /// registration call, the account is created and signed in, and the Emergency Kit comes back
    /// for the host to show and have the user confirm.
    pub async fn sign_up(&self, request: SignUpRequest) -> Result<SignUpKit, CoreError> {
        let expected = parse_fingerprint(&request.server_fingerprint)?;
        let code = text(&request.code)?;
        let password = secret_string(&request.password)?;
        let mut client = self.client.lock().await;
        let kit = client
            .sign_up_pinned(
                &SignUp {
                    origin: &request.origin,
                    token: code.trim(),
                    login: &request.login,
                    password: &password,
                },
                Some(expected),
                &Self::token(),
            )
            .await?;
        Self::after_password_unlock(&mut client)?;
        let document = kit.document(client.now())?;
        self.emit(EventKind::Unlocked);
        Ok(SignUpKit {
            origin: kit.origin.clone(),
            login: kit.login.clone(),
            server_fingerprint: kit.server_fingerprint.clone(),
            secret_key: Secret::from_slice(kit.secret_key().as_bytes()),
            qr_blob: Secret::from_slice(&kit.qr_blob()?),
            qr_text: Secret::from_slice(kit.qr_text()?.as_bytes()),
            document_text: Secret::from_slice(document.text.as_bytes()),
            document_pdf: Secret::from_slice(&document.pdf),
        })
    }

    pub async fn sign_in_with_kit_qr(
        &self,
        blob: &[u8],
        password: Secret,
    ) -> Result<(), CoreError> {
        let kit = EmergencyKit::parse_qr(blob)?;
        let password = secret_string(&password)?;
        let mut client = self.client.lock().await;
        client
            .sign_in(
                &SignIn {
                    origin: &kit.origin,
                    login: &kit.login,
                    secret_key: secrecy::ExposeSecret::expose_secret(&kit.secret_key),
                    password: &password,
                    kit_server_fp: Some(kit.server_fp),
                },
                &Self::token(),
            )
            .await?;
        Self::after_password_unlock(&mut client)?;
        self.emit(EventKind::Unlocked);
        Ok(())
    }

    pub async fn unlock_password(&self, password: Secret) -> Result<(), CoreError> {
        let password = secret_string(&password)?;
        let mut client = self.client.lock().await;
        client.unlock_password(&password, &Self::token()).await?;
        Self::after_password_unlock(&mut client)?;
        self.emit(EventKind::Unlocked);
        Ok(())
    }

    /// Password unlock for a password-only device (the standalone extension). Returns the
    /// session blob: `K_loc` with a version byte, derived from the password but not revealing it
    /// and unable to log in. The host keeps it in session-scoped storage only and never stores
    /// the password (protocol 4.6).
    pub async fn unlock_with_password(
        &self,
        password: Secret,
    ) -> Result<PasswordSession, CoreError> {
        let password = secret_string(&password)?;
        let mut client = self.client.lock().await;
        let k_loc = client
            .unlock_password_session(&password, &Self::token())
            .await?;
        Self::after_password_unlock(&mut client)?;
        self.emit(EventKind::Unlocked);
        let mut blob = Vec::with_capacity(SESSION_BLOB_LEN);
        blob.push(SESSION_BLOB_VERSION);
        blob.extend_from_slice(k_loc.expose());
        Ok(PasswordSession {
            session_blob: Secret::new(blob),
        })
    }

    pub async fn resume_session(&self, session_blob: Secret) -> Result<(), CoreError> {
        let bytes = session_blob.as_bytes();
        let key = match bytes.split_first() {
            Some((&SESSION_BLOB_VERSION, rest)) if bytes.len() == SESSION_BLOB_LEN => {
                hasp_crypto::SecretKey::from_slice(rest)?
            }
            _ => return Err(hasp_proto::ProtoError::Format.into()),
        };
        let mut client = self.client.lock().await;
        client.resume_with_session_key(&key, &Self::token()).await?;
        self.emit(EventKind::Unlocked);
        Ok(())
    }

    pub async fn enable_hardware_unlock(&self, password: Secret) -> Result<(), CoreError> {
        let password = secret_string(&password)?;
        let mut client = self.client.lock().await;
        client.enable_hardware_unlock(&password, &Self::token())
    }

    pub async fn unlock_biometric(&self) -> Result<(), CoreError> {
        let mut client = self.client.lock().await;
        if Self::password_due(&client) {
            return Err(CoreError::Refused("password required"));
        }
        client.unlock_biometric(&Self::token()).await?;
        if let Err(error) = Self::ensure_password_not_due(&client) {
            client.lock();
            return Err(error);
        }
        Self::note_time(&mut client)?;
        self.emit(EventKind::Unlocked);
        Ok(())
    }

    pub async fn unlock_extension(&self, k_ext: Secret) -> Result<(), CoreError> {
        let key = secret_key(&k_ext)?;
        let mut client = self.client.lock().await;
        client.unlock_extension(&key, &Self::token()).await?;
        self.emit(EventKind::Unlocked);
        Ok(())
    }

    pub async fn lock(&self) {
        let mut client = self.client.lock().await;
        client.lock();
        drop(client);
        self.drop_watchtower().await;
        self.emit(EventKind::Locked);
    }

    /// Desktop side of protocol 7.2 C. `peer` is the browser and extension id the transport
    /// verified; it is stored with `K_ext` and must match on every later release.
    pub async fn serve_extension_pairing<C: Channel>(
        &self,
        channel: &C,
        peer: &str,
    ) -> Result<String, CoreError> {
        let mut client = self.client.lock().await;
        let (device, k_ext) = client
            .serve_extension_pairing(channel, &Self::token())
            .await?;
        let device = ids::hex(device.as_bytes());
        let mut record = k_ext.expose().to_vec();
        record.extend_from_slice(peer.as_bytes());
        client
            .secure_store()
            .put(&format!("{EXT_KEY_PREFIX}{device}"), &record)?;
        record.zeroize();
        Ok(device)
    }

    pub async fn pair_with_desktop<C: Channel>(
        &self,
        channel: &C,
        browser: &str,
    ) -> Result<Secret, CoreError> {
        let mut client = self.client.lock().await;
        let k_ext = client
            .pair_with_desktop(channel, browser, &Self::token())
            .await?;
        self.emit(EventKind::Unlocked);
        Ok(Secret::from_slice(k_ext.expose()))
    }

    /// Desktop side of protocol 7.16: the peer must be the one that paired, the device must not be
    /// revoked, the password rule must not be due, then user presence with a code bound to the
    /// request's `nonce`, then `K_ext` and its deadline. The engine lock is not held while the
    /// prompt is open.
    pub async fn release_extension_key(
        &self,
        device: &str,
        peer: &str,
        nonce: &str,
    ) -> Result<ExtensionRelease, CoreError> {
        let device_id = ids::device(device)?;
        let nonce: [u8; UNLOCK_NONCE_LEN] =
            hasp_proto::base64url::decode_array(nonce).ok_or(hasp_proto::ProtoError::Format)?;
        let (key, biometric) = {
            let mut client = self.client.lock().await;
            client.require_unlocked()?;
            Self::ensure_password_not_due(&client)?;
            let key = Self::held_extension_key(&client, device, peer)?;
            if self.revoked_remotely(&mut client, &device_id).await {
                Self::delete_extension_key(&client, device)?;
                return Err(CoreError::NotFound("extension key"));
            }
            (key, client.biometric())
        };
        let browser = peer.split_once(':').map_or(peer, |(browser, _)| browser);
        let code = unlock_code(&device_id, &nonce);
        biometric.authenticate(&format!("Unlock the {browser} extension. Code {code}"))?;
        let mut client = self.client.lock().await;
        client.require_unlocked()?;
        if !hasp_crypto::ct_eq(
            Self::held_extension_key(&client, device, peer)?.as_bytes(),
            key.as_bytes(),
        ) {
            return Err(CoreError::NotFound("extension key"));
        }
        Self::ensure_password_not_due(&client)?;
        Self::note_time(&mut client)?;
        Ok(ExtensionRelease {
            key,
            valid_until: client.now().saturating_add(EXT_VALID_S),
        })
    }

    fn held_extension_key(
        client: &crate::client::Client<T, S>,
        device: &str,
        peer: &str,
    ) -> Result<Secret, CoreError> {
        let record = client
            .secure_store()
            .get(&format!("{EXT_KEY_PREFIX}{device}"))
            .map_err(|error| match error {
                PlatformError::Missing => CoreError::NotFound("extension key"),
                other => other.into(),
            })?;
        let (key, paired) = record
            .expose()
            .split_at_checked(32)
            .ok_or(CoreError::NotFound("extension key"))?;
        if !hasp_crypto::ct_eq(paired, peer.as_bytes()) {
            return Err(hasp_proto::ProtoError::Authz.into());
        }
        Ok(Secret::from_slice(key))
    }

    fn delete_extension_key(
        client: &crate::client::Client<T, S>,
        device: &str,
    ) -> Result<(), CoreError> {
        client
            .secure_store()
            .delete(&format!("{EXT_KEY_PREFIX}{device}"))?;
        Ok(())
    }

    async fn revoked_remotely(
        &self,
        client: &mut crate::client::Client<T, S>,
        device: &hasp_proto::DeviceId,
    ) -> bool {
        let Ok(listed) = client.devices(&Self::token()).await else {
            return false;
        };
        listed
            .iter()
            .find(|entry| entry.device_id == *device)
            .is_none_or(|entry| entry.revoked)
    }

    /// Whether `device` is still paired as exactly this `peer`, for a desktop-initiated request.
    /// No user presence: it releases nothing.
    pub async fn extension_paired(&self, device: &str, peer: &str) -> bool {
        let client = self.client.lock().await;
        let Ok(record) = client
            .secure_store()
            .get(&format!("{EXT_KEY_PREFIX}{device}"))
        else {
            return false;
        };
        record
            .expose()
            .split_at_checked(32)
            .is_some_and(|(_, paired)| hasp_crypto::ct_eq(paired, peer.as_bytes()))
    }

    pub async fn forget_extension_key(&self, device: &str) -> Result<(), CoreError> {
        let client = self.client.lock().await;
        Self::delete_extension_key(&client, device)
    }

    pub async fn sync(&self) -> Result<SyncSummary, CoreError> {
        self.emit(EventKind::SyncStarted);
        let outcome = {
            let mut client = self.client.lock().await;
            client.sync(&Self::token()).await
        };
        match outcome {
            Ok(report) => {
                let changed = report.vaults.iter().filter(|v| v.commits > 0).count();
                let attention = report
                    .vaults
                    .iter()
                    .filter(|v| !matches!(v.state, VaultSyncState::UpToDate))
                    .count();
                let summary = SyncSummary {
                    vaults: u32::try_from(report.vaults.len()).unwrap_or(u32::MAX),
                    changed: u32::try_from(changed).unwrap_or(u32::MAX),
                    needs_attention: u32::try_from(attention).unwrap_or(u32::MAX),
                };
                self.refresh_provider_index().await;
                self.emit(EventKind::SyncFinished);
                if summary.changed > 0 {
                    self.emit(EventKind::VaultChanged);
                }
                Ok(summary)
            }
            Err(error) => {
                self.emit_failure(&error);
                Err(error)
            }
        }
    }

    pub async fn sync_vault(&self, vault: &str) -> Result<(), CoreError> {
        let id = ids::vault(vault)?;
        let outcome = {
            let mut client = self.client.lock().await;
            client.sync_vault(&id).await
        };
        match outcome {
            Ok(()) => {
                self.events.push(EngineEvent {
                    vault: Some(vault.to_owned()),
                    ..event(EventKind::VaultChanged)
                });
                Ok(())
            }
            Err(error) => {
                self.emit_failure(&error);
                Err(error)
            }
        }
    }

    /// What a hint means for the engine: pull the named vault, pull everything, or lock.
    pub async fn on_hint(&self, hint: HintEvent) {
        match hint {
            HintEvent::Vault(vault) => {
                let _reported_as_event = self.sync_vault(&ids::hex(vault.as_bytes())).await;
            }
            HintEvent::Notice => {
                let _reported_as_event = self.sync().await;
            }
            HintEvent::SessionRevoked => self.session_revoked().await,
        }
    }

    pub async fn session_revoked(&self) {
        let mut client = self.client.lock().await;
        client.lock();
        drop(client);
        self.drop_watchtower().await;
        self.emit(EventKind::SessionRevoked);
    }

    /// The first frame of the hint socket. It carries the session bearer, so it is
    /// a secret: a host sends it once over the socket and drops it.
    pub async fn hint_auth_frame(&self) -> Result<Secret, CoreError> {
        let client = self.client.lock().await;
        let token = hasp_proto::base64url::encode(client.session_token()?.as_bytes());
        let frame = serde_json::json!({ "t": "auth", "token": token }).to_string();
        Ok(Secret::new(frame.into_bytes()))
    }

    /// Acts on one text frame from the hint socket; unknown and pong frames are ignored.
    pub async fn handle_hint_frame(&self, frame: &str) -> Result<(), CoreError> {
        let value: serde_json::Value =
            serde_json::from_str(frame).map_err(|_| hasp_proto::ProtoError::Format)?;
        let hint = match value.get("t").and_then(serde_json::Value::as_str) {
            Some("hint") => {
                let encoded = value
                    .get("vault")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(hasp_proto::ProtoError::Format)?;
                let raw: [u8; 16] = hasp_proto::base64url::decode_array(encoded)
                    .ok_or(hasp_proto::ProtoError::Format)?;
                HintEvent::Vault(hasp_proto::VaultId::from_bytes(raw))
            }
            Some("notice") => HintEvent::Notice,
            Some("session_revoked") => HintEvent::SessionRevoked,
            _ => return Ok(()),
        };
        self.on_hint(hint).await;
        Ok(())
    }

    pub async fn hint_token(&self) -> Result<Secret, CoreError> {
        let client = self.client.lock().await;
        Ok(Secret::from_slice(client.session_token()?.as_bytes()))
    }

    pub async fn devices(&self) -> Result<Vec<DeviceView>, CoreError> {
        let mut client = self.client.lock().await;
        let listed = client.devices(&Self::token()).await?;
        for revoked in listed.iter().filter(|d| d.revoked) {
            Self::delete_extension_key(&client, &ids::hex(revoked.device_id.as_bytes()))?;
        }
        Ok(listed
            .into_iter()
            .map(|d| DeviceView {
                session: ids::hex(d.session_id.as_bytes()),
                device: ids::hex(d.device_id.as_bytes()),
                platform: d.platform,
                label: d.label,
                current: d.current,
                revoked: d.revoked,
            })
            .collect())
    }

    pub async fn revoke_device(&self, session: &str, device: &str) -> Result<(), CoreError> {
        let (session, device) = (ids::session(session)?, ids::device(device)?);
        let mut client = self.client.lock().await;
        client
            .revoke_device(&session, &device, &Self::token())
            .await?;
        Self::delete_extension_key(&client, &ids::hex(device.as_bytes()))
    }

    fn after_password_unlock(client: &mut crate::client::Client<T, S>) -> Result<(), CoreError> {
        client.local_note_put(LAST_PASSWORD, &client.now().to_be_bytes())?;
        Self::note_time(client)?;
        Self::refresh_password_hint(client)
    }

    /// Remembers the latest time this device has seen, sealed. A clock set back past it by more
    /// than `CLOCK_SKEW_S` makes the password rule due, so rolling the clock back cannot stretch
    /// the 14-day window.
    pub(super) fn note_time(client: &mut crate::client::Client<T, S>) -> Result<(), CoreError> {
        let now = client.now();
        if Self::clock_mark(client).is_none_or(|mark| now > mark) {
            client.local_note_put(CLOCK_MARK, &now.to_be_bytes())?;
        }
        Ok(())
    }

    fn clock_mark(client: &crate::client::Client<T, S>) -> Option<u64> {
        client
            .local_note_get(CLOCK_MARK)
            .ok()
            .flatten()
            .and_then(|raw| <[u8; 8]>::try_from(raw.expose()).ok())
            .map(u64::from_be_bytes)
    }

    fn password_deadline(client: &crate::client::Client<T, S>) -> u64 {
        let days = Self::lock_policy_of(client).password_every_days;
        if days == 0 {
            return u64::MAX;
        }
        let rolled_back = Self::clock_mark(client)
            .is_some_and(|mark| mark > client.now().saturating_add(CLOCK_SKEW_S));
        if rolled_back {
            return 0;
        }
        let last = client
            .local_note_get(LAST_PASSWORD)
            .ok()
            .flatten()
            .and_then(|raw| <[u8; 8]>::try_from(raw.expose()).ok())
            .map(u64::from_be_bytes);
        last.map_or(0, |last| {
            last.saturating_add(u64::from(days) * SECONDS_PER_DAY)
        })
    }

    pub(super) fn refresh_password_hint(
        client: &mut crate::client::Client<T, S>,
    ) -> Result<(), CoreError> {
        let deadline = Self::password_deadline(client);
        client.meta_put(PASSWORD_DUE_HINT, &deadline.to_be_bytes())
    }

    /// Whether the password rule requires the password now. While unlocked this reads the
    /// sealed record; while locked it can only read an unauthenticated hint, which is advisory:
    /// every key release re-checks with `ensure_password_not_due`.
    pub(super) fn password_due(client: &crate::client::Client<T, S>) -> bool {
        let deadline = if client.is_unlocked() {
            Self::password_deadline(client)
        } else {
            client
                .meta_get(PASSWORD_DUE_HINT)
                .ok()
                .flatten()
                .and_then(|raw| <[u8; 8]>::try_from(raw).ok())
                .map_or(0, u64::from_be_bytes)
        };
        client.now() >= deadline
    }

    pub(super) fn ensure_password_not_due(
        client: &crate::client::Client<T, S>,
    ) -> Result<(), CoreError> {
        if client.is_unlocked() && Self::password_deadline(client) <= client.now() {
            return Err(CoreError::Refused("password required"));
        }
        Ok(())
    }

    fn emit_failure(&self, error: &CoreError) {
        let kind = match error {
            CoreError::Transport(TransportError::Unreachable) => EventKind::Offline,
            CoreError::DeviceRevoked => EventKind::DeviceRevoked,
            CoreError::SessionExpired => EventKind::SessionRevoked,
            _ => EventKind::NeedsAttention,
        };
        self.emit(kind);
    }
}

fn secret_key(secret: &Secret) -> Result<hasp_crypto::SecretKey, CoreError> {
    let bytes: [u8; 32] = secret
        .as_bytes()
        .try_into()
        .map_err(|_| hasp_proto::ProtoError::Format)?;
    Ok(hasp_crypto::SecretKey::from_bytes(bytes))
}
