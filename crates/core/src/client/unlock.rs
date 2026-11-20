use std::collections::BTreeMap;

use hasp_crypto::{Argon2idParams, SecretKey};
use hasp_proto::wire::{SessionList, SessionToken};
use hasp_proto::{
    Aad, KeysetKeys, LocalField, PinState, ProtoError, SealedRaw, SecretAscii, VaultId, VaultKind,
    head_code, vk_commit,
};
use secrecy::{ExposeSecret, SecretString};
use tokio_util::sync::CancellationToken;

use super::auth::{Subject, check_server_key, opaque_login};
use super::{Client, ClientConfig, ClientState, ctx};
use crate::CoreError;
use crate::keys::{copy_key, derive_account_secrets, kdf_params, local_key, secret_from_slice};
use crate::platform::Platform;
use crate::session::{Identity, Session};
use crate::store::{AccountLocal, Batch, Records, Store, UnlockClass};
use crate::sync::{refresh_pins, server_code};
use crate::transport::{Transport, TransportError};

pub(crate) const DUK_LABEL: &str = "hasp.duk";
pub(super) const FAILURES_BEFORE_DELAY: u32 = 5;
const BASE_DELAY_S: u64 = 2;
const MAX_DELAY_S: u64 = 15 * 60;

pub(crate) const fn field_code(field: LocalField) -> u8 {
    match field {
        LocalField::AkBio => 1,
        LocalField::Sk => 2,
        LocalField::Session => 3,
        LocalField::AkPw => 4,
        LocalField::SessionPw => 5,
        LocalField::ExtAk => 6,
        LocalField::ExtSession => 7,
        LocalField::ExtKey => 8,
    }
}

pub(super) struct Unlocking<'a> {
    pub local: &'a AccountLocal,
    pub ak: SecretKey,
    pub sk: &'a SecretAscii,
    pub token: Option<SessionToken>,
    pub password: Option<&'a str>,
}

#[derive(Clone, Copy)]
pub(super) struct LocalSecrets<'a> {
    pub ak: &'a SecretKey,
    pub sk: &'a SecretAscii,
    pub token: &'a SessionToken,
}

pub(crate) struct Material {
    pub duk: Option<SecretKey>,
    pub k_loc: Option<SecretKey>,
}

impl std::fmt::Debug for Material {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Material(..)")
    }
}

fn local_params(config: &ClientConfig) -> Result<Argon2idParams, CoreError> {
    Ok(Argon2idParams::local(
        config.local_kdf.m,
        config.local_kdf.t,
        config.local_kdf.p,
    )?)
}

impl Material {
    pub(super) fn create(
        platform: &Platform,
        config: &ClientConfig,
        local: &AccountLocal,
        password: Option<&str>,
    ) -> Result<Self, CoreError> {
        match local.class {
            UnlockClass::Hardware => {
                let duk = SecretKey::random()?;
                platform.secure.put(DUK_LABEL, duk.expose())?;
                Ok(Self {
                    duk: Some(duk),
                    k_loc: None,
                })
            }
            UnlockClass::PasswordOnly => {
                let password = password.ok_or(CoreError::Refused("a password is required"))?;
                Ok(Self {
                    duk: None,
                    k_loc: Some(local_key(
                        password,
                        &local.local_salt,
                        &local_params(config)?,
                    )?),
                })
            }
            UnlockClass::Extension => Ok(Self {
                duk: None,
                k_loc: None,
            }),
        }
    }

    pub(super) fn write(
        &self,
        batch: &mut Batch,
        local: &mut AccountLocal,
        secrets: &LocalSecrets<'_>,
    ) -> Result<(), CoreError> {
        let LocalSecrets { ak, sk, token } = secrets;
        local.local_gen = local.local_gen.saturating_add(1);
        let generation = hasp_proto::Uint53::new(local.local_gen)?;
        let seal = |key: &SecretKey, field: LocalField, plain: &[u8]| {
            SealedRaw::seal(
                key,
                plain,
                &Aad::device_local(local.account_id, field, local.device_id, generation),
            )
        };
        if let Some(duk) = &self.duk {
            Records::put_blob(
                batch,
                field_code(LocalField::AkBio),
                &seal(duk, LocalField::AkBio, ak.expose())?,
            )?;
            Records::put_blob(
                batch,
                field_code(LocalField::Sk),
                &seal(duk, LocalField::Sk, sk.expose())?,
            )?;
            Records::put_blob(
                batch,
                field_code(LocalField::Session),
                &seal(duk, LocalField::Session, token.as_bytes())?,
            )?;
        }
        if let Some(k_loc) = &self.k_loc {
            Records::put_blob(
                batch,
                field_code(LocalField::AkPw),
                &seal(k_loc, LocalField::AkPw, ak.expose())?,
            )?;
            Records::put_blob(
                batch,
                field_code(LocalField::SessionPw),
                &seal(k_loc, LocalField::SessionPw, token.as_bytes())?,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadInfo {
    pub vault_id: VaultId,
    pub kind: VaultKind,
    pub seq: u64,
    pub code: String,
    pub confirmed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confirmation {
    Confirmed,
    NeedsSync { local_seq: u64 },
}

fn open_blob(
    cache_blob: Option<SealedRaw>,
    key: &SecretKey,
    local: &AccountLocal,
    field: LocalField,
) -> Result<hasp_crypto::SecretBytes, CoreError> {
    let blob = cache_blob.ok_or(CoreError::Credentials)?;
    let generation = hasp_proto::Uint53::new(local.local_gen)?;
    blob.open(
        key,
        &Aad::device_local(local.account_id, field, local.device_id, generation),
    )
    .map_err(|_| CoreError::Credentials)
}

impl<T: Transport, S: Store> Client<T, S> {
    pub fn lock(&mut self) {
        self.session = None;
    }

    pub fn is_unlocked(&self) -> bool {
        matches!(self.state(), Ok(ClientState::Unlocked))
    }

    pub(super) fn check_lockout(&self) -> Result<(), CoreError> {
        let now = self.platform.clock.now();
        if self.failed_unlocks >= FAILURES_BEFORE_DELAY && now < self.locked_until {
            return Err(CoreError::Pending {
                retry_after: self.locked_until.saturating_sub(now),
            });
        }
        Ok(())
    }

    pub(super) fn note_failure(&mut self) {
        self.failed_unlocks = self.failed_unlocks.saturating_add(1);
        if self.failed_unlocks >= FAILURES_BEFORE_DELAY {
            let steps = self
                .failed_unlocks
                .saturating_sub(FAILURES_BEFORE_DELAY)
                .min(20);
            let delay = BASE_DELAY_S.saturating_mul(1_u64 << steps).min(MAX_DELAY_S);
            self.locked_until = self.platform.clock.now().saturating_add(delay);
        }
    }

    pub async fn unlock_password(
        &mut self,
        password: &SecretString,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        let cancel = self.begin(call);
        self.check_lockout()?;
        let local = self.cache.account()?.ok_or(CoreError::Locked)?;
        let opened = self.open_ak_with_password(&local, password.expose_secret());
        let (ak, sk, token) = match opened {
            Ok(opened) => opened,
            Err(error) => {
                self.note_failure();
                return Err(error);
            }
        };
        self.failed_unlocks = 0;
        self.finish_unlock(
            Unlocking {
                local: &local,
                ak,
                sk: &sk,
                token,
                password: Some(password.expose_secret()),
            },
            &cancel,
        )
        .await
    }

    /// Moves a password-only device to the hardware class once the platform can gate a key
    /// (protocol 4.6): the password opens the keys, a fresh `DUK` seals them, and the password
    /// blobs are replaced.
    pub fn enable_hardware_unlock(
        &mut self,
        password: &SecretString,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        let _cancel = self.begin(call);
        if !self.platform.secure.hardware_gated() {
            return Err(CoreError::Refused(
                "this device has no hardware-gated store",
            ));
        }
        self.check_lockout()?;
        let mut local = self.cache.account()?.ok_or(CoreError::Locked)?;
        if local.class != UnlockClass::PasswordOnly {
            return Err(CoreError::Refused("this device is not password-only"));
        }
        let (ak, sk, token) = match self.open_ak_with_password(&local, password.expose_secret()) {
            Ok(opened) => opened,
            Err(error) => {
                self.note_failure();
                return Err(error);
            }
        };
        self.failed_unlocks = 0;
        let token = token.unwrap_or_else(|| SessionToken::from_bytes([0; 32]));
        local.class = UnlockClass::Hardware;
        let mut batch = Batch::new();
        let material = Material::create(&self.platform, &self.config, &local, None)?;
        material.write(
            &mut batch,
            &mut local,
            &LocalSecrets {
                ak: &ak,
                sk: &sk,
                token: &token,
            },
        )?;
        Records::delete_blob(&mut batch, field_code(LocalField::AkPw));
        Records::delete_blob(&mut batch, field_code(LocalField::SessionPw));
        Records::put_account(&mut batch, &local)?;
        self.cache.commit(&batch)?;
        Ok(())
    }

    pub(super) fn open_ak_with_password(
        &self,
        local: &AccountLocal,
        password: &str,
    ) -> Result<(SecretKey, SecretAscii, Option<SessionToken>), CoreError> {
        let record = local.record.unverified()?;
        match local.class {
            UnlockClass::Hardware => {
                let duk = secret_from_slice(&self.platform.secure.get(DUK_LABEL)?)?;
                let sk_bytes = open_blob(
                    self.cache.blob(field_code(LocalField::Sk))?,
                    &duk,
                    local,
                    LocalField::Sk,
                )?;
                let sk = SecretAscii::from_ascii(sk_bytes.expose())?;
                let params = kdf_params(&record.kdf, self.config.max_kdf_m_kib)?;
                let secrets = derive_account_secrets(password, &sk, &local.account_id, &params)?;
                let ak = local
                    .keyset
                    .ak_wrap
                    .open(
                        &secrets.auk,
                        &Aad::ak_wrap(local.account_id, &record.kdf, local.keyset.generation),
                    )
                    .map_err(|_| CoreError::Credentials)?;
                let token = self.stored_token(local, &duk, LocalField::Session);
                Ok((secret_from_slice(&ak)?, sk, token))
            }
            UnlockClass::PasswordOnly => {
                let k_loc = local_key(password, &local.local_salt, &local_params(&self.config)?)?;
                self.open_with_local_key(local, &k_loc)
            }
            UnlockClass::Extension => Err(CoreError::Refused(
                "this device unlocks through the desktop app",
            )),
        }
    }

    fn open_with_local_key(
        &self,
        local: &AccountLocal,
        k_loc: &SecretKey,
    ) -> Result<(SecretKey, SecretAscii, Option<SessionToken>), CoreError> {
        let ak = open_blob(
            self.cache.blob(field_code(LocalField::AkPw))?,
            k_loc,
            local,
            LocalField::AkPw,
        )?;
        let ak = secret_from_slice(&ak)?;
        let keys = Self::open_keys(local, &ak)?;
        let sk = SecretAscii::from_ascii(keys.sk_ascii.expose())?;
        let token = self.stored_token(local, k_loc, LocalField::SessionPw);
        Ok((ak, sk, token))
    }

    /// Password unlock of a password-only device that also returns `K_loc`, the key that opens
    /// the device-local blobs (protocol 4.6). `K_loc` is derived from the password but does not
    /// reveal it, and it cannot log in: a host keeps it in session-scoped storage and resumes
    /// with `resume_with_session_key`, so the password itself never has to be kept.
    pub async fn unlock_password_session(
        &mut self,
        password: &SecretString,
        call: &CancellationToken,
    ) -> Result<SecretKey, CoreError> {
        let cancel = self.begin(call);
        self.check_lockout()?;
        let local = self.cache.account()?.ok_or(CoreError::Locked)?;
        if local.class != UnlockClass::PasswordOnly {
            return Err(CoreError::Refused(
                "only a password-only device has a session key",
            ));
        }
        let k_loc = local_key(
            password.expose_secret(),
            &local.local_salt,
            &local_params(&self.config)?,
        )?;
        let (ak, sk, token) = match self.open_with_local_key(&local, &k_loc) {
            Ok(opened) => opened,
            Err(error) => {
                self.note_failure();
                return Err(error);
            }
        };
        self.failed_unlocks = 0;
        self.finish_unlock(
            Unlocking {
                local: &local,
                ak,
                sk: &sk,
                token,
                password: Some(password.expose_secret()),
            },
            &cancel,
        )
        .await?;
        Ok(k_loc)
    }

    /// Unlocks a password-only device with the `K_loc` of an earlier `unlock_password_session`.
    /// If the stored server session has expired the device stays unlocked offline-capable and
    /// the next server call asks for the password.
    pub async fn resume_with_session_key(
        &mut self,
        k_loc: &SecretKey,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        let cancel = self.begin(call);
        let local = self.cache.account()?.ok_or(CoreError::Locked)?;
        if local.class != UnlockClass::PasswordOnly {
            return Err(CoreError::Refused(
                "only a password-only device has a session key",
            ));
        }
        let (ak, sk, token) = self.open_with_local_key(&local, k_loc)?;
        self.finish_unlock(
            Unlocking {
                local: &local,
                ak,
                sk: &sk,
                token,
                password: None,
            },
            &cancel,
        )
        .await
    }

    fn stored_token(
        &self,
        local: &AccountLocal,
        key: &SecretKey,
        field: LocalField,
    ) -> Option<SessionToken> {
        let blob = self.cache.blob(field_code(field)).ok()?;
        let opened = open_blob(blob, key, local, field).ok()?;
        let bytes: zeroize::Zeroizing<[u8; 32]> =
            zeroize::Zeroizing::new(opened.expose().try_into().ok()?);
        Some(SessionToken::from_bytes(*bytes))
    }

    pub(crate) fn open_keys(local: &AccountLocal, ak: &SecretKey) -> Result<KeysetKeys, CoreError> {
        let k_keyset = crate::keys::ak_keys(ak)?.keyset;
        local
            .keyset
            .keys
            .open(
                &k_keyset,
                &Aad::keyset_keys(local.account_id, local.keyset.generation),
            )
            .map_err(|_| CoreError::Credentials)
    }

    pub async fn unlock_biometric(&mut self, call: &CancellationToken) -> Result<(), CoreError> {
        self.unlock_gated(call, true).await
    }

    /// The unlock of an autofill extension: the biometric-gated device key opens the account
    /// key, no Argon2 runs and no server is called.
    pub async fn unlock_provider(&mut self, call: &CancellationToken) -> Result<(), CoreError> {
        self.unlock_gated(call, false).await
    }

    async fn unlock_gated(
        &mut self,
        call: &CancellationToken,
        online: bool,
    ) -> Result<(), CoreError> {
        let cancel = self.begin(call);
        let local = self.cache.account()?.ok_or(CoreError::Locked)?;
        if local.class != UnlockClass::Hardware {
            return Err(CoreError::Refused(
                "biometric unlock needs a hardware-gated platform",
            ));
        }
        self.check_lockout()?;
        if let Err(error) = self.platform.biometric.authenticate("Unlock hasp") {
            self.note_failure();
            return Err(error.into());
        }
        let duk = secret_from_slice(&self.platform.secure.get(DUK_LABEL)?)?;
        let ak = open_blob(
            self.cache.blob(field_code(LocalField::AkBio))?,
            &duk,
            &local,
            LocalField::AkBio,
        )?;
        let sk_bytes = open_blob(
            self.cache.blob(field_code(LocalField::Sk))?,
            &duk,
            &local,
            LocalField::Sk,
        )?;
        let sk = SecretAscii::from_ascii(sk_bytes.expose())?;
        let token = self.stored_token(&local, &duk, LocalField::Session);
        self.failed_unlocks = 0;
        let unlocking = Unlocking {
            local: &local,
            ak: secret_from_slice(&ak)?,
            sk: &sk,
            token,
            password: None,
        };
        if online {
            self.finish_unlock(unlocking, &cancel).await
        } else {
            self.install_session(&unlocking, &cancel, false)
        }
    }

    pub(super) async fn finish_unlock(
        &mut self,
        unlocking: Unlocking<'_>,
        cancel: &crate::session::Cancel,
    ) -> Result<(), CoreError> {
        self.install_session(&unlocking, cancel, true)?;
        let Unlocking {
            local,
            sk,
            password,
            ..
        } = unlocking;
        let ping = {
            let cx = ctx!(self, cancel);
            cx.call(&SessionList {}).await
        };
        match ping {
            Ok(_) | Err(CoreError::Transport(TransportError::Unreachable)) => Ok(()),
            Err(CoreError::SessionExpired | CoreError::Credentials) => match password {
                Some(password) => self.relogin(local, sk, password, cancel).await,
                None if local.class == UnlockClass::Extension => {
                    self.wipe_local()?;
                    Err(CoreError::DeviceRevoked)
                }
                None => Ok(()),
            },
            Err(error) if server_code(&error).is_some() => Ok(()),
            Err(error) => {
                self.session = None;
                Err(error)
            }
        }
    }

    fn install_session(
        &mut self,
        unlocking: &Unlocking<'_>,
        cancel: &crate::session::Cancel,
        with_pins: bool,
    ) -> Result<(), CoreError> {
        let record = unlocking.local.record.unverified()?;
        let keys = Self::open_keys(unlocking.local, &unlocking.ak)?;
        let identity = Identity::from_keys(&record, copy_key(&unlocking.ak), &keys)?;
        let mut session = Session {
            identity,
            token: unlocking
                .token
                .clone()
                .unwrap_or_else(|| SessionToken::from_bytes([0; 32])),
            opk: None,
            vks: BTreeMap::new(),
            pins: PinState::new(),
        };
        self.load_vks(&mut session)?;
        self.session = Some(session);
        if !with_pins {
            return Ok(());
        }
        let mut cx = ctx!(self, cancel);
        refresh_pins(&mut cx)
    }

    async fn relogin(
        &mut self,
        local: &AccountLocal,
        sk: &SecretAscii,
        password: &str,
        cancel: &crate::session::Cancel,
    ) -> Result<(), CoreError> {
        let record = local.record.unverified()?;
        let params = kdf_params(&record.kdf, self.config.max_kdf_m_kib)?;
        let secrets = derive_account_secrets(password, sk, &local.account_id, &params)?;
        let subject = Subject {
            origin: &local.origin,
            account: local.account_id,
            kdf: &record.kdf,
        };
        let device = hasp_proto::wire::DeviceInfo {
            device_id: local.device_id,
            platform: local.platform.clone(),
            label: None,
        };
        check_server_key(&self.transport, cancel, &local.origin, &local.server_fp).await?;
        let done = opaque_login(&self.transport, cancel, &subject, &secrets.opk, device).await?;
        if done.server_fp != local.server_fp {
            self.session = None;
            return Err(CoreError::ServerKey);
        }
        let session = self.session.as_mut().ok_or(CoreError::Locked)?;
        session.token = done.token.clone();
        session.opk = Some(copy_key(&secrets.opk));
        let mut local = local.clone();
        let mut batch = Batch::new();
        let ak = copy_key(&session.identity.ak);
        let material = Material::create_existing(&self.platform, &self.config, &local, password)?;
        material.write(
            &mut batch,
            &mut local,
            &LocalSecrets {
                ak: &ak,
                sk,
                token: &done.token,
            },
        )?;
        Records::put_account(&mut batch, &local)?;
        self.cache.commit(&batch)?;
        Ok(())
    }

    fn load_vks(&self, session: &mut Session) -> Result<(), CoreError> {
        for vault in self.cache.vaults()? {
            for (epoch, wrap) in self.cache.self_wraps(&vault.vault_id)? {
                let Ok(opened) = wrap.open(
                    &session.identity.k_self,
                    &Aad::self_wrap(session.identity.account_id, vault.vault_id, epoch),
                ) else {
                    continue;
                };
                let vk = secret_from_slice(&opened)?;
                let ok = vault.vk_commits.get(&epoch.get()).is_none_or(|expected| {
                    vk_commit(&vk, &vault.vault_id, epoch).is_ok_and(|got| got == *expected)
                });
                if ok {
                    session.put_vk(vault.vault_id, epoch, &vk);
                }
            }
        }
        Ok(())
    }

    pub fn heads(&self) -> Result<Vec<HeadInfo>, CoreError> {
        let mut out = Vec::new();
        for vault in self.cache.vaults()? {
            let Some(head) = &vault.head else { continue };
            let state = head.state()?;
            out.push(HeadInfo {
                vault_id: vault.vault_id,
                kind: vault.kind,
                seq: head.seq.get(),
                code: head_code(
                    &vault.vault_id,
                    state.rver,
                    state.epoch,
                    head.seq,
                    &head.hash,
                )?,
                confirmed: vault.confirmed,
            });
        }
        Ok(out)
    }

    pub fn confirm_head(
        &mut self,
        vault: VaultId,
        remote_seq: u64,
        remote_code: &str,
    ) -> Result<Confirmation, CoreError> {
        let mut local = self
            .cache
            .vault(&vault)?
            .ok_or(CoreError::NotFound("vault"))?;
        let head = local
            .head
            .as_ref()
            .ok_or(CoreError::NotFound("vault state"))?;
        if head.seq.get() != remote_seq {
            return Ok(Confirmation::NeedsSync {
                local_seq: head.seq.get(),
            });
        }
        let state = head.state()?;
        let mine = head_code(&vault, state.rver, state.epoch, head.seq, &head.hash)?;
        let normalised = |code: &str| {
            code.chars()
                .filter(|c| *c != '-' && !c.is_whitespace())
                .map(|c| c.to_ascii_uppercase())
                .collect::<String>()
        };
        if normalised(&mine) != normalised(remote_code) {
            return Err(ProtoError::Fork.into());
        }
        local.confirmed = true;
        let mut batch = Batch::new();
        Records::put_vault(&mut batch, &local)?;
        if self
            .cache
            .vaults()?
            .iter()
            .all(|v| v.vault_id == vault || v.confirmed || v.head.is_none())
        {
            Records::put_meta(&mut batch, "device-confirmed", b"1");
        }
        self.cache.commit(&batch)?;
        Ok(Confirmation::Confirmed)
    }

    /// A user with no other device and no member may accept the risk for the Private vault only;
    /// shared writes stay blocked (protocol 7.3 item 5).
    pub fn confirm_private_unverified(&mut self) -> Result<(), CoreError> {
        let mut batch = Batch::new();
        for mut vault in self.cache.vaults()? {
            if vault.kind == VaultKind::Private && !vault.confirmed {
                vault.confirmed = true;
                Records::put_vault(&mut batch, &vault)?;
            }
        }
        self.cache.commit(&batch)?;
        Ok(())
    }

    pub fn device_confirmed(&self) -> Result<bool, CoreError> {
        crate::sync::device_confirmed_pub(&self.cache)
    }
}

impl Material {
    pub(super) fn create_existing(
        platform: &Platform,
        config: &ClientConfig,
        local: &AccountLocal,
        password: &str,
    ) -> Result<Self, CoreError> {
        match local.class {
            UnlockClass::Hardware => Ok(Self {
                duk: Some(secret_from_slice(&platform.secure.get(DUK_LABEL)?)?),
                k_loc: None,
            }),
            UnlockClass::PasswordOnly => Ok(Self {
                duk: None,
                k_loc: Some(local_key(
                    password,
                    &local.local_salt,
                    &local_params(config)?,
                )?),
            }),
            UnlockClass::Extension => Ok(Self {
                duk: None,
                k_loc: None,
            }),
        }
    }
}
