use serde::{Deserialize, Serialize};

use super::engine::Engine;
use super::{EventKind, LockPolicy, LockTrigger, SecretTag, Settings};
use crate::CoreError;
use crate::client::Client;
use crate::store::Store;
use crate::transport::Transport;

const SETTINGS: &str = "settings";
const TAG_NOTE: &str = "secret-tag";
const LANGUAGE_HINT: &str = "language-hint";
pub(super) const PASSWORD_DUE_HINT: &str = "password-due-hint";

pub(super) struct Loaded {
    stored: Stored,
    pub(super) tampered: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one flag per persisted setting"
)]
struct Stored {
    idle_minutes: u32,
    lock_on_sleep: bool,
    lock_on_screen_lock: bool,
    lock_on_user_switch: bool,
    lock_on_quit: bool,
    background_seconds: u32,
    password_every_days: u32,
    clipboard_clear_seconds: u32,
    language: String,
    inline_menu: bool,
    auto_submit: bool,
    ask_before_filling: bool,
    hardened_mode: bool,
    copy_totp_after_fill: bool,
    breach_check: bool,
}

impl Default for Stored {
    fn default() -> Self {
        let lock = LockPolicy::default();
        Self {
            idle_minutes: lock.idle_minutes,
            lock_on_sleep: lock.lock_on_sleep,
            lock_on_screen_lock: lock.lock_on_screen_lock,
            lock_on_user_switch: lock.lock_on_user_switch,
            lock_on_quit: lock.lock_on_quit,
            background_seconds: lock.background_seconds,
            password_every_days: lock.password_every_days,
            clipboard_clear_seconds: lock.clipboard_clear_seconds,
            language: "ko".to_owned(),
            inline_menu: true,
            auto_submit: true,
            ask_before_filling: false,
            hardened_mode: false,
            copy_totp_after_fill: false,
            breach_check: false,
        }
    }
}

impl Default for LockPolicy {
    fn default() -> Self {
        Self {
            idle_minutes: 10,
            lock_on_sleep: true,
            lock_on_screen_lock: true,
            lock_on_user_switch: true,
            lock_on_quit: true,
            background_seconds: 60,
            password_every_days: 14,
            clipboard_clear_seconds: 30,
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::from_stored(Stored::default(), None)
    }
}

impl Settings {
    fn from_stored(stored: Stored, secret_tag: Option<SecretTag>) -> Self {
        Self {
            lock: LockPolicy {
                idle_minutes: stored.idle_minutes,
                lock_on_sleep: stored.lock_on_sleep,
                lock_on_screen_lock: stored.lock_on_screen_lock,
                lock_on_user_switch: stored.lock_on_user_switch,
                lock_on_quit: stored.lock_on_quit,
                background_seconds: stored.background_seconds,
                password_every_days: stored.password_every_days,
                clipboard_clear_seconds: stored.clipboard_clear_seconds,
            },
            secret_tag,
            language: stored.language,
            inline_menu: stored.inline_menu,
            auto_submit: stored.auto_submit,
            ask_before_filling: stored.ask_before_filling,
            hardened_mode: stored.hardened_mode,
            copy_totp_after_fill: stored.copy_totp_after_fill,
            breach_check: stored.breach_check,
        }
    }

    fn to_stored(&self) -> Stored {
        Stored {
            idle_minutes: self.lock.idle_minutes,
            lock_on_sleep: self.lock.lock_on_sleep,
            lock_on_screen_lock: self.lock.lock_on_screen_lock,
            lock_on_user_switch: self.lock.lock_on_user_switch,
            lock_on_quit: self.lock.lock_on_quit,
            background_seconds: self.lock.background_seconds,
            password_every_days: self.lock.password_every_days,
            clipboard_clear_seconds: self.lock.clipboard_clear_seconds,
            language: self.language.clone(),
            inline_menu: self.inline_menu,
            auto_submit: self.auto_submit,
            ask_before_filling: self.ask_before_filling,
            hardened_mode: self.hardened_mode,
            copy_totp_after_fill: self.copy_totp_after_fill,
            breach_check: self.breach_check,
        }
    }
}

fn load<T: Transport, S: Store>(client: &Client<T, S>) -> Loaded {
    if !client.is_unlocked() {
        let language = client
            .meta_get(LANGUAGE_HINT)
            .ok()
            .flatten()
            .and_then(|raw| String::from_utf8(raw).ok())
            .filter(|language| language.len() <= 8);
        let mut stored = Stored::default();
        if let Some(language) = language {
            stored.language = language;
        }
        return Loaded {
            stored,
            tampered: false,
        };
    }
    match client.local_note_get(SETTINGS) {
        Ok(None) => Loaded {
            stored: Stored::default(),
            tampered: false,
        },
        Ok(Some(raw)) => match serde_json::from_slice(raw.expose()) {
            Ok(stored) => Loaded {
                stored,
                tampered: false,
            },
            Err(_) => Loaded {
                stored: Stored::default(),
                tampered: true,
            },
        },
        Err(_) => Loaded {
            stored: Stored::default(),
            tampered: true,
        },
    }
}

fn validate_tag(tag: &SecretTag) -> Result<(), CoreError> {
    let word = tag.word.trim();
    if word.is_empty()
        || word.chars().count() > super::SECRET_TAG_WORD_MAX
        || word.chars().any(char::is_control)
    {
        return Err(CoreError::Refused("secret tag word"));
    }
    if tag.glyph >= super::SECRET_TAG_GLYPHS {
        return Err(CoreError::Refused("secret tag glyph"));
    }
    Ok(())
}

impl<T: Transport, S: Store> Engine<T, S> {
    pub(super) fn lock_policy_of(client: &Client<T, S>) -> LockPolicy {
        Settings::from_stored(load(client).stored, None).lock
    }

    pub(super) fn settings_sync(client: &Client<T, S>) -> Settings {
        Settings::from_stored(load(client).stored, None)
    }

    pub async fn settings(&self) -> Result<Settings, CoreError> {
        let mut client = self.client.lock().await;
        let loaded = load(&client);
        if loaded.tampered {
            let defaults = serde_json::to_vec(&Stored::default())
                .map_err(|_| CoreError::Internal("settings"))?;
            client.local_note_put(SETTINGS, &defaults)?;
            self.emit(EventKind::NeedsAttention);
        }
        let tag = match client.local_note_get(TAG_NOTE) {
            Ok(Some(raw)) => serde_json::from_slice::<(String, u32)>(raw.expose())
                .ok()
                .map(|(word, glyph)| SecretTag { word, glyph }),
            _ => None,
        };
        Ok(Settings::from_stored(load(&client).stored, tag))
    }

    pub async fn set_settings(&self, settings: Settings) -> Result<(), CoreError> {
        if let Some(tag) = &settings.secret_tag {
            validate_tag(tag)?;
        }
        let mut client = self.client.lock().await;
        let encoded = serde_json::to_vec(&settings.to_stored())
            .map_err(|_| CoreError::Internal("settings"))?;
        client.local_note_put(SETTINGS, &encoded)?;
        client.meta_put(LANGUAGE_HINT, settings.language.as_bytes())?;
        Self::refresh_password_hint(&mut client)?;
        if let Some(tag) = &settings.secret_tag {
            let raw = serde_json::to_vec(&(tag.word.trim(), tag.glyph))
                .map_err(|_| CoreError::Internal("settings"))?;
            client.local_note_put(TAG_NOTE, &raw)?;
        }
        self.emit(EventKind::SettingsChanged);
        Ok(())
    }

    /// Applies the shared lock policy to one trigger and locks when it says so.
    /// `elapsed_seconds` is the idle or background time for those two triggers.
    pub async fn apply_lock_trigger(
        &self,
        trigger: LockTrigger,
        elapsed_seconds: u64,
    ) -> Result<bool, CoreError> {
        let mut client = self.client.lock().await;
        let policy = Self::lock_policy_of(&client);
        let lock = match trigger {
            LockTrigger::Sleep => policy.lock_on_sleep,
            LockTrigger::ScreenLock => policy.lock_on_screen_lock,
            LockTrigger::UserSwitch => policy.lock_on_user_switch,
            LockTrigger::Quit => policy.lock_on_quit,
            LockTrigger::Manual => true,
            LockTrigger::Idle => {
                policy.idle_minutes > 0 && elapsed_seconds >= u64::from(policy.idle_minutes) * 60
            }
            LockTrigger::Background => elapsed_seconds >= u64::from(policy.background_seconds),
        };
        if lock && client.is_unlocked() {
            client.lock();
            drop(client);
            self.drop_watchtower().await;
            self.emit(EventKind::Locked);
        }
        Ok(lock)
    }
}
