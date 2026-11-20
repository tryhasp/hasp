use hasp_core::platform::{PlatformError, SecureStore};
use hasp_crypto::SecretBytes;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::passwords::{
    PasswordOptions, delete_generic_password, delete_generic_password_options, generic_password,
    get_generic_password, set_generic_password, set_generic_password_options,
};
use security_framework::passwords_options::AccessControlOptions;

const SERVICE: &str = "hasp";
const PROBE: &str = "hasp.probe";
const ERR_ITEM_NOT_FOUND: i32 = -25300;

#[derive(Debug)]
pub(super) struct Keychain {
    gated: bool,
}

fn gated_options(label: &str) -> Result<PasswordOptions, security_framework::base::Error> {
    let mut options = PasswordOptions::new_generic_password(SERVICE, label);
    options.use_protected_keychain();
    options.set_access_control(SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        AccessControlOptions::USER_PRESENCE.bits(),
    )?);
    Ok(options)
}

impl Keychain {
    // Why: user-presence items need the data-protection keychain, which an unsigned build may
    // not use; then the store holds items in the login keychain and is not hardware-gated.
    pub(super) fn probe() -> Self {
        let written = gated_options(PROBE)
            .and_then(|options| set_generic_password_options(b"probe", options))
            .is_ok();
        if written && let Ok(options) = gated_options(PROBE) {
            delete_generic_password_options(options).ok();
        }
        Self { gated: written }
    }
}

fn map(error: security_framework::base::Error) -> PlatformError {
    if error.code() == ERR_ITEM_NOT_FOUND {
        PlatformError::Missing
    } else {
        PlatformError::Store
    }
}

impl SecureStore for Keychain {
    fn hardware_gated(&self) -> bool {
        self.gated
    }

    fn put(&self, label: &str, secret: &[u8]) -> Result<(), PlatformError> {
        if self.gated {
            self.delete(label)?;
            let options = gated_options(label).map_err(map)?;
            set_generic_password_options(secret, options).map_err(map)
        } else {
            set_generic_password(SERVICE, label, secret).map_err(map)
        }
    }

    fn get(&self, label: &str) -> Result<SecretBytes, PlatformError> {
        let bytes = if self.gated {
            generic_password(gated_options(label).map_err(map)?)
        } else {
            get_generic_password(SERVICE, label)
        }
        .map_err(map)?;
        Ok(SecretBytes::from_vec(bytes))
    }

    fn delete(&self, label: &str) -> Result<(), PlatformError> {
        let deleted = if self.gated {
            let legacy = delete_generic_password(SERVICE, label);
            if let Err(error) = legacy
                && error.code() != ERR_ITEM_NOT_FOUND
            {
                return Err(map(error));
            }
            delete_generic_password_options(gated_options(label).map_err(map)?)
        } else {
            delete_generic_password(SERVICE, label)
        };
        match deleted {
            Ok(()) => Ok(()),
            Err(error) if error.code() == ERR_ITEM_NOT_FOUND => Ok(()),
            Err(error) => Err(map(error)),
        }
    }
}
