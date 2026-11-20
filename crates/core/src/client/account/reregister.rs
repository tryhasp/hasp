use hasp_crypto::OpaqueClientRegistration;
use hasp_proto::wire::{DeviceInfo, ReregisterFinish, ReregisterStart, SignupToken};
use secrecy::{ExposeSecret, SecretString};
use tokio_util::sync::CancellationToken;

use crate::CoreError;
use crate::client::Client;
use crate::client::auth::{Subject, opaque_login, register_finish, server_fingerprint};
use crate::client::unlock::{LocalSecrets, Material};
use crate::keys::{derive_account_secrets, kdf_params};
use crate::store::{Batch, Records, Store};
use crate::transport::Transport;

impl<T: Transport, S: Store> Client<T, S> {
    /// Protocol 7.14, server-secret loss. The local copy opens with the password (proof of the
    /// password and Secret Key), a fresh OPAQUE credential for the same keys is registered under
    /// the operator's token, and the device pins the server fingerprint the user compared with
    /// `haspd fingerprint`. Nothing is sent unless the server key matches `expected_fp`.
    pub async fn reregister(
        &mut self,
        token: &str,
        password: &SecretString,
        expected_fp: [u8; 15],
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        let cancel = self.begin(call);
        self.check_lockout()?;
        let token = SignupToken::parse(token)?;
        let mut local = self.cache.account()?.ok_or(CoreError::Locked)?;
        let opened = self.open_ak_with_password(&local, password.expose_secret());
        let (ak, sk, _) = match opened {
            Ok(opened) => opened,
            Err(error) => {
                self.note_failure();
                return Err(error);
            }
        };
        let record = local.record.unverified()?;
        let params = kdf_params(&record.kdf, self.config.max_kdf_m_kib)?;
        let secrets =
            derive_account_secrets(password.expose_secret(), &sk, &local.account_id, &params)?;
        let (state, request) = OpaqueClientRegistration::start(&secrets.opk)?;
        let response = self
            .transport
            .call(
                None,
                &ReregisterStart {
                    token: token.clone(),
                    request: request.into(),
                },
            )
            .await?;
        let offered = OpaqueClientRegistration::response_server_key(response.response.as_slice())?;
        if server_fingerprint(&offered) != expected_fp {
            return Err(CoreError::ServerKey);
        }
        let opaque_record = register_finish(
            state,
            response.response.as_slice(),
            &local.origin,
            &local.account_id,
        )?;
        cancel.check()?;
        self.transport
            .call(
                None,
                &ReregisterFinish {
                    token,
                    record: opaque_record.into(),
                },
            )
            .await?;
        let device = DeviceInfo {
            device_id: local.device_id,
            platform: local.platform.clone(),
            label: None,
        };
        let subject = Subject {
            origin: &local.origin,
            account: local.account_id,
            kdf: &record.kdf,
        };
        let done = opaque_login(&self.transport, &cancel, &subject, &secrets.opk, device).await?;
        if done.server_fp != expected_fp {
            return Err(CoreError::ServerKey);
        }
        local.server_fp = expected_fp;
        let mut batch = Batch::new();
        let material = Material::create_existing(
            &self.platform,
            &self.config,
            &local,
            password.expose_secret(),
        )?;
        material.write(
            &mut batch,
            &mut local,
            &LocalSecrets {
                ak: &ak,
                sk: &sk,
                token: &done.token,
            },
        )?;
        Records::put_account(&mut batch, &local)?;
        self.cache.commit(&batch)?;
        self.failed_unlocks = 0;
        self.unlock_password(password, call).await
    }
}
