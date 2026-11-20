use hasp_crypto::{OpaqueClientLogin, OpaqueClientRegistration, OpaqueIdentities, SecretKey};
use hasp_proto::wire::{
    DeviceInfo, ErrorCode, LoginFinish, LoginStart, OpaquePurpose, ReauthFinish, ReauthStart,
    ServerKey, SessionToken, opaque_context, session_token,
};
use hasp_proto::{AccountId, KdfWire};

use crate::CoreError;
use crate::session::Cancel;
use crate::sync::server_code;
use crate::transport::Transport;

pub(crate) struct LoginOutcome {
    pub token: SessionToken,
    pub server_fp: [u8; 15],
}

impl std::fmt::Debug for LoginOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LoginOutcome(..)")
    }
}

pub(crate) struct Subject<'a> {
    pub origin: &'a str,
    pub account: AccountId,
    pub kdf: &'a KdfWire,
}

pub(crate) fn ids<'a>(origin: &'a str, account: &'a AccountId) -> OpaqueIdentities<'a> {
    OpaqueIdentities {
        client: account.as_bytes(),
        server: origin.as_bytes(),
    }
}

pub(crate) fn uniform(error: CoreError) -> CoreError {
    match server_code(&error) {
        Some(ErrorCode::Auth) => CoreError::Credentials,
        _ => error,
    }
}

pub(crate) async fn opaque_login<T: Transport>(
    transport: &T,
    cancel: &Cancel,
    subject: &Subject<'_>,
    opk: &SecretKey,
    device: DeviceInfo,
) -> Result<LoginOutcome, CoreError> {
    cancel.check()?;
    let (state, ke1) = OpaqueClientLogin::start(opk)?;
    let start = transport
        .call(
            None,
            &LoginStart {
                account_id: subject.account,
                ke1: ke1.into(),
            },
        )
        .await
        .map_err(CoreError::from)
        .map_err(uniform)?;
    cancel.check()?;
    let context = opaque_context(OpaquePurpose::Login, &subject.account, subject.kdf)?;
    let (ke3, key, server_key) = state
        .finish_with_server_key(
            start.ke2.as_slice(),
            &context,
            &ids(subject.origin, &subject.account),
        )
        .map_err(|_| CoreError::Credentials)?;
    let done = transport
        .call(
            None,
            &LoginFinish {
                handle: start.handle,
                ke3: ke3.into(),
                device,
            },
        )
        .await
        .map_err(CoreError::from)
        .map_err(uniform)?;
    cancel.check()?;
    Ok(LoginOutcome {
        token: session_token(key.expose(), &done.session_id)?,
        server_fp: server_fingerprint(&server_key),
    })
}

pub(crate) async fn opaque_reauth<T: Transport>(
    transport: &T,
    cancel: &Cancel,
    token: &SessionToken,
    subject: &Subject<'_>,
    opk: &SecretKey,
) -> Result<(), CoreError> {
    cancel.check()?;
    let (state, ke1) = OpaqueClientLogin::start(opk)?;
    let start = transport
        .call(Some(token), &ReauthStart { ke1: ke1.into() })
        .await
        .map_err(CoreError::from)
        .map_err(uniform)?;
    let context = opaque_context(OpaquePurpose::Reauth, &subject.account, subject.kdf)?;
    let (ke3, _key) = state
        .finish(
            start.ke2.as_slice(),
            &context,
            &ids(subject.origin, &subject.account),
        )
        .map_err(|_| CoreError::Credentials)?;
    transport
        .call(
            Some(token),
            &ReauthFinish {
                handle: start.handle,
                ke3: ke3.into(),
            },
        )
        .await
        .map_err(CoreError::from)
        .map_err(uniform)?;
    cancel.check()?;
    Ok(())
}

pub(crate) fn register_finish(
    state: OpaqueClientRegistration,
    response: &[u8],
    origin: &str,
    account: &AccountId,
) -> Result<Vec<u8>, CoreError> {
    state
        .finish(response, &ids(origin, account))
        .map_err(|_| CoreError::Credentials)
}

pub(crate) fn server_fingerprint(server_key: &[u8; 32]) -> [u8; 15] {
    let digest = hasp_crypto::sha256(&[server_key]);
    let mut out = [0_u8; 15];
    out.copy_from_slice(digest.get(..15).unwrap_or(&[0; 15]));
    out
}

pub(crate) async fn check_server_key<T: Transport>(
    transport: &T,
    cancel: &Cancel,
    origin: &str,
    expected: &[u8; 15],
) -> Result<(), CoreError> {
    cancel.check()?;
    let reply = transport.call(None, &ServerKey {}).await?;
    cancel.check()?;
    let key: [u8; 32] = reply
        .public_key
        .0
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::ServerKey)?;
    if reply.origin != origin || server_fingerprint(&key) != *expected {
        return Err(CoreError::ServerKey);
    }
    Ok(())
}
