use std::fmt;

use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse, RegistrationUpload,
    Ristretto255, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup, TripleDh,
    ksf::Identity,
    rand::{CryptoRng, RngCore},
};
use sha2_legacy::Sha512;
use zeroize::{Zeroize, Zeroizing};

use crate::{CryptoError, Prk, SecretBytes, SecretKey, hkdf_expand};

const OPRF_LABEL: &str = "hasp/v1/srv/oprf";
const AKE_LABEL: &str = "hasp/v1/srv/ake";
const SERVER_STREAM_LEN: usize = 256;
const SERVER_PUBLIC_KEY_LEN: usize = 32;

#[derive(Debug)]
struct Suite;

impl CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Identity;
}

type SuiteSetup = ServerSetup<Suite>;

#[derive(Clone, Copy, Debug)]
pub struct OpaqueIdentities<'a> {
    pub client: &'a [u8],
    pub server: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
pub struct OpaqueLoginBinding<'a> {
    pub credential_id: &'a [u8],
    pub context: &'a [u8],
    pub ids: OpaqueIdentities<'a>,
}

pub struct OpaqueSessionKey(SecretBytes);

pub struct OpaqueClientRegistration {
    state: ClientRegistration<Suite>,
    password: SecretKey,
}

pub struct OpaqueClientLogin {
    state: ClientLogin<Suite>,
    password: SecretKey,
}

const DECOY_RECORD_LEN: usize = 192;

pub struct OpaqueServerSetup(SuiteSetup, Vec<u8>);

pub struct OpaqueServerLogin {
    state: ServerLogin<Suite>,
    context: Vec<u8>,
    client: Vec<u8>,
    server: Vec<u8>,
}
impl OpaqueSessionKey {
    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }
}

impl fmt::Debug for OpaqueSessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpaqueSessionKey(..)")
    }
}

impl OpaqueClientRegistration {
    pub fn start(password_input: &SecretKey) -> Result<(Self, Vec<u8>), CryptoError> {
        let mut rng = OsRng::new();
        let result = client_registration_start(&mut rng, password_input.expose());
        rng.checked(result).map(|(state, request)| {
            (
                Self {
                    state,
                    password: SecretKey::duplicate(password_input),
                },
                request,
            )
        })
    }

    pub fn finish(
        self,
        response: &[u8],
        ids: &OpaqueIdentities<'_>,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut rng = OsRng::new();
        let result = client_registration_finish(
            self.state,
            &mut rng,
            self.password.expose(),
            response,
            identifiers(ids),
        );
        rng.checked(result)
    }

    pub fn response_server_key(
        response: &[u8],
    ) -> Result<[u8; SERVER_PUBLIC_KEY_LEN], CryptoError> {
        let parsed = RegistrationResponse::<Suite>::deserialize(response)
            .map_err(|_| CryptoError::Opaque)?;
        to_server_key(&parsed.serialize())
    }
}

impl fmt::Debug for OpaqueClientRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpaqueClientRegistration(..)")
    }
}

impl OpaqueClientLogin {
    pub fn start(password_input: &SecretKey) -> Result<(Self, Vec<u8>), CryptoError> {
        let mut rng = OsRng::new();
        let result = client_login_start(&mut rng, password_input.expose());
        rng.checked(result).map(|(state, ke1)| {
            (
                Self {
                    state,
                    password: SecretKey::duplicate(password_input),
                },
                ke1,
            )
        })
    }

    pub fn finish(
        self,
        ke2: &[u8],
        context: &[u8],
        ids: &OpaqueIdentities<'_>,
    ) -> Result<(Vec<u8>, OpaqueSessionKey), CryptoError> {
        self.finish_with_server_key(ke2, context, ids)
            .map(|(ke3, key, _)| (ke3, key))
    }

    /// Like `finish`, and also returns the server public key the handshake authenticated, for
    /// the pin check.
    pub fn finish_with_server_key(
        self,
        ke2: &[u8],
        context: &[u8],
        ids: &OpaqueIdentities<'_>,
    ) -> Result<(Vec<u8>, OpaqueSessionKey, [u8; SERVER_PUBLIC_KEY_LEN]), CryptoError> {
        let mut rng = OsRng::new();
        let result = client_login_finish(
            self.state,
            &mut rng,
            self.password.expose(),
            ke2,
            ClientLoginFinishParameters::new(Some(context), identifiers(ids), None),
        );
        rng.checked(result)
    }
}

impl fmt::Debug for OpaqueClientLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpaqueClientLogin(..)")
    }
}

impl OpaqueServerSetup {
    /// The `oprf_seed` and AKE key pair come from labelled HKDF streams of `server_master`.
    pub fn derive(server_master: &SecretKey) -> Result<Self, CryptoError> {
        let prk = Prk::from_secret(SecretKey::duplicate(server_master));
        let mut ake_rng = StreamRng::new(stream(&prk, AKE_LABEL)?);
        let ake_setup = SuiteSetup::new(&mut ake_rng);
        let key_pair = ake_setup.keypair().clone();
        let mut oprf_rng = StreamRng::new(stream(&prk, OPRF_LABEL)?);
        let setup = SuiteSetup::new_with_key_pair(&mut oprf_rng, key_pair);
        if ake_rng.exhausted || oprf_rng.exhausted {
            return Err(CryptoError::Internal("server setup stream"));
        }
        let mut decoy = Vec::with_capacity(DECOY_RECORD_LEN);
        decoy.extend_from_slice(&setup.keypair().public().serialize());
        decoy.resize(DECOY_RECORD_LEN, 0);
        Ok(Self(setup, decoy))
    }

    pub fn public_key(&self) -> [u8; SERVER_PUBLIC_KEY_LEN] {
        let mut key = [0_u8; SERVER_PUBLIC_KEY_LEN];
        key.iter_mut()
            .zip(self.0.keypair().public().serialize().iter())
            .for_each(|(slot, byte)| *slot = *byte);
        key
    }
}

impl fmt::Debug for OpaqueServerSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpaqueServerSetup(..)")
    }
}

impl OpaqueServerLogin {
    pub fn finish(self, ke3: &[u8]) -> Result<OpaqueSessionKey, CryptoError> {
        let parameters = ServerLoginParameters {
            context: Some(&self.context),
            identifiers: Identifiers {
                client: Some(&self.client),
                server: Some(&self.server),
            },
        };
        let message =
            CredentialFinalization::<Suite>::deserialize(ke3).map_err(|_| CryptoError::Opaque)?;
        let result = self
            .state
            .finish(message, parameters)
            .map_err(|_| CryptoError::Opaque)?;
        Ok(OpaqueSessionKey(secret_from_output(result.session_key)))
    }
}

impl fmt::Debug for OpaqueServerLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpaqueServerLogin(..)")
    }
}

pub fn opaque_register_response(
    setup: &OpaqueServerSetup,
    request: &[u8],
    credential_id: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let message =
        RegistrationRequest::<Suite>::deserialize(request).map_err(|_| CryptoError::Opaque)?;
    ServerRegistration::start(&setup.0, message, credential_id)
        .map(|result| result.message.serialize().to_vec())
        .map_err(|_| CryptoError::Opaque)
}

pub fn opaque_check_record(record: &[u8]) -> Result<(), CryptoError> {
    RegistrationUpload::<Suite>::deserialize(record)
        .map(drop)
        .map_err(|_| CryptoError::Opaque)
}

pub fn opaque_login_start(
    setup: &OpaqueServerSetup,
    record: Option<&[u8]>,
    ke1: &[u8],
    binding: &OpaqueLoginBinding<'_>,
) -> Result<(OpaqueServerLogin, Vec<u8>), CryptoError> {
    let mut rng = OsRng::new();
    let input = ServerLoginInput {
        record,
        ke1,
        credential_id: binding.credential_id,
        parameters: ServerLoginParameters {
            context: Some(binding.context),
            identifiers: identifiers(&binding.ids),
        },
    };
    let result = server_login_start(&mut rng, &setup.0, &setup.1, input);
    rng.checked(result).map(|(state, ke2)| {
        (
            OpaqueServerLogin {
                state,
                context: binding.context.to_vec(),
                client: binding.ids.client.to_vec(),
                server: binding.ids.server.to_vec(),
            },
            ke2,
        )
    })
}

fn client_registration_start<R: RngCore + CryptoRng>(
    rng: &mut R,
    password: &[u8],
) -> Result<(ClientRegistration<Suite>, Vec<u8>), CryptoError> {
    let result =
        ClientRegistration::<Suite>::start(rng, password).map_err(|_| CryptoError::Opaque)?;
    Ok((result.state, result.message.serialize().to_vec()))
}

fn client_registration_finish<R: RngCore + CryptoRng>(
    state: ClientRegistration<Suite>,
    rng: &mut R,
    password: &[u8],
    response: &[u8],
    ids: Identifiers<'_>,
) -> Result<Vec<u8>, CryptoError> {
    let response =
        RegistrationResponse::<Suite>::deserialize(response).map_err(|_| CryptoError::Opaque)?;
    let result = state
        .finish(
            rng,
            password,
            response,
            ClientRegistrationFinishParameters::new(ids, None),
        )
        .map_err(|_| CryptoError::Opaque)?;
    Ok(result.message.serialize().to_vec())
}

fn client_login_start<R: RngCore + CryptoRng>(
    rng: &mut R,
    password: &[u8],
) -> Result<(ClientLogin<Suite>, Vec<u8>), CryptoError> {
    let result = ClientLogin::<Suite>::start(rng, password).map_err(|_| CryptoError::Opaque)?;
    Ok((result.state, result.message.serialize().to_vec()))
}

fn client_login_finish<R: RngCore + CryptoRng>(
    state: ClientLogin<Suite>,
    rng: &mut R,
    password: &[u8],
    ke2: &[u8],
    parameters: ClientLoginFinishParameters<'_, '_, '_, Suite>,
) -> Result<(Vec<u8>, OpaqueSessionKey, [u8; SERVER_PUBLIC_KEY_LEN]), CryptoError> {
    let response =
        CredentialResponse::<Suite>::deserialize(ke2).map_err(|_| CryptoError::Opaque)?;
    let result = state
        .finish(rng, password, response, parameters)
        .map_err(|_| CryptoError::Opaque)?;
    let server_key = to_server_key(&result.server_s_pk.serialize())?;
    Ok((
        result.message.serialize().to_vec(),
        OpaqueSessionKey(secret_from_output(result.session_key)),
        server_key,
    ))
}

struct ServerLoginInput<'a> {
    record: Option<&'a [u8]>,
    ke1: &'a [u8],
    credential_id: &'a [u8],
    parameters: ServerLoginParameters<'a, 'a>,
}

fn server_login_start<R: RngCore + CryptoRng>(
    rng: &mut R,
    setup: &SuiteSetup,
    decoy: &[u8],
    input: ServerLoginInput<'_>,
) -> Result<(ServerLogin<Suite>, Vec<u8>), CryptoError> {
    let request =
        CredentialRequest::<Suite>::deserialize(input.ke1).map_err(|_| CryptoError::Opaque)?;
    let registration = input
        .record
        .map(ServerRegistration::<Suite>::deserialize)
        .transpose()
        .map_err(|_| CryptoError::Opaque)?;
    if registration.is_none() {
        std::hint::black_box(ServerRegistration::<Suite>::deserialize(decoy).is_ok());
    }
    let result = ServerLogin::start(
        rng,
        setup,
        registration,
        request,
        input.credential_id,
        input.parameters,
    )
    .map_err(|_| CryptoError::Opaque)?;
    Ok((result.state, result.message.serialize().to_vec()))
}

fn identifiers<'a>(ids: &OpaqueIdentities<'a>) -> Identifiers<'a> {
    Identifiers {
        client: Some(ids.client),
        server: Some(ids.server),
    }
}

fn secret_from_output(
    mut output: opaque_ke::generic_array::GenericArray<u8, opaque_ke::generic_array::typenum::U64>,
) -> SecretBytes {
    let mut bytes = Vec::with_capacity(output.len());
    bytes.extend_from_slice(&output);
    output.zeroize();
    SecretBytes::from_vec(bytes)
}

fn to_server_key(serialized: &[u8]) -> Result<[u8; SERVER_PUBLIC_KEY_LEN], CryptoError> {
    let start = serialized
        .len()
        .checked_sub(SERVER_PUBLIC_KEY_LEN)
        .ok_or(CryptoError::Opaque)?;
    let tail = serialized.get(start..).ok_or(CryptoError::Opaque)?;
    let mut key = [0_u8; SERVER_PUBLIC_KEY_LEN];
    key.copy_from_slice(tail);
    Ok(key)
}

fn stream(prk: &Prk, label: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut info = Vec::with_capacity(label.len().saturating_add(2));
    // Why: X(k, name) expands over cbor(["hasp/v1/<name>"]), a one-element array of a short text (protocol 3.2).
    info.push(0x81);
    info.push(0x60_u8.saturating_add(u8::try_from(label.len()).map_err(|_| CryptoError::Length)?));
    info.extend_from_slice(label.as_bytes());
    let expanded = hkdf_expand(prk, &info, SERVER_STREAM_LEN)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(SERVER_STREAM_LEN));
    bytes.extend_from_slice(expanded.expose());
    Ok(bytes)
}

mod rng;
#[cfg(test)]
mod tests;

use rng::{OsRng, StreamRng};
