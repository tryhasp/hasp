use std::collections::VecDeque;

use opaque_ke::rand::Error as RngError;
use serde_json::Value;

use super::*;
use crate::testutil::{array, field, load, unhex};
use crate::to_hex;

struct ScriptRng {
    chunks: VecDeque<Vec<u8>>,
}

impl ScriptRng {
    fn new(chunks: Vec<Vec<u8>>) -> Self {
        Self {
            chunks: chunks.into(),
        }
    }
}

impl RngCore for ScriptRng {
    fn next_u32(&mut self) -> u32 {
        panic!("unexpected u32 draw")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("unexpected u64 draw")
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let chunk = self.chunks.pop_front().expect("unexpected draw");
        assert_eq!(chunk.len(), dest.len(), "draw size");
        dest.copy_from_slice(&chunk);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for ScriptRng {}

struct Rfc9807Case {
    name: String,
    fields: Value,
    context: Vec<u8>,
    client: Option<Vec<u8>>,
    server: Option<Vec<u8>>,
}

impl Rfc9807Case {
    fn new(case: &Value) -> Self {
        let optional = |name: &str| {
            case["fields"]
                .get(name)
                .map(|value| unhex(value.as_str().unwrap()))
        };
        Self {
            name: case["name"].as_str().unwrap().to_owned(),
            fields: case["fields"].clone(),
            context: unhex(case["config"]["Context"].as_str().unwrap()),
            client: optional("client_identity"),
            server: optional("server_identity"),
        }
    }

    fn bytes(&self, name: &str) -> Vec<u8> {
        field(&self.fields, name)
    }

    fn expect(&self, name: &str, actual: &[u8]) {
        assert_eq!(
            to_hex(actual),
            self.fields[name].as_str().unwrap(),
            "{} {name}",
            self.name
        );
    }

    fn ids(&self) -> Identifiers<'_> {
        Identifiers {
            client: self.client.as_deref(),
            server: self.server.as_deref(),
        }
    }

    fn blind(&self, name: &str) -> Vec<u8> {
        let mut wide = self.bytes(name);
        wide.resize(64, 0);
        wide
    }

    fn setup(&self) -> SuiteSetup {
        let mut bytes = self.bytes("oprf_seed");
        bytes.extend(self.bytes("server_private_key"));
        bytes.extend(self.bytes("server_public_key"));
        let setup = SuiteSetup::deserialize(&bytes).unwrap();
        self.expect("server_public_key", &setup.keypair().public().serialize());
        setup
    }

    fn register(&self, setup: &SuiteSetup, password: &[u8]) -> Vec<u8> {
        let mut rng = ScriptRng::new(vec![self.blind("blind_registration")]);
        let (state, request) = client_registration_start(&mut rng, password).unwrap();
        self.expect("registration_request", &request);
        let response = opaque_register_response(
            &OpaqueServerSetup(setup.clone(), Vec::new()),
            &request,
            &self.bytes("credential_identifier"),
        )
        .unwrap();
        self.expect("registration_response", &response);
        let mut rng = ScriptRng::new(vec![self.bytes("envelope_nonce")]);
        let record =
            client_registration_finish(state, &mut rng, password, &response, self.ids()).unwrap();
        self.expect("registration_upload", &record);
        record
    }

    fn login(&self, setup: &SuiteSetup, record: &[u8], password: &[u8]) {
        let mut rng = ScriptRng::new(vec![
            self.blind("blind_login"),
            self.bytes("client_keyshare_seed"),
            self.bytes("client_nonce"),
        ]);
        let (client, ke1) = client_login_start(&mut rng, password).unwrap();
        self.expect("KE1", &ke1);

        let mut rng = ScriptRng::new(vec![
            vec![0x5a; 64],
            self.bytes("masking_nonce"),
            self.bytes("server_keyshare_seed"),
            self.bytes("server_nonce"),
        ]);
        let input = ServerLoginInput {
            record: Some(record),
            ke1: &ke1,
            credential_id: &self.bytes("credential_identifier"),
            parameters: ServerLoginParameters {
                context: Some(&self.context),
                identifiers: self.ids(),
            },
        };
        let (server, ke2) = server_login_start(&mut rng, setup, &[], input).unwrap();
        self.expect("KE2", &ke2);

        let mut rng = ScriptRng::new(vec![]);
        let parameters = ClientLoginFinishParameters::new(Some(&self.context), self.ids(), None);
        let (ke3, client_key, _) =
            client_login_finish(client, &mut rng, password, &ke2, parameters).unwrap();
        self.expect("KE3", &ke3);
        self.expect("session_key", client_key.expose());

        let finalization = CredentialFinalization::<Suite>::deserialize(&ke3).unwrap();
        let server_key = server
            .finish(
                finalization,
                ServerLoginParameters {
                    context: Some(&self.context),
                    identifiers: self.ids(),
                },
            )
            .unwrap();
        self.expect("session_key", &server_key.session_key);
    }
}

fn password_key(seed: u8) -> SecretKey {
    SecretKey::from_bytes([seed; 32])
}

const ID_CLIENT: &[u8] = b"account-id";
const ID_SERVER: &[u8] = b"https://hasp.example";
const CONTEXT: &[u8] = b"login-context";
const CREDENTIAL: &[u8] = b"credential-id";

fn ids() -> OpaqueIdentities<'static> {
    OpaqueIdentities {
        client: ID_CLIENT,
        server: ID_SERVER,
    }
}

fn binding(credential_id: &'static [u8]) -> OpaqueLoginBinding<'static> {
    OpaqueLoginBinding {
        credential_id,
        context: CONTEXT,
        ids: ids(),
    }
}

fn setup() -> OpaqueServerSetup {
    OpaqueServerSetup::derive(&SecretKey::from_bytes([0x11; 32])).unwrap()
}

fn register(setup: &OpaqueServerSetup, password: &SecretKey) -> Vec<u8> {
    let (state, request) = OpaqueClientRegistration::start(password).unwrap();
    let response = opaque_register_response(setup, &request, CREDENTIAL).unwrap();
    state.finish(&response, &ids()).unwrap()
}

fn login(
    setup: &OpaqueServerSetup,
    record: Option<&[u8]>,
    password: &SecretKey,
    client_context: &[u8],
) -> Result<(OpaqueSessionKey, OpaqueSessionKey), CryptoError> {
    let (client, ke1) = OpaqueClientLogin::start(password)?;
    let (server, ke2) = opaque_login_start(setup, record, &ke1, &binding(CREDENTIAL))?;
    let (ke3, client_key) = client.finish(&ke2, client_context, &ids())?;
    let server_key = server.finish(&ke3)?;
    Ok((client_key, server_key))
}

#[test]
fn replays_rfc9807_ristretto255_real_vectors() {
    let vectors = load("opaque-rfc9807");
    let mut replayed = 0;
    for case in vectors["vectors"].as_array().unwrap() {
        let ours = case["kind"] == "real"
            && case["config"]["OPRF"] == "ristretto255-SHA512"
            && case["config"]["Group"] == "ristretto255";
        if !ours {
            continue;
        }
        let replay = Rfc9807Case::new(case);
        let password = replay.bytes("password");
        let setup = replay.setup();
        let record = replay.register(&setup, &password);
        replay.login(&setup, &record, &password);
        replayed += 1;
    }
    assert_eq!(replayed, 2);
}

#[test]
fn registration_and_login_agree_on_a_session_key() {
    let setup = setup();
    let password = password_key(1);
    let record = register(&setup, &password);
    let (client_key, server_key) = login(&setup, Some(&record), &password, CONTEXT).unwrap();
    assert_eq!(client_key.expose().len(), 64);
    assert_eq!(client_key.expose(), server_key.expose());
    let (other, _) = login(&setup, Some(&record), &password, CONTEXT).unwrap();
    assert_ne!(client_key.expose(), other.expose());
}

#[test]
fn rejects_wrong_password() {
    let setup = setup();
    let record = register(&setup, &password_key(1));
    assert!(matches!(
        login(&setup, Some(&record), &password_key(2), CONTEXT),
        Err(CryptoError::Opaque)
    ));
}

#[test]
fn rejects_context_and_identity_mismatch() {
    let setup = setup();
    let password = password_key(1);
    let record = register(&setup, &password);
    assert!(login(&setup, Some(&record), &password, b"other-context").is_err());

    let (client, ke1) = OpaqueClientLogin::start(&password).unwrap();
    let (_, ke2) = opaque_login_start(&setup, Some(&record), &ke1, &binding(CREDENTIAL)).unwrap();
    let wrong = OpaqueIdentities {
        client: ID_CLIENT,
        server: b"https://evil.example",
    };
    assert!(client.finish(&ke2, CONTEXT, &wrong).is_err());
}

#[test]
fn rejects_login_under_another_credential_identifier() {
    let setup = setup();
    let password = password_key(1);
    let record = register(&setup, &password);
    let (client, ke1) = OpaqueClientLogin::start(&password).unwrap();
    let (_, ke2) =
        opaque_login_start(&setup, Some(&record), &ke1, &binding(b"other-credential")).unwrap();
    assert!(client.finish(&ke2, CONTEXT, &ids()).is_err());
}

#[test]
fn unknown_account_gets_a_fake_response_of_equal_shape() {
    let setup = setup();
    let password = password_key(1);
    let record = register(&setup, &password);
    let (_, ke1) = OpaqueClientLogin::start(&password).unwrap();
    let (_, real) = opaque_login_start(&setup, Some(&record), &ke1, &binding(CREDENTIAL)).unwrap();
    let (_, fake) = opaque_login_start(&setup, None, &ke1, &binding(CREDENTIAL)).unwrap();
    assert_eq!(real.len(), fake.len());
    assert!(matches!(
        login(&setup, None, &password, CONTEXT),
        Err(CryptoError::Opaque)
    ));
}

#[test]
fn rejects_tampered_final_message() {
    let setup = setup();
    let password = password_key(1);
    let record = register(&setup, &password);
    let (client, ke1) = OpaqueClientLogin::start(&password).unwrap();
    let (server, ke2) =
        opaque_login_start(&setup, Some(&record), &ke1, &binding(CREDENTIAL)).unwrap();
    let (mut ke3, _) = client.finish(&ke2, CONTEXT, &ids()).unwrap();
    ke3[0] ^= 1;
    assert!(matches!(server.finish(&ke3), Err(CryptoError::Opaque)));
}

#[test]
fn rejects_malformed_messages() {
    let setup = setup();
    assert!(opaque_register_response(&setup, &[0; 5], CREDENTIAL).is_err());
    assert!(opaque_login_start(&setup, None, &[0; 5], &binding(CREDENTIAL)).is_err());
    assert!(opaque_check_record(&[0; 5]).is_err());
    let password = password_key(1);
    let (registration, request) = OpaqueClientRegistration::start(&password).unwrap();
    assert!(registration.finish(&[1; 7], &ids()).is_err());
    let record = register(&setup, &password);
    opaque_check_record(&record).unwrap();
    let (_, ke1) = OpaqueClientLogin::start(&password).unwrap();
    assert!(opaque_login_start(&setup, Some(&record[1..]), &ke1, &binding(CREDENTIAL)).is_err());
    let (login, _) = OpaqueClientLogin::start(&password).unwrap();
    assert!(login.finish(&request, CONTEXT, &ids()).is_err());
}

#[test]
fn response_exposes_the_server_key_for_pinning() {
    let setup = setup();
    let (_, request) = OpaqueClientRegistration::start(&password_key(1)).unwrap();
    let response = opaque_register_response(&setup, &request, CREDENTIAL).unwrap();
    assert_eq!(
        OpaqueClientRegistration::response_server_key(&response).unwrap(),
        setup.public_key()
    );
    assert!(OpaqueClientRegistration::response_server_key(&response[1..]).is_err());
}

#[test]
fn server_setup_derivation_is_deterministic_and_pinned() {
    let pinned = load("opaque-server-setup");
    let case = &pinned["cases"][0];
    let master = SecretKey::from_bytes(array(case["server_master"].as_str().unwrap()));
    let first = OpaqueServerSetup::derive(&master).unwrap();
    let second = OpaqueServerSetup::derive(&master).unwrap();
    assert_eq!(first.0.serialize(), second.0.serialize());
    assert_eq!(
        to_hex(&first.public_key()),
        case["public_key"].as_str().unwrap()
    );
    assert_eq!(
        to_hex(&first.0.serialize()),
        case["serialized_setup"].as_str().unwrap()
    );
    let other = OpaqueServerSetup::derive(&SecretKey::from_bytes([0x12; 32])).unwrap();
    assert_ne!(first.public_key(), other.public_key());
}

#[test]
fn server_oprf_seed_is_the_labelled_expansion() {
    let master = SecretKey::from_bytes([0x33; 32]);
    let setup = OpaqueServerSetup::derive(&master).unwrap();
    let prk = Prk::from_secret(SecretKey::from_bytes([0x33; 32]));
    let expected = stream(&prk, OPRF_LABEL).unwrap();
    assert_eq!(
        setup.0.serialize().get(..64).unwrap(),
        expected.get(..64).unwrap()
    );
}

#[test]
fn debug_output_is_redacted() {
    let setup = setup();
    let password = password_key(1);
    let (registration, _) = OpaqueClientRegistration::start(&password).unwrap();
    let (client, _) = OpaqueClientLogin::start(&password).unwrap();
    assert_eq!(format!("{setup:?}"), "OpaqueServerSetup(..)");
    assert_eq!(format!("{registration:?}"), "OpaqueClientRegistration(..)");
    assert_eq!(format!("{client:?}"), "OpaqueClientLogin(..)");
    let record = register(&setup, &password);
    let (client, ke1) = OpaqueClientLogin::start(&password).unwrap();
    let (server, ke2) =
        opaque_login_start(&setup, Some(&record), &ke1, &binding(CREDENTIAL)).unwrap();
    assert_eq!(format!("{server:?}"), "OpaqueServerLogin(..)");
    let (_, client_key) = client.finish(&ke2, CONTEXT, &ids()).unwrap();
    assert_eq!(format!("{client_key:?}"), "OpaqueSessionKey(..)");
}

#[test]
fn login_finish_returns_the_authenticated_server_key() {
    let setup = setup();
    let password = password_key(1);
    let record = register(&setup, &password);
    let (client, ke1) = OpaqueClientLogin::start(&password).unwrap();
    let (server, ke2) =
        opaque_login_start(&setup, Some(&record), &ke1, &binding(CREDENTIAL)).unwrap();
    let (ke3, client_key, server_key) = client
        .finish_with_server_key(&ke2, CONTEXT, &ids())
        .unwrap();
    assert_eq!(server_key, setup.public_key());
    assert_eq!(server.finish(&ke3).unwrap().expose(), client_key.expose());
}

#[test]
fn os_rng_fills_from_the_system_source() {
    let mut rng = OsRng::new();
    let words32 = [rng.next_u32(), rng.next_u32(), rng.next_u32()];
    let words64 = [rng.next_u64(), rng.next_u64(), rng.next_u64()];
    assert!(words32.iter().any(|word| *word > 1));
    assert!(words64.iter().any(|word| *word > 1));
    let mut filled = [0_u8; 32];
    rng.fill_bytes(&mut filled);
    assert_ne!(filled, [0; 32]);
    let mut tried = [0_u8; 32];
    rng.try_fill_bytes(&mut tried).unwrap();
    assert_ne!(tried, [0; 32]);
    assert!(!rng.failed);
    assert_ne!(filled, tried);
}

#[test]
fn stream_rng_serves_bytes_in_order_and_reports_exhaustion() {
    let bytes: Vec<u8> = (2..=40).collect();
    let mut rng = StreamRng::new(Zeroizing::new(bytes));
    assert_eq!(rng.next_u32(), u32::from_le_bytes([2, 3, 4, 5]));
    assert_eq!(
        rng.next_u64(),
        u64::from_le_bytes([6, 7, 8, 9, 10, 11, 12, 13])
    );
    let mut filled = [0_u8; 3];
    rng.fill_bytes(&mut filled);
    assert_eq!(filled, [14, 15, 16]);
    let mut tried = [0_u8; 3];
    rng.try_fill_bytes(&mut tried).unwrap();
    assert_eq!(tried, [17, 18, 19]);
    assert_eq!(rng.offset, 18);
    assert!(!rng.exhausted);
    let mut rest = [0_u8; 21];
    rng.try_fill_bytes(&mut rest).unwrap();
    assert_eq!(rest.first(), Some(&20));
    assert_eq!(rest.last(), Some(&40));
    let mut over = [7_u8; 1];
    assert!(rng.try_fill_bytes(&mut over).is_err());
    assert_eq!(over, [0]);
    assert!(rng.exhausted);
}

#[test]
fn server_streams_are_the_labelled_hkdf_expansion() {
    let prk = Prk::from_secret(SecretKey::from_bytes([0x44; 32]));
    let label = "hasp/v1/srv/oprf";
    let mut info = vec![0x81, 0x60 + 16];
    info.extend_from_slice(label.as_bytes());
    let expected = hkdf_expand(&prk, &info, SERVER_STREAM_LEN).unwrap();
    let actual = stream(&prk, label).unwrap();
    assert_eq!(actual.len(), SERVER_STREAM_LEN);
    assert_eq!(actual.as_slice(), expected.expose());
    assert_ne!(
        stream(&prk, AKE_LABEL).unwrap().as_slice(),
        actual.as_slice()
    );
}
