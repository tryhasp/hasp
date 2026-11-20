#![expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]

#[path = "support/relying_party.rs"]
mod relying_party;

use std::sync::Arc;

use hasp_core::CoreError;
use hasp_core::api::{
    Engine, EngineConfig, FrameContext, PasskeyAssertion, PasskeyCreateRequest, PasskeyCreated,
    PasskeyGetRequest, PasskeyQuery, Secret, UserVerification,
};
use hasp_core::client::SignUp;
use hasp_core::platform::{ManualClock, Platform};
use hasp_core::store::MemoryStore as ClientStore;
use hasp_proto::base64url;
use hasp_server::MemoryStore;
use hasp_testsupport::{InProcess, TEST_ORIGIN, World, block_on};
use relying_party::{Rejected, RelyingParty};
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

type TestEngine = Engine<InProcess<MemoryStore>, ClientStore>;

const PASSWORD: &str = "a long passkey test password";
const CHALLENGE: &str = "dGhpcyBpcyBhIGNoYWxsZW5nZSE";
const OTHER_CHALLENGE: &str = "YW5vdGhlciBjaGFsbGVuZ2Uh";
const USER_HANDLE: &str = "dXNlci0x";

fn run<F: Future<Output = ()> + Send + 'static>(future: F) {
    std::thread::Builder::new()
        .stack_size(32 << 20)
        .spawn(move || block_on(Box::pin(future)))
        .unwrap()
        .join()
        .unwrap();
}

async fn engine(world: &World) -> TestEngine {
    let mut creator = world.device(true);
    let token = world.server.issue_bootstrap_token().unwrap().to_text();
    let kit = Box::pin(creator.client.sign_up(
        &SignUp {
            origin: TEST_ORIGIN,
            token: &token,
            login: "alice",
            password: &SecretString::from(PASSWORD),
        },
        &CancellationToken::new(),
    ))
    .await
    .unwrap();
    let engine = Engine::new(
        world.transport(),
        ClientStore::new(),
        Platform::for_tests(Arc::new(ManualClock::new(1_000_000))),
        EngineConfig::new("macos"),
    )
    .unwrap();
    Box::pin(engine.sign_in_with_kit_qr(
        &kit.qr_blob().unwrap(),
        Secret::new(PASSWORD.as_bytes().to_vec()),
    ))
    .await
    .unwrap();
    engine
}

fn top_frame() -> FrameContext {
    FrameContext {
        top_frame: true,
        cross_origin_frame: false,
        sandboxed: false,
        obscured: false,
        visibility_check_supported: true,
    }
}

fn create_request(origin: &str, rp_id: Option<&str>) -> PasskeyCreateRequest {
    PasskeyCreateRequest {
        origin: origin.to_owned(),
        frame: top_frame(),
        rp_id: rp_id.map(str::to_owned),
        rp_name: "Example".to_owned(),
        challenge: CHALLENGE.to_owned(),
        user_handle: USER_HANDLE.to_owned(),
        user_name: "alice@example.com".to_owned(),
        user_display_name: "Alice".to_owned(),
        algorithms: vec![-7, -257],
        exclude: Vec::new(),
        user_verification: UserVerification::Preferred,
        user_verified: false,
        vault: None,
        item: None,
    }
}

fn get_request(origin: &str, rp_id: Option<&str>) -> PasskeyGetRequest {
    PasskeyGetRequest {
        origin: origin.to_owned(),
        frame: top_frame(),
        rp_id: rp_id.map(str::to_owned),
        challenge: CHALLENGE.to_owned(),
        allow: Vec::new(),
        user_verification: UserVerification::Preferred,
        user_verified: false,
        vault: None,
        item: None,
        credential_id: None,
    }
}

fn refused<T: std::fmt::Debug>(result: &Result<T, CoreError>) {
    assert!(
        matches!(result, Err(CoreError::Refused(_))),
        "expected a refusal, got {result:?}"
    );
}

fn register(rp: &RelyingParty, created: &PasskeyCreated) -> relying_party::Registered {
    rp.register(
        CHALLENGE,
        &created.client_data_json,
        &created.attestation_object,
    )
    .unwrap()
}

fn authenticate(
    rp: &RelyingParty,
    public: &[u8],
    challenge: &str,
    assertion: &PasskeyAssertion,
) -> Result<relying_party::Authenticated, Rejected> {
    rp.authenticate(
        public,
        0,
        challenge,
        &assertion.client_data_json,
        &assertion.authenticator_data,
        &assertion.signature,
    )
}

#[test]
fn a_relying_party_verifies_registration_and_assertions() {
    run(async {
        let world = World::new();
        let engine = engine(&world).await;
        let rp = RelyingParty::new("example.com", "https://login.example.com");
        let created = engine
            .passkey_create(create_request(
                "https://login.example.com",
                Some("example.com"),
            ))
            .await
            .unwrap();
        let registered = register(&rp, &created);
        assert_eq!(registered.counter, 0);
        assert_eq!(registered.flags & 0x04, 0, "no UV without verification");
        assert_eq!(
            registered.flags & 0x18,
            0x18,
            "synced: backup eligible and backed up"
        );
        assert_eq!(
            base64url::decode(&created.credential_id).unwrap(),
            registered.credential_id
        );
        assert_eq!(created.public_key_algorithm, -7);
        let spki = base64url::decode(&created.public_key).unwrap();
        assert_eq!(spki.get(26..).unwrap(), registered.public_sec1.as_slice());

        let assertion = engine
            .passkey_get(get_request(
                "https://login.example.com",
                Some("example.com"),
            ))
            .await
            .unwrap();
        let outcome = authenticate(&rp, &registered.public_sec1, CHALLENGE, &assertion).unwrap();
        assert_eq!(outcome.counter, 0);
        assert_eq!(assertion.credential_id, created.credential_id);
        assert_eq!(assertion.user_handle, USER_HANDLE);

        assert_eq!(
            authenticate(&rp, &registered.public_sec1, OTHER_CHALLENGE, &assertion),
            Err(Rejected::ClientData("challenge"))
        );
        let hostile = RelyingParty::new("example.com", "https://evil.example.com");
        assert_eq!(
            authenticate(&hostile, &registered.public_sec1, CHALLENGE, &assertion),
            Err(Rejected::ClientData("origin"))
        );
        let elsewhere = RelyingParty::new("example.org", "https://login.example.com");
        assert_eq!(
            authenticate(&elsewhere, &registered.public_sec1, CHALLENGE, &assertion),
            Err(Rejected::AuthData("rpIdHash"))
        );
        let other_key = hasp_crypto::Es256Key::generate().unwrap().public_sec1();
        assert_eq!(
            authenticate(&rp, &other_key, CHALLENGE, &assertion),
            Err(Rejected::Signature)
        );
    });
}

#[test]
fn the_user_verified_flag_follows_what_actually_happened() {
    run(async {
        let world = World::new();
        let engine = engine(&world).await;
        let rp = RelyingParty::new("example.com", "https://example.com");
        let mut request = create_request("https://example.com", None);
        request.user_verification = UserVerification::Required;
        refused(&engine.passkey_create(request.clone()).await);
        request.user_verified = true;
        let created = engine.passkey_create(request).await.unwrap();
        assert_eq!(register(&rp, &created).flags & 0x04, 0x04);

        let mut get = get_request("https://example.com", None);
        get.user_verification = UserVerification::Required;
        refused(&engine.passkey_get(get.clone()).await);
        get.user_verified = true;
        let assertion = engine.passkey_get(get).await.unwrap();
        let public = register(&rp, &created).public_sec1;
        assert_eq!(
            authenticate(&rp, &public, CHALLENGE, &assertion)
                .unwrap()
                .flags
                & 0x04,
            0x04
        );
        let unverified = engine
            .passkey_get(get_request("https://example.com", None))
            .await
            .unwrap();
        assert_eq!(
            authenticate(&rp, &public, CHALLENGE, &unverified)
                .unwrap()
                .flags
                & 0x04,
            0
        );
    });
}

#[test]
fn origin_and_rp_id_rules_hold_for_create_and_get() {
    run(async {
        let world = World::new();
        let engine = engine(&world).await;
        refused(
            &engine
                .passkey_create(create_request("https://example.co.uk", Some("co.uk")))
                .await,
        );
        refused(
            &engine
                .passkey_create(create_request("https://example.com", Some("evil.com")))
                .await,
        );
        refused(
            &engine
                .passkey_create(create_request("https://alice.github.io", Some("github.io")))
                .await,
        );
        refused(
            &engine
                .passkey_create(create_request("http://example.com", None))
                .await,
        );
        refused(
            &engine
                .passkey_create(create_request("https://192.0.2.1", None))
                .await,
        );
        let mut sandboxed = create_request("https://example.com", None);
        sandboxed.frame.sandboxed = true;
        refused(&engine.passkey_create(sandboxed).await);
        let mut framed = create_request("https://example.com", None);
        framed.frame.cross_origin_frame = true;
        refused(&engine.passkey_create(framed).await);
        let mut no_es256 = create_request("https://example.com", None);
        no_es256.algorithms = vec![-257, -8];
        refused(&engine.passkey_create(no_es256).await);
        let mut bad_handle = create_request("https://example.com", None);
        bad_handle.user_handle = String::new();
        refused(&engine.passkey_create(bad_handle).await);
        let mut bad_challenge = create_request("https://example.com", None);
        bad_challenge.challenge = "not base64!".to_owned();
        refused(&engine.passkey_create(bad_challenge).await);
        assert!(
            engine
                .items(&engine.vaults().await.unwrap()[0].id)
                .await
                .unwrap()
                .is_empty()
        );

        engine
            .passkey_create(create_request(
                "https://login.example.com",
                Some("example.com"),
            ))
            .await
            .unwrap();
        refused(
            &engine
                .passkey_get(get_request("https://evil.example.org", Some("example.com")))
                .await,
        );
        refused(
            &engine
                .passkey_get(get_request("https://login.example.com", Some("com")))
                .await,
        );
        assert!(matches!(
            engine
                .passkey_get(get_request("https://other.example.net", None))
                .await,
            Err(CoreError::NotFound(_))
        ));
        let sibling = engine
            .passkey_get(get_request("https://app.example.com", Some("example.com")))
            .await
            .unwrap();
        assert_eq!(sibling.rp_id, "example.com");
    });
}

#[test]
fn the_credential_lives_in_an_item_and_the_private_key_never_leaves() {
    run(async {
        let world = World::new();
        let engine = engine(&world).await;
        let vault = engine.vaults().await.unwrap().remove(0).id;
        let created = engine
            .passkey_create(create_request("https://example.com", None))
            .await
            .unwrap();
        assert_eq!(created.vault, vault);
        let detail = engine
            .item_detail(&created.vault, &created.item)
            .await
            .unwrap();
        assert_eq!(detail.passkeys, 1);
        assert!(detail.row.has_passkey);
        assert_eq!(detail.row.title, "Example");
        assert_eq!(detail.urls[0].url, "https://example.com");
        let shown = format!("{detail:?}");
        assert!(!shown.contains("PRIVATE"));
        let candidates = engine
            .passkey_candidates(PasskeyQuery {
                origin: "https://example.com".to_owned(),
                frame: top_frame(),
                rp_id: None,
                allow: Vec::new(),
            })
            .await
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].credential_id, created.credential_id);
        assert_eq!(candidates[0].user_name, "alice@example.com");
        assert_eq!(candidates[0].last_used, None);

        engine.lock().await;
        engine
            .unlock_password(Secret::new(PASSWORD.as_bytes().to_vec()))
            .await
            .unwrap();
        let rp = RelyingParty::new("example.com", "https://example.com");
        let assertion = engine
            .passkey_get(get_request("https://example.com", None))
            .await
            .unwrap();
        let candidates = engine
            .passkey_candidates(PasskeyQuery {
                origin: "https://example.com".to_owned(),
                frame: top_frame(),
                rp_id: None,
                allow: Vec::new(),
            })
            .await
            .unwrap();
        assert!(candidates[0].last_used.is_some());
        let public = {
            let spki = base64url::decode(&created.public_key).unwrap();
            spki.get(26..).unwrap().to_vec()
        };
        authenticate(&rp, &public, CHALLENGE, &assertion).unwrap();
    });
}

#[test]
fn exclusion_replacement_and_selection() {
    run(async {
        let world = World::new();
        let engine = engine(&world).await;
        let first = engine
            .passkey_create(create_request("https://example.com", None))
            .await
            .unwrap();
        let mut excluded = create_request("https://example.com", None);
        excluded.exclude = vec![first.credential_id.clone()];
        assert!(matches!(
            engine.passkey_create(excluded).await,
            Err(CoreError::Conflict(_))
        ));

        let replacement = engine
            .passkey_create(create_request("https://example.com", None))
            .await
            .unwrap();
        assert_eq!(replacement.item, first.item);
        assert_ne!(replacement.credential_id, first.credential_id);
        let detail = engine.item_detail(&first.vault, &first.item).await.unwrap();
        assert_eq!(detail.passkeys, 1);
        assert!(matches!(
            engine
                .passkey_get(PasskeyGetRequest {
                    allow: vec![first.credential_id.clone()],
                    ..get_request("https://example.com", None)
                })
                .await,
            Err(CoreError::NotFound(_))
        ));

        let mut second_user = create_request("https://example.com", None);
        second_user.user_handle = "dXNlci0y".to_owned();
        second_user.user_name = "bob@example.com".to_owned();
        let second = engine.passkey_create(second_user).await.unwrap();
        assert_ne!(second.item, first.item);
        refused(
            &engine
                .passkey_get(get_request("https://example.com", None))
                .await,
        );
        let chosen = engine
            .passkey_get(PasskeyGetRequest {
                credential_id: Some(second.credential_id.clone()),
                ..get_request("https://example.com", None)
            })
            .await
            .unwrap();
        assert_eq!(chosen.item, second.item);
        let allowed = engine
            .passkey_get(PasskeyGetRequest {
                allow: vec![replacement.credential_id.clone()],
                ..get_request("https://example.com", None)
            })
            .await
            .unwrap();
        assert_eq!(allowed.item, first.item);
    });
}

#[test]
fn a_passkey_can_be_added_to_an_existing_login() {
    run(async {
        let world = World::new();
        let engine = engine(&world).await;
        let vault = engine.vaults().await.unwrap().remove(0).id;
        let mut draft = engine.blank_draft("login").unwrap();
        "Existing".clone_into(&mut draft.title);
        let item = engine.create_item(&vault, draft).await.unwrap();
        let mut request = create_request("https://example.com", None);
        request.vault = Some(vault.clone());
        request.item = Some(item.item.clone());
        let created = engine.passkey_create(request).await.unwrap();
        assert_eq!(created.item, item.item);
        let detail = engine.item_detail(&vault, &item.item).await.unwrap();
        assert_eq!(detail.passkeys, 1);
        assert_eq!(detail.row.title, "Existing");
        assert_eq!(engine.items(&vault).await.unwrap().len(), 1);
    });
}
