#![expect(
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "tests assert by unwrapping"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hasp_core::CoreError;
use hasp_core::api::{
    CredentialIdentity, CxfImportRequest, Engine, EngineConfig, FillPolicy, IdentityKind,
    ItemDraft, LockState, OsAssertionRequest, OsRegistrationRequest, ProviderPasskeyQuery,
    ProviderQuery, SearchQuery, Secret, TextQuery, UrlDraft, UserVerification,
};
use hasp_core::client::SignUp;
use hasp_core::platform::{ManualClock, MemorySecureStore, Platform, ScriptedBiometric};
use hasp_core::store::MemoryStore as ClientStore;
use hasp_core::testing::fixture;
use hasp_core::transport::{Transport, TransportError};
use hasp_crypto::{sha256, verify_es256};
use hasp_proto::base64url;
use hasp_proto::wire::{Operation, SessionToken};
use hasp_server::MemoryStore;
use hasp_testsupport::{InProcess, TEST_ORIGIN, World, block_on};
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

const PASSWORD: &str = "a long provider test password";
const HASH: &str = "mS3k4o5sJ6cRkN3JrF9pQ7mZqk3a9tTQxA2kqj1R0eY";
const HANDLE: &str = "dXNlci0x";

#[derive(Debug)]
struct Counting {
    inner: InProcess<MemoryStore>,
    calls: Arc<AtomicUsize>,
}

impl Transport for Counting {
    fn call<O: Operation + Sync>(
        &self,
        token: Option<&SessionToken>,
        request: &O,
    ) -> impl Future<Output = Result<O::Response, TransportError>> + Send {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.call(token, request)
    }
}

type TestEngine = Engine<Counting, ClientStore>;

struct Rig {
    engine: TestEngine,
    calls: Arc<AtomicUsize>,
    biometric: Arc<ScriptedBiometric>,
    vault: String,
}

fn run<F: Future<Output = ()> + Send + 'static>(future: F) {
    std::thread::Builder::new()
        .stack_size(32 << 20)
        .spawn(move || block_on(Box::pin(future)))
        .unwrap()
        .join()
        .unwrap();
}

async fn new_rig(world: &World) -> Rig {
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
    let calls = Arc::new(AtomicUsize::new(0));
    let biometric = Arc::new(ScriptedBiometric::new(true, true));
    let platform = Platform {
        secure: Arc::new(MemorySecureStore::new(true)),
        biometric: biometric.clone(),
        clock: Arc::new(ManualClock::new(1_000_000)),
    };
    let engine = Engine::new(
        Counting {
            inner: world.transport(),
            calls: Arc::clone(&calls),
        },
        ClientStore::new(),
        platform,
        EngineConfig::new("ios"),
    )
    .unwrap();
    Box::pin(engine.sign_in_with_kit_qr(
        &kit.qr_blob().unwrap(),
        Secret::new(PASSWORD.as_bytes().to_vec()),
    ))
    .await
    .unwrap();
    let vault = engine.vaults().await.unwrap().remove(0).id;
    Rig {
        engine,
        calls,
        biometric,
        vault,
    }
}

fn login(engine: &TestEngine, title: &str, url: &str, user: &str, pass: &str) -> ItemDraft {
    let mut draft = engine.blank_draft("login").unwrap();
    for field in draft.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        match field.purpose.as_deref() {
            Some("username") => field.value = Secret::new(user.as_bytes().to_vec()),
            Some("password") => field.value = Secret::new(pass.as_bytes().to_vec()),
            _ => {}
        }
    }
    title.clone_into(&mut draft.title);
    draft.urls.push(UrlDraft {
        id: None,
        url: url.to_owned(),
        mode: "domain".to_owned(),
        kind: "sign-in".to_owned(),
    });
    draft
}

fn blank(engine: &TestEngine, kind: &str) -> ItemDraft {
    let mut draft = engine.blank_draft(kind).unwrap();
    for field in draft.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        if field.kind == "address" {
            field.value = Secret::new(b"{}".to_vec());
        }
    }
    draft
}

fn set_purpose(draft: &mut ItemDraft, purpose: &str, value: &str) {
    for field in draft.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        if field.purpose.as_deref() == Some(purpose) {
            field.value = Secret::new(value.as_bytes().to_vec());
        }
    }
}

async fn publish_and_relock(rig: &Rig) {
    rig.engine.sync().await.unwrap();
    rig.engine.lock().await;
    rig.calls.store(0, Ordering::Relaxed);
    rig.engine.provider_unlock().await.unwrap();
}

fn registration(rp: &str, user: &str, handle: &str) -> OsRegistrationRequest {
    OsRegistrationRequest {
        rp_id: rp.to_owned(),
        rp_name: "Example".to_owned(),
        client_data_hash: HASH.to_owned(),
        user_name: user.to_owned(),
        user_display_name: user.to_owned(),
        user_handle: handle.to_owned(),
        algorithms: vec![-7, -257],
        exclude: Vec::new(),
        user_verification: UserVerification::Preferred,
        user_verified: false,
        vault: None,
        item: None,
    }
}

fn assertion(rp: &str) -> OsAssertionRequest {
    OsAssertionRequest {
        rp_id: rp.to_owned(),
        client_data_hash: HASH.to_owned(),
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

fn kinds(identities: &[CredentialIdentity], kind: IdentityKind) -> Vec<&CredentialIdentity> {
    identities.iter().filter(|i| i.kind == kind).collect()
}

#[test]
fn the_provider_unlocks_with_the_device_key_and_never_calls_the_server() {
    run(async {
        let world = World::new();
        let rig = new_rig(&world).await;
        rig.engine.lock().await;
        rig.biometric.set_approve(false);
        assert!(rig.engine.provider_unlock().await.is_err());
        assert_eq!(rig.engine.status().await.unwrap().state, LockState::Locked);
        rig.biometric.set_approve(true);
        rig.calls.store(0, Ordering::Relaxed);
        rig.engine.provider_unlock().await.unwrap();
        assert_eq!(
            rig.engine.status().await.unwrap().state,
            LockState::Unlocked
        );
        let listed = rig
            .engine
            .provider_candidates(ProviderQuery {
                identifiers: Vec::new(),
                limit: 0,
            })
            .await
            .unwrap();
        assert!(listed.is_empty());
        assert_eq!(rig.calls.load(Ordering::Relaxed), 0);
    });
}

#[test]
fn identities_cover_passwords_codes_and_passkeys_and_diff_after_changes() {
    run(async {
        let world = World::new();
        let rig = new_rig(&world).await;
        let engine = &rig.engine;
        let mut github = login(engine, "GitHub", "https://github.com/login", "alice", "pw1");
        set_purpose(
            &mut github,
            "totp",
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP",
        );
        let github = engine.create_item(&rig.vault, github).await.unwrap();
        engine
            .create_item(
                &rig.vault,
                login(engine, "Example", "https://example.com", "bob", "pw2"),
            )
            .await
            .unwrap();
        publish_and_relock(&rig).await;
        engine
            .provider_passkey_register(registration("passkeys.example", "carol", HANDLE))
            .await
            .unwrap();

        let diff = engine.identity_diff().await.unwrap();
        assert!(diff.changed);
        let passwords = kinds(&diff.identities, IdentityKind::Password);
        let codes = kinds(&diff.identities, IdentityKind::OneTimeCode);
        let passkeys = kinds(&diff.identities, IdentityKind::Passkey);
        assert_eq!(passwords.len(), 2);
        assert_eq!(codes.len(), 1);
        assert_eq!(passkeys.len(), 1);
        assert_eq!(
            passwords
                .iter()
                .find(|i| i.service == "github.com")
                .unwrap()
                .user,
            "alice"
        );
        assert_eq!(codes[0].service, "github.com");
        assert_eq!(passkeys[0].service, "passkeys.example");
        assert_eq!(passkeys[0].user, "carol");
        assert_eq!(passkeys[0].user_handle.as_deref(), Some(HANDLE));
        assert!(passkeys[0].credential_id.is_some());
        assert_eq!(diff.added.len(), 4);
        engine.identity_ack(&diff.fingerprint).await.unwrap();

        let same = engine.identity_diff().await.unwrap();
        assert!(!same.changed && same.identities.is_empty());
        assert_eq!(same.fingerprint, diff.fingerprint);
        assert!(matches!(
            engine.identity_ack("00").await,
            Err(CoreError::Conflict(_))
        ));

        engine
            .set_favourite(&rig.vault, &github.item, true)
            .await
            .unwrap();
        let favourite = engine.identity_diff().await.unwrap();
        assert!(favourite.changed);
        assert_eq!(favourite.updated.len(), 2);
        assert!(favourite.added.is_empty() && favourite.removed.is_empty());
        engine.identity_ack(&favourite.fingerprint).await.unwrap();

        engine.delete_item(&rig.vault, &github.item).await.unwrap();
        let removed = engine.identity_diff().await.unwrap();
        assert_eq!(removed.removed.len(), 2);
        assert_eq!(removed.identities.len(), 2);
    });
}

#[test]
fn candidates_and_lists_read_the_index_and_open_no_item() {
    run(async {
        let world = World::new();
        let rig = new_rig(&world).await;
        let engine = &rig.engine;
        for n in 0..30 {
            engine
                .create_item(
                    &rig.vault,
                    login(
                        engine,
                        &format!("Site {n}"),
                        &format!("https://site{n}.example/login"),
                        "user",
                        "secret",
                    ),
                )
                .await
                .unwrap();
        }
        engine
            .create_item(
                &rig.vault,
                login(engine, "Mail", "https://mail.example.com", "me", "pw"),
            )
            .await
            .unwrap();
        publish_and_relock(&rig).await;
        engine.provider_index_refresh().await.unwrap();
        let before = engine.items_opened_for_tests().await;
        let hits = engine
            .provider_candidates(ProviderQuery {
                identifiers: vec!["login.mail.example.com".to_owned()],
                limit: 5,
            })
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].title, "Mail");
        assert_eq!(hits[0].subtitle, "me");
        let none = engine
            .provider_candidates(ProviderQuery {
                identifiers: vec!["unknown.test".to_owned()],
                limit: 5,
            })
            .await
            .unwrap();
        assert!(none.is_empty());
        let rows = engine
            .provider_list(SearchQuery {
                text: "site 1".to_owned(),
                vault: None,
                kind: None,
                tag: None,
                favourites_only: false,
                status: None,
                boost_url: None,
                limit: 3,
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(engine.items_opened_for_tests().await, before);
        assert_eq!(rig.calls.load(Ordering::Relaxed), 0);
    });
}

#[test]
fn a_password_fill_opens_one_item_and_checks_the_service() {
    run(async {
        let world = World::new();
        let rig = new_rig(&world).await;
        let engine = &rig.engine;
        let mine = engine
            .create_item(
                &rig.vault,
                login(engine, "Example", "https://example.com", "bob", "pw-bob"),
            )
            .await
            .unwrap();
        for n in 0..20 {
            engine
                .create_item(
                    &rig.vault,
                    login(
                        engine,
                        &format!("Other {n}"),
                        "https://other.test",
                        "x",
                        "y",
                    ),
                )
                .await
                .unwrap();
        }
        publish_and_relock(&rig).await;
        engine.provider_index_refresh().await.unwrap();
        refused(
            &engine
                .provider_password(
                    &rig.vault,
                    &mine.item,
                    Some("www.example.com".to_owned()),
                    false,
                    false,
                )
                .await,
        );
        let before = engine.items_opened_for_tests().await;
        let credential = engine
            .provider_password(
                &rig.vault,
                &mine.item,
                Some("www.example.com".to_owned()),
                false,
                true,
            )
            .await
            .unwrap();
        assert_eq!(credential.user, "bob");
        assert_eq!(credential.password.as_bytes(), b"pw-bob");
        assert_eq!(credential.host, "www.example.com");
        assert_eq!(engine.items_opened_for_tests().await - before, 1);
        refused(
            &engine
                .provider_password(
                    &rig.vault,
                    &mine.item,
                    Some("evil.test".to_owned()),
                    false,
                    false,
                )
                .await,
        );
        refused(
            &engine
                .provider_password(&rig.vault, &mine.item, None, false, false)
                .await,
        );
        let without = engine
            .provider_password(&rig.vault, &mine.item, None, true, false)
            .await
            .unwrap();
        assert_eq!(without.password.as_bytes(), b"pw-bob");
    });
}

fn parse_attested(auth_data: &[u8]) -> (u8, Vec<u8>, Vec<u8>) {
    assert_eq!(auth_data.get(33..37).unwrap(), [0; 4], "counter stays 0");
    let flags = auth_data[32];
    let length = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
    let id = auth_data[55..55 + length].to_vec();
    let cose = &auth_data[55 + length..];
    let mut sec1 = vec![4];
    sec1.extend_from_slice(&cose[10..42]);
    sec1.extend_from_slice(&cose[45..77]);
    (flags, id, sec1)
}

#[test]
fn the_os_passkey_paths_register_and_sign_over_the_client_data_hash() {
    run(async {
        let world = World::new();
        let rig = new_rig(&world).await;
        publish_and_relock(&rig).await;
        let engine = &rig.engine;
        let created = engine
            .provider_passkey_register(registration("example.com", "alice@example.com", HANDLE))
            .await
            .unwrap();
        let auth_data = base64url::decode(&created.authenticator_data).unwrap();
        assert_eq!(&auth_data[..32], sha256(&[b"example.com"]));
        let (flags, credential_id, sec1) = parse_attested(&auth_data);
        assert_eq!(flags & 0x40, 0x40);
        assert_eq!(flags & 0x19, 0x19);
        assert_eq!(flags & 0x04, 0, "no UV without verification");
        assert_eq!(base64url::encode(&credential_id), created.credential_id);
        let object = base64url::decode(&created.attestation_object).unwrap();
        assert!(object.starts_with(&[0xa3, 0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e']));
        assert!(object.ends_with(&auth_data));
        assert_eq!(
            base64url::decode(&created.public_key)
                .unwrap()
                .get(26..)
                .unwrap(),
            sec1.as_slice()
        );

        let listed = engine
            .provider_passkeys(ProviderPasskeyQuery {
                rp_id: "Example.com".to_owned(),
                allow: Vec::new(),
            })
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].user_name, "alice@example.com");

        let signed = engine
            .provider_passkey_assert(assertion("example.com"))
            .await
            .unwrap();
        let assertion_data = base64url::decode(&signed.authenticator_data).unwrap();
        assert_eq!(assertion_data.len(), 37);
        assert_eq!(assertion_data[32] & 0x40, 0);
        let mut message = assertion_data.clone();
        message.extend_from_slice(&base64url::decode(HASH).unwrap());
        verify_es256(
            &sec1,
            &message,
            &base64url::decode(&signed.signature).unwrap(),
        )
        .unwrap();
        assert_eq!(signed.user_handle, HANDLE);
        assert_eq!(signed.credential_id, created.credential_id);
        let mut tampered = message.clone();
        tampered[40] ^= 1;
        assert!(
            verify_es256(
                &sec1,
                &tampered,
                &base64url::decode(&signed.signature).unwrap()
            )
            .is_err()
        );

        let again = engine
            .provider_passkeys(ProviderPasskeyQuery {
                rp_id: "example.com".to_owned(),
                allow: Vec::new(),
            })
            .await
            .unwrap();
        assert_eq!(again[0].last_used, Some(1_000_000));

        let mut excluded = registration("example.com", "alice@example.com", "b3RoZXI");
        excluded.exclude = vec![created.credential_id.clone()];
        assert!(matches!(
            engine.provider_passkey_register(excluded).await,
            Err(CoreError::Conflict(_))
        ));

        let replaced = engine
            .provider_passkey_register(registration("example.com", "alice@example.com", HANDLE))
            .await
            .unwrap();
        assert_eq!(replaced.item, created.item);
        let current = engine
            .provider_passkeys(ProviderPasskeyQuery {
                rp_id: "example.com".to_owned(),
                allow: Vec::new(),
            })
            .await
            .unwrap();
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].credential_id, replaced.credential_id);

        engine
            .provider_passkey_register(registration("example.com", "second", "c2Vjb25k"))
            .await
            .unwrap();
        refused(
            &engine
                .provider_passkey_assert(assertion("example.com"))
                .await,
        );
        let mut picked = assertion("example.com");
        picked.credential_id = Some(replaced.credential_id.clone());
        assert_eq!(
            engine
                .provider_passkey_assert(picked)
                .await
                .unwrap()
                .credential_id,
            replaced.credential_id
        );
        assert!(matches!(
            engine
                .provider_passkey_assert(assertion("nothing.test"))
                .await,
            Err(CoreError::NotFound(_))
        ));
    });
}

#[test]
fn the_os_passkey_paths_refuse_bad_input() {
    run(async {
        let world = World::new();
        let rig = new_rig(&world).await;
        publish_and_relock(&rig).await;
        let engine = &rig.engine;
        refused(
            &engine
                .provider_passkey_register(registration("co.uk", "u", HANDLE))
                .await,
        );
        refused(
            &engine
                .provider_passkey_register(registration("192.0.2.1", "u", HANDLE))
                .await,
        );
        refused(
            &engine
                .provider_passkey_register(registration("exa mple.com", "u", HANDLE))
                .await,
        );
        let mut short = registration("example.com", "u", HANDLE);
        short.client_data_hash = "AAAA".to_owned();
        refused(&engine.provider_passkey_register(short).await);
        let mut rsa = registration("example.com", "u", HANDLE);
        rsa.algorithms = vec![-257];
        refused(&engine.provider_passkey_register(rsa).await);
        let mut required = registration("example.com", "u", HANDLE);
        required.user_verification = UserVerification::Required;
        refused(&engine.provider_passkey_register(required.clone()).await);
        required.user_verified = true;
        let created = engine.provider_passkey_register(required).await.unwrap();
        let flags = base64url::decode(&created.authenticator_data).unwrap()[32];
        assert_eq!(flags & 0x04, 0x04);
        let mut needs_uv = assertion("example.com");
        needs_uv.user_verification = UserVerification::Required;
        refused(&engine.provider_passkey_assert(needs_uv).await);
        let mut short_hash = assertion("example.com");
        short_hash.client_data_hash = "AAAA".to_owned();
        refused(&engine.provider_passkey_assert(short_hash).await);
        engine.lock().await;
        assert!(matches!(
            engine
                .provider_passkey_assert(assertion("example.com"))
                .await,
            Err(CoreError::Locked)
        ));
    });
}

#[test]
fn text_to_insert_offers_identity_and_card_details_but_never_secrets() {
    run(async {
        let world = World::new();
        let rig = new_rig(&world).await;
        let engine = &rig.engine;
        let mut identity = blank(engine, "identity");
        identity.title = "Me".to_owned();
        set_purpose(&mut identity, "given-name", "Alice");
        set_purpose(&mut identity, "email", "alice@example.com");
        let identity = engine.create_item(&rig.vault, identity).await.unwrap();
        let mut card = blank(engine, "credit-card");
        card.title = "Visa".to_owned();
        set_purpose(&mut card, "card-holder", "Alice Kim");
        set_purpose(&mut card, "card-number", "4111111111111111");
        set_purpose(&mut card, "card-cvc", "123");
        let card = engine.create_item(&rig.vault, card).await.unwrap();
        let account = engine
            .create_item(
                &rig.vault,
                login(engine, "Mail", "https://mail.test", "alice", "hunter2"),
            )
            .await
            .unwrap();
        let note = blank(engine, "secure-note");
        engine.create_item(&rig.vault, note).await.unwrap();
        publish_and_relock(&rig).await;

        let all = engine
            .text_candidates(TextQuery {
                text: String::new(),
                limit: 0,
            })
            .await
            .unwrap();
        let purposes: Vec<&str> = all.iter().filter_map(|c| c.purpose.as_deref()).collect();
        for banned in ["password", "card-cvc", "totp", "new-password"] {
            assert!(!purposes.contains(&banned), "{banned} must not be offered");
        }
        assert!(purposes.contains(&"email") && purposes.contains(&"card-holder"));
        let number = all
            .iter()
            .find(|c| c.purpose.as_deref() == Some("card-number"))
            .unwrap();
        assert!(number.concealed);
        assert!(number.preview.ends_with("1111") && !number.preview.contains("4111"));
        let user = all.iter().find(|c| c.item == account.item).unwrap();
        assert_eq!(user.purpose.as_deref(), Some("username"));
        assert_eq!(user.preview, "alice");

        let email = all
            .iter()
            .find(|c| c.purpose.as_deref() == Some("email"))
            .unwrap();
        assert_eq!(
            engine
                .text_value(&email.vault, &email.item, &email.field)
                .await
                .unwrap()
                .as_bytes(),
            b"alice@example.com"
        );
        assert_eq!(
            engine
                .text_value(&number.vault, &number.item, &number.field)
                .await
                .unwrap()
                .as_bytes(),
            b"4111111111111111"
        );
        assert_eq!(
            engine
                .text_value(&rig.vault, &account.item, "username")
                .await
                .unwrap()
                .as_bytes(),
            b"alice"
        );
        let detail = engine.item_detail(&rig.vault, &card.item).await.unwrap();
        let cvc = detail
            .sections
            .iter()
            .flat_map(|s| &s.fields)
            .find(|f| f.purpose.as_deref() == Some("card-cvc"))
            .unwrap();
        refused(&engine.text_value(&rig.vault, &card.item, &cvc.id).await);
        let login_detail = engine.item_detail(&rig.vault, &account.item).await.unwrap();
        let password = login_detail
            .sections
            .iter()
            .flat_map(|s| &s.fields)
            .find(|f| f.purpose.as_deref() == Some("password"))
            .unwrap();
        refused(
            &engine
                .text_value(&rig.vault, &account.item, &password.id)
                .await,
        );
        refused(&engine.text_value(&rig.vault, &identity.item, "zz").await);

        let filtered = engine
            .text_candidates(TextQuery {
                text: "visa".to_owned(),
                limit: 0,
            })
            .await
            .unwrap();
        assert!(filtered.iter().all(|c| c.item == card.item));
    });
}

#[test]
fn cxf_import_dedupes_reports_and_round_trips_through_an_export() {
    run(async {
        let world = World::new();
        let rig = new_rig(&world).await;
        let engine = &rig.engine;
        let existing = login(
            engine,
            "GitHub Login",
            "https://github.com",
            "johndoe",
            "old",
        );
        engine.create_item(&rig.vault, existing).await.unwrap();
        publish_and_relock(&rig).await;

        let data = fixture("cxf-spec-appendix-a.json");
        let preview = engine
            .cxf_import(CxfImportRequest {
                data: Secret::new(data.clone()),
                dry_run: true,
            })
            .await
            .unwrap();
        assert!(preview.dry_run && preview.report_id.is_none());
        assert_eq!(preview.duplicates, 1);
        assert_eq!(preview.imported, 13);
        assert_eq!(preview.passkeys, 1);
        assert!(preview.with_loss >= 1);
        assert_eq!(engine.provider_index_refresh().await.unwrap(), 1);

        let done = engine
            .cxf_import(CxfImportRequest {
                data: Secret::new(data.clone()),
                dry_run: false,
            })
            .await
            .unwrap();
        assert_eq!((done.imported, done.duplicates), (13, 1));
        assert!(
            done.report_id
                .as_deref()
                .is_some_and(|id| id.starts_with("cxf-"))
        );
        assert!(done.report.contains("\"source\": \"cxf\""));
        let passkeys = engine
            .provider_passkeys(ProviderPasskeyQuery {
                rp_id: "webauthn.io".to_owned(),
                allow: Vec::new(),
            })
            .await
            .unwrap();
        assert_eq!(passkeys.len(), 1);
        assert_eq!(engine.provider_index_refresh().await.unwrap(), 14);

        let again = engine
            .cxf_import(CxfImportRequest {
                data: Secret::new(data),
                dry_run: false,
            })
            .await
            .unwrap();
        assert_eq!((again.imported, again.unchanged), (0, 14));
        assert_eq!(engine.provider_index_refresh().await.unwrap(), 14);

        let exported = engine.cxf_export_for_tests().await.unwrap();
        let other_world = World::new();
        let second = new_rig(&other_world).await;
        let round = second
            .engine
            .cxf_import(CxfImportRequest {
                data: Secret::new(exported.into_bytes()),
                dry_run: false,
            })
            .await
            .unwrap();
        assert_eq!(round.imported, 14);
        assert_eq!(round.passkeys, 1);
        let moved = second
            .engine
            .provider_passkeys(ProviderPasskeyQuery {
                rp_id: "webauthn.io".to_owned(),
                allow: Vec::new(),
            })
            .await
            .unwrap();
        assert_eq!(moved[0].credential_id, passkeys[0].credential_id);
        let password = second
            .engine
            .provider_password(
                &second.vault,
                &hits_of(&second, "GitHub Login").await,
                None,
                true,
                false,
            )
            .await
            .unwrap();
        assert_eq!(password.user, "johndoe");
    });
}

async fn hits_of(rig: &Rig, title: &str) -> String {
    rig.engine
        .provider_list(SearchQuery {
            text: title.to_owned(),
            vault: None,
            kind: None,
            tag: None,
            favourites_only: false,
            status: None,
            boost_url: None,
            limit: 1,
        })
        .await
        .unwrap()
        .remove(0)
        .id
}

#[test]
fn a_cxf_import_merges_new_passkeys_into_an_existing_login() {
    run(async {
        let world = World::new();
        let rig = new_rig(&world).await;
        let engine = &rig.engine;
        engine
            .create_item(
                &rig.vault,
                login(
                    engine,
                    "WebAuthn.io",
                    "https://webauthn.io",
                    "johndoe",
                    "pw",
                ),
            )
            .await
            .unwrap();
        let data = fixture("cxf-spec-appendix-a.json");
        let done = engine
            .cxf_import(CxfImportRequest {
                data: Secret::new(data),
                dry_run: false,
            })
            .await
            .unwrap();
        assert_eq!(done.merged_passkeys, 1);
        assert_eq!(done.duplicates, 0);
        let keys = engine
            .provider_passkeys(ProviderPasskeyQuery {
                rp_id: "webauthn.io".to_owned(),
                allow: Vec::new(),
            })
            .await
            .unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].title, "WebAuthn.io");
    });
}

#[test]
fn a_sync_commits_more_pending_items_than_one_commit_holds() {
    run(async {
        let world = World::new();
        let rig = new_rig(&world).await;
        let engine = &rig.engine;
        for n in 0..520 {
            engine
                .create_item(
                    &rig.vault,
                    login(
                        engine,
                        &format!("Bulk {n}"),
                        &format!("https://bulk{n}.test"),
                        "u",
                        "p",
                    ),
                )
                .await
                .unwrap();
        }
        publish_and_relock(&rig).await;
        assert_eq!(engine.provider_index_refresh().await.unwrap(), 520);
        let before = engine.items_opened_for_tests().await;
        assert_eq!(engine.provider_index_refresh().await.unwrap(), 520);
        assert_eq!(
            engine.items_opened_for_tests().await,
            before,
            "every item is committed, none is pending"
        );
    });
}

#[test]
fn a_cxf_batch_merges_a_passkey_into_the_first_same_login_item_instead_of_dropping_it() {
    run(async {
        let world = World::new();
        let rig = new_rig(&world).await;
        let engine = &rig.engine;
        let mut document: serde_json::Value =
            serde_json::from_slice(&fixture("cxf-spec-appendix-a.json")).unwrap();
        let items = document["accounts"][0]["items"].as_array_mut().unwrap();
        let mut twin = items
            .iter()
            .find(|item| item["title"] == "WebAuthn.io")
            .unwrap()
            .clone();
        twin["id"] = serde_json::json!("password-only-twin");
        twin["scope"] = serde_json::json!({"urls": ["https://webauthn.io"]});
        twin["credentials"] = serde_json::json!([{
            "type": "basic-auth",
            "username": {"value": "johndoe", "fieldType": "string"},
            "password": {"value": "pw", "fieldType": "concealed-string"}
        }]);
        items.insert(0, twin);
        let data = serde_json::to_vec(&document).unwrap();
        let preview = engine
            .cxf_import(CxfImportRequest {
                data: Secret::new(data.clone()),
                dry_run: true,
            })
            .await
            .unwrap();
        assert_eq!(preview.merged_passkeys, 1);
        let done = engine
            .cxf_import(CxfImportRequest {
                data: Secret::new(data),
                dry_run: false,
            })
            .await
            .unwrap();
        assert_eq!(done.merged_passkeys, 1);
        let keys = engine
            .provider_passkeys(ProviderPasskeyQuery {
                rp_id: "webauthn.io".to_owned(),
                allow: Vec::new(),
            })
            .await
            .unwrap();
        assert_eq!(keys.len(), 1, "the passkey of the second item is kept");
        assert_eq!(done.imported + done.merged_passkeys + done.duplicates, 15);
    });
}

#[test]
fn a_provider_fill_honours_confirm_first_never_and_the_item_kind() {
    run(async {
        let world = World::new();
        let rig = new_rig(&world).await;
        let engine = &rig.engine;
        let site = engine
            .create_item(
                &rig.vault,
                login(engine, "Site", "https://login.example.com", "bob", "pw-bob"),
            )
            .await
            .unwrap();
        let mut note = engine.blank_draft("secure-note").unwrap();
        note.title = "Note".to_owned();
        let note = engine.create_item(&rig.vault, note).await.unwrap();
        publish_and_relock(&rig).await;
        let vault = &rig.vault;

        let exact = engine
            .provider_fill_check(
                vault,
                &site.item,
                Some("login.example.com".to_owned()),
                false,
            )
            .await
            .unwrap();
        assert_eq!(exact.fill, FillPolicy::OneClick);

        let sibling = engine
            .provider_fill_check(
                vault,
                &site.item,
                Some("evil.example.com".to_owned()),
                false,
            )
            .await;
        match sibling {
            Ok(check) => {
                assert_eq!(check.fill, FillPolicy::ConfirmFirst);
                refused(
                    &engine
                        .provider_password(
                            vault,
                            &site.item,
                            Some("evil.example.com".to_owned()),
                            false,
                            false,
                        )
                        .await,
                );
                engine
                    .provider_password(
                        vault,
                        &site.item,
                        Some("evil.example.com".to_owned()),
                        false,
                        true,
                    )
                    .await
                    .unwrap();
            }
            Err(error) => refused::<()>(&Err(error)),
        }

        let unrelated = engine
            .provider_fill_check(vault, &site.item, Some("evil.test".to_owned()), true)
            .await
            .unwrap();
        assert_eq!(unrelated.fill, FillPolicy::ConfirmFirst);
        assert_eq!(unrelated.host, "evil.test");
        refused(
            &engine
                .provider_password(vault, &site.item, Some("evil.test".to_owned()), true, false)
                .await,
        );
        engine
            .provider_password(vault, &site.item, Some("evil.test".to_owned()), true, true)
            .await
            .unwrap();

        refused(
            &engine
                .provider_password(
                    vault,
                    &note.item,
                    Some("note.example.com".to_owned()),
                    true,
                    true,
                )
                .await,
        );
        refused(
            &engine
                .provider_fill_check(vault, &note.item, None, true)
                .await,
        );
    });
}

#[test]
fn a_custom_identity_text_field_is_offered_only_masked() {
    run(async {
        let world = World::new();
        let rig = new_rig(&world).await;
        let engine = &rig.engine;
        let mut identity = blank(engine, "identity");
        identity.title = "Me".to_owned();
        identity.sections[0]
            .fields
            .push(hasp_core::api::FieldDraft {
                id: None,
                label: "Passport number".to_owned(),
                kind: "text".to_owned(),
                purpose: None,
                concealed: false,
                expires_alert: false,
                value: Secret::new(b"M12345678".to_vec()),
                keep_value: false,
            });
        engine.create_item(&rig.vault, identity).await.unwrap();
        publish_and_relock(&rig).await;
        let all = engine
            .text_candidates(TextQuery {
                text: String::new(),
                limit: 0,
            })
            .await
            .unwrap();
        let passport = all.iter().find(|c| c.label == "Passport number").unwrap();
        assert!(passport.concealed);
        assert!(!passport.preview.contains("M1234"), "{}", passport.preview);
    });
}
