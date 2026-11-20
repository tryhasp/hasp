#![expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]

use std::sync::Arc;

use hasp_core::CoreError;
use hasp_core::api::{
    Engine, EngineConfig, LockState, Secret, SignInRequest, SignUpRequest, UnlockMode,
};
use hasp_core::platform::{ManualClock, Platform};
use hasp_core::store::MemoryStore as ClientStore;
use hasp_server::MemoryStore;
use hasp_testsupport::{InProcess, TEST_ORIGIN, World, block_on};

type TestEngine = Engine<InProcess<MemoryStore>, ClientStore>;

const PASSWORD: &str = "a long account test password";

fn run<F: Future<Output = ()> + Send + 'static>(future: F) {
    std::thread::Builder::new()
        .stack_size(32 << 20)
        .spawn(move || block_on(Box::pin(future)))
        .unwrap()
        .join()
        .unwrap();
}

fn fresh(world: &World, hardware: bool) -> TestEngine {
    let clock = Arc::new(ManualClock::new(1_000_000));
    let platform = if hardware {
        Platform::for_tests(clock)
    } else {
        Platform::password_only_for_tests(clock)
    };
    Engine::new(
        world.transport(),
        ClientStore::new(),
        platform,
        EngineConfig::new(if hardware { "macos" } else { "chrome" }),
    )
    .unwrap()
}

fn fingerprint(world: &World) -> String {
    hasp_proto::format_fingerprint(&world.fingerprint())
}

fn secret(text: &str) -> Secret {
    Secret::new(text.as_bytes().to_vec())
}

fn sign_up_request(code: &str, fingerprint: String) -> SignUpRequest {
    SignUpRequest {
        origin: TEST_ORIGIN.to_owned(),
        login: "alice".to_owned(),
        code: secret(code),
        password: secret(PASSWORD),
        server_fingerprint: fingerprint,
    }
}

#[test]
fn sign_up_checks_the_typed_fingerprint_before_registering_anything() {
    run(async {
        let world = World::new();
        let code = world.server.issue_bootstrap_token().unwrap().to_text();
        let engine = fresh(&world, true);
        assert_eq!(
            engine.server_fingerprint(TEST_ORIGIN).await.unwrap(),
            fingerprint(&world)
        );

        let wrong = hasp_proto::format_fingerprint(&[7; 15]);
        let refused = Box::pin(engine.sign_up(sign_up_request(&code, wrong))).await;
        assert!(matches!(refused, Err(CoreError::ServerKey)), "{refused:?}");
        assert_eq!(engine.status().await.unwrap().state, LockState::Empty);
        let garbled = Box::pin(engine.sign_up(sign_up_request(&code, "nope".into()))).await;
        assert!(matches!(garbled, Err(CoreError::Refused(_))), "{garbled:?}");

        let kit = Box::pin(engine.sign_up(sign_up_request(&code, fingerprint(&world))))
            .await
            .unwrap();
        let status = engine.status().await.unwrap();
        assert_eq!(status.state, LockState::Unlocked);
        assert_eq!(status.login.as_deref(), Some("alice"));
        assert_eq!(status.unlock_mode, Some(UnlockMode::Hardware));
        assert!(status.device_confirmed);
        assert_eq!(kit.server_fingerprint, fingerprint(&world));
        assert_eq!(kit.login, "alice");
        let secret_key = String::from_utf8(kit.secret_key.take()).unwrap();
        assert!(secret_key.starts_with("V1-"), "{secret_key}");
        let preview =
            Engine::<InProcess<MemoryStore>, ClientStore>::parse_kit_qr(kit.qr_blob.as_bytes())
                .unwrap();
        assert_eq!(preview.server_fingerprint, fingerprint(&world));
        assert!(!kit.document_pdf.as_bytes().is_empty());
        assert!(
            String::from_utf8(kit.document_text.take())
                .unwrap()
                .contains(&secret_key)
        );

        let vaults = engine.vaults().await.unwrap();
        assert_eq!(vaults.len(), 1);
        assert!(vaults[0].writable);
        assert_eq!(
            engine
                .settings()
                .await
                .unwrap()
                .lock
                .clipboard_clear_seconds,
            30
        );
    });
}

#[test]
fn typed_secret_key_sign_in_compares_the_server_fingerprint_first() {
    run(async {
        let world = World::new();
        let code = world.server.issue_bootstrap_token().unwrap().to_text();
        let creator = fresh(&world, true);
        let kit = Box::pin(creator.sign_up(sign_up_request(&code, fingerprint(&world))))
            .await
            .unwrap();
        let secret_key = String::from_utf8(kit.secret_key.take()).unwrap();
        let request = |fingerprint: String| SignInRequest {
            origin: TEST_ORIGIN.to_owned(),
            login: "alice".to_owned(),
            secret_key: secret(&secret_key),
            password: secret(PASSWORD),
            server_fingerprint: fingerprint,
        };

        let device = fresh(&world, true);
        let wrong =
            Box::pin(device.sign_in(request(hasp_proto::format_fingerprint(&[3; 15])))).await;
        assert!(matches!(wrong, Err(CoreError::ServerKey)), "{wrong:?}");
        assert_eq!(device.status().await.unwrap().state, LockState::Empty);
        let missing = Box::pin(device.sign_in(request(String::new()))).await;
        assert!(matches!(missing, Err(CoreError::Refused(_))), "{missing:?}");

        Box::pin(device.sign_in(request(fingerprint(&world))))
            .await
            .unwrap();
        assert_eq!(device.status().await.unwrap().state, LockState::Unlocked);
    });
}

#[test]
fn a_password_only_device_resumes_from_a_session_blob_without_the_password() {
    run(async {
        let world = World::new();
        let code = world.server.issue_bootstrap_token().unwrap().to_text();
        let engine = fresh(&world, false);
        Box::pin(engine.sign_up(sign_up_request(&code, fingerprint(&world))))
            .await
            .unwrap();
        assert_eq!(
            engine.status().await.unwrap().unlock_mode,
            Some(UnlockMode::PasswordOnly)
        );
        engine.lock().await;

        let wrong = engine
            .unlock_with_password(secret("not the password at all"))
            .await;
        assert!(wrong.is_err());
        assert_eq!(engine.status().await.unwrap().state, LockState::Locked);
        let blob = engine
            .unlock_with_password(secret(PASSWORD))
            .await
            .unwrap()
            .session_blob;
        assert_eq!(engine.status().await.unwrap().state, LockState::Unlocked);
        assert_eq!(blob.as_bytes().len(), 33);
        assert!(
            !blob
                .as_bytes()
                .windows(PASSWORD.len())
                .any(|window| window == PASSWORD.as_bytes())
        );

        engine.lock().await;
        assert_eq!(engine.status().await.unwrap().state, LockState::Locked);
        engine.resume_session(blob.clone()).await.unwrap();
        assert_eq!(engine.status().await.unwrap().state, LockState::Unlocked);
        assert_eq!(engine.vaults().await.unwrap().len(), 1);

        engine.lock().await;
        let mut damaged = blob.as_bytes().to_vec();
        damaged[7] ^= 1;
        assert!(engine.resume_session(Secret::new(damaged)).await.is_err());
        assert!(engine.resume_session(secret("short")).await.is_err());
        let mut other_version = blob.as_bytes().to_vec();
        other_version[0] = 2;
        assert!(
            engine
                .resume_session(Secret::new(other_version))
                .await
                .is_err()
        );
        assert_eq!(engine.status().await.unwrap().state, LockState::Locked);
    });
}

#[test]
fn a_hardware_device_has_no_session_blob() {
    run(async {
        let world = World::new();
        let code = world.server.issue_bootstrap_token().unwrap().to_text();
        let engine = fresh(&world, true);
        Box::pin(engine.sign_up(sign_up_request(&code, fingerprint(&world))))
            .await
            .unwrap();
        engine.lock().await;
        let refused = engine.unlock_with_password(secret(PASSWORD)).await;
        assert!(matches!(refused, Err(CoreError::Refused(_))), "{refused:?}");
        assert!(
            engine
                .resume_session(Secret::new(vec![1; 33]))
                .await
                .is_err()
        );
    });
}

#[test]
fn a_desktop_fill_request_is_decided_with_the_normal_match_and_step_up_rules() {
    use hasp_core::api::{BrowserFillCheck, BrowserFillDecision, FrameContext, ItemDraft};

    run(async {
        let world = World::new();
        let code = world.server.issue_bootstrap_token().unwrap().to_text();
        let engine = fresh(&world, true);
        Box::pin(engine.sign_up(sign_up_request(&code, fingerprint(&world))))
            .await
            .unwrap();
        let vault = engine.vaults().await.unwrap().remove(0).id;
        let mut draft: ItemDraft = engine.blank_draft("login").unwrap();
        for field in draft.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
            match field.purpose.as_deref() {
                Some("username") => field.value = secret("alice"),
                Some("password") => field.value = secret("pw"),
                _ => {}
            }
        }
        "Example".clone_into(&mut draft.title);
        draft.urls.push(hasp_core::api::UrlDraft {
            id: None,
            url: "https://example.com/login".to_owned(),
            mode: "domain".to_owned(),
            kind: "sign-in".to_owned(),
        });
        let item = engine.create_item(&vault, draft).await.unwrap().item;
        let frame = FrameContext {
            top_frame: true,
            cross_origin_frame: false,
            sandboxed: false,
            obscured: false,
            visibility_check_supported: true,
        };
        let check = |item: &str, origin: &str| BrowserFillCheck {
            vault: vault.clone(),
            item: item.to_owned(),
            origin: origin.to_owned(),
            page_url: format!("{origin}/"),
            frame: frame.clone(),
        };
        let decide = |item: &str, origin: &str| engine.browser_fill_decision(check(item, origin));

        assert_eq!(
            decide(&item, "https://example.com").await.unwrap(),
            BrowserFillDecision::Fill
        );
        assert_eq!(
            decide(&item, "https://accounts.example.com").await.unwrap(),
            BrowserFillDecision::ConfirmInBrowser
        );
        assert_eq!(
            decide(&item, "https://evil.example.org").await.unwrap(),
            BrowserFillDecision::NoMatchingPage
        );
        assert_eq!(
            decide(&item, "http://example.com").await.unwrap(),
            BrowserFillDecision::NoMatchingPage
        );
        assert_eq!(
            decide(&"0".repeat(32), "https://example.com")
                .await
                .unwrap(),
            BrowserFillDecision::Unavailable
        );
        assert!(!engine.extension_paired(&"0".repeat(32), "chrome:abc").await);
        engine.lock().await;
        assert_eq!(
            decide(&item, "https://example.com").await.unwrap(),
            BrowserFillDecision::Locked
        );
    });
}
