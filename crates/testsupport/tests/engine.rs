#![expect(
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "tests assert by unwrapping"
)]

use std::sync::Arc;

use hasp_core::api::{
    AutofillQuery, Engine, EngineConfig, EventKind, FillKind, FillRequest, FrameContext,
    GeneratorKind, GeneratorRequest, ItemDraft, LockState, LockTrigger, SaveCommit, SaveDraft,
    SaveKind, SearchQuery, Secret, SecretTag, StepUp,
};
use hasp_core::client::SignUp;
use hasp_core::platform::{ManualClock, Platform};
use hasp_core::store::MemoryStore as ClientStore;
use hasp_server::MemoryStore;
use hasp_testsupport::{InProcess, TEST_ORIGIN, World, block_on};
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

type TestEngine = Engine<InProcess<MemoryStore>, ClientStore>;

const PASSWORD: &str = "a long engine test password";

fn frame() -> FrameContext {
    FrameContext {
        top_frame: true,
        cross_origin_frame: false,
        sandboxed: false,
        obscured: false,
        visibility_check_supported: true,
    }
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
    let clock = Arc::new(ManualClock::new(1_000_000));
    let engine = Engine::new(
        world.transport(),
        ClientStore::new(),
        Platform::for_tests(clock),
        EngineConfig::new("macos"),
    )
    .unwrap();
    let blob = kit.qr_blob().unwrap();
    Box::pin(engine.sign_in_with_kit_qr(&blob, Secret::new(PASSWORD.as_bytes().to_vec())))
        .await
        .unwrap();
    engine
}

fn login_draft(engine: &TestEngine, title: &str, url: &str, user: &str, pass: &str) -> ItemDraft {
    let mut draft = engine.blank_draft("login").unwrap();
    for field in draft.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        match field.purpose.as_deref() {
            Some("username") => field.value = Secret::new(user.as_bytes().to_vec()),
            Some("password") => field.value = Secret::new(pass.as_bytes().to_vec()),
            _ => {}
        }
    }
    title.clone_into(&mut draft.title);
    draft.urls.push(hasp_core::api::UrlDraft {
        id: None,
        url: url.to_owned(),
        mode: "domain".to_owned(),
        kind: "sign-in".to_owned(),
    });
    draft
}

fn run<F: Future<Output = ()> + Send + 'static>(future: F) {
    std::thread::Builder::new()
        .stack_size(32 << 20)
        .spawn(move || block_on(Box::pin(future)))
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn items_search_reveal_edit_and_history() {
    run(async {
        let world = World::new();
        let engine = engine(&world).await;
        let status = engine.status().await.unwrap();
        assert_eq!(status.state, LockState::Unlocked);
        assert_eq!(status.login.as_deref(), Some("alice"));
        let vault = engine.vaults().await.unwrap().remove(0);
        assert!(vault.writable);

        let created = engine
            .create_item(
                &vault.id,
                login_draft(
                    &engine,
                    "Example",
                    "https://example.com/login",
                    "alice@x.com",
                    "pw-one",
                ),
            )
            .await
            .unwrap();
        let rows = engine.items(&vault.id).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].hosts, vec!["example.com".to_owned()]);

        let detail = engine.item_detail(&vault.id, &created.item).await.unwrap();
        let password = detail
            .sections
            .iter()
            .flat_map(|s| &s.fields)
            .find(|f| f.purpose.as_deref() == Some("password"))
            .unwrap();
        assert!(password.concealed && password.value.is_none());
        let revealed = engine
            .reveal_field(&vault.id, &created.item, &password.id)
            .await
            .unwrap();
        assert_eq!(revealed.as_bytes(), b"pw-one");

        let found = engine
            .search(SearchQuery {
                text: "exa".to_owned(),
                vault: None,
                kind: None,
                tag: None,
                favourites_only: false,
                status: None,
                boost_url: None,
                limit: 0,
            })
            .await
            .unwrap();
        assert_eq!(found.len(), 1);

        let mut draft = engine.edit_draft(&vault.id, &created.item).await.unwrap();
        for field in draft.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
            if field.purpose.as_deref() == Some("password") {
                field.value = Secret::new(b"pw-two".to_vec());
                field.keep_value = false;
            }
        }
        engine
            .edit_item(&vault.id, &created.item, draft)
            .await
            .unwrap();
        let detail = engine.item_detail(&vault.id, &created.item).await.unwrap();
        assert_eq!(detail.password_history, 1);
        engine.sync().await.unwrap();
        assert!(
            !engine
                .history(&vault.id, &created.item)
                .await
                .unwrap()
                .is_empty()
        );

        engine
            .set_favourite(&vault.id, &created.item, true)
            .await
            .unwrap();
        engine
            .set_status(
                &vault.id,
                &created.item,
                hasp_core::api::ItemStatus::Trashed,
            )
            .await
            .unwrap();
        assert_eq!(
            engine.items(&vault.id).await.unwrap()[0].status,
            hasp_core::api::ItemStatus::Trashed
        );
    });
}

#[test]
fn totp_codes_and_the_fill_wait() {
    run(async {
        let world = World::new();
        let engine = engine(&world).await;
        let vault = engine.vaults().await.unwrap().remove(0);
        let mut draft = login_draft(&engine, "Otp", "https://otp.example.com/", "u", "p");
        draft.sections[0].fields.push(hasp_core::api::FieldDraft {
            id: None,
            label: "one-time password".to_owned(),
            kind: "otp".to_owned(),
            purpose: Some("totp".to_owned()),
            concealed: true,
            expires_alert: false,
            value: Secret::new(
                b"otpauth://totp/Example:u?secret=JBSWY3DPEHPK3PXP&issuer=Example".to_vec(),
            ),
            keep_value: false,
        });
        let created = engine.create_item(&vault.id, draft).await.unwrap();
        let code = engine.totp(&vault.id, &created.item, None).await.unwrap();
        assert_eq!(code.digits, 6);
        assert_eq!(code.period, 30);
        assert_eq!(code.remaining, 20);
        assert_eq!(code.code.as_bytes().len(), 6);
        let request = FillRequest {
            vault: vault.id.clone(),
            item: created.item.clone(),
            origin: "https://otp.example.com".to_owned(),
            page_url: "https://otp.example.com/".to_owned(),
            kind: FillKind::Otp,
            frame: frame(),
            approved: false,
            remember_host: false,
            in_iframe_click: false,
        };
        let payload = engine.fill_payload(request).await.unwrap();
        assert_eq!(payload.otp_wait_seconds, 0);
        assert_eq!(payload.values.len(), 1);
    });
}

#[test]
fn matching_step_up_and_save_proposals() {
    run(async {
        let world = World::new();
        let engine = engine(&world).await;
        let vault = engine.vaults().await.unwrap().remove(0);
        let created = engine
            .create_item(
                &vault.id,
                login_draft(
                    &engine,
                    "Example",
                    "https://www.example.com/login",
                    "bob",
                    "secret-1",
                ),
            )
            .await
            .unwrap();

        let exact = engine
            .autofill_query(AutofillQuery {
                page_url: "https://www.example.com/login".to_owned(),
                origin: "https://www.example.com".to_owned(),
                frame: frame(),
            })
            .await
            .unwrap();
        assert_eq!(exact.candidates.len(), 1);
        assert_eq!(exact.candidates[0].tier, hasp_core::api::MatchTier::Exact);

        let cross = engine
            .autofill_query(AutofillQuery {
                page_url: "https://accounts.example.com/".to_owned(),
                origin: "https://accounts.example.com".to_owned(),
                frame: frame(),
            })
            .await
            .unwrap();
        assert_eq!(cross.candidates[0].tier, hasp_core::api::MatchTier::Domain);
        assert_eq!(
            cross.candidates[0].host_to_confirm.as_deref(),
            Some("accounts.example.com")
        );

        let http = engine
            .autofill_query(AutofillQuery {
                page_url: "http://www.example.com/".to_owned(),
                origin: "http://www.example.com".to_owned(),
                frame: frame(),
            })
            .await
            .unwrap();
        assert!(http.candidates.is_empty() && http.refusal.is_some());

        let request = |origin: &str, approved: bool| FillRequest {
            remember_host: approved,
            vault: vault.id.clone(),
            item: created.item.clone(),
            origin: origin.to_owned(),
            page_url: origin.to_owned(),
            kind: FillKind::Login,
            frame: frame(),
            approved,
            in_iframe_click: true,
        };
        let plan = engine
            .fill_plan(request("https://accounts.example.com", false))
            .await
            .unwrap();
        assert_eq!(plan.step_up, StepUp::InlineConfirmHost);
        assert!(
            engine
                .fill_payload(request("https://accounts.example.com", false))
                .await
                .is_err()
        );
        let payload = engine
            .fill_payload(request("https://accounts.example.com", true))
            .await
            .unwrap();
        assert!(
            payload
                .values
                .iter()
                .any(|v| v.purpose == "password" && v.value.as_bytes() == b"secret-1")
        );
        let again = engine
            .fill_plan(request("https://accounts.example.com", false))
            .await
            .unwrap();
        assert_eq!(again.step_up, StepUp::Allow);

        let obscured = FillRequest {
            frame: FrameContext {
                obscured: true,
                ..frame()
            },
            ..request("https://www.example.com", false)
        };
        assert_eq!(
            engine.fill_plan(obscured).await.unwrap().step_up,
            StepUp::BrowserUi
        );

        let draft = |user: &str, pass: &str| SaveDraft {
            origin: "https://www.example.com".to_owned(),
            page_url: "https://www.example.com/login".to_owned(),
            username: user.to_owned(),
            password: Secret::new(pass.as_bytes().to_vec()),
            generated: false,
        };
        assert_eq!(
            engine
                .propose_save(draft("bob", "secret-1"))
                .await
                .unwrap()
                .kind,
            SaveKind::Identical
        );
        let update = engine.propose_save(draft("bob", "secret-2")).await.unwrap();
        assert_eq!(update.kind, SaveKind::Update);
        engine
            .commit_save(SaveCommit {
                draft: draft("bob", "secret-2"),
                kind: SaveKind::Update,
                vault: update.vault.clone().unwrap(),
                item: update.item.clone(),
                title: update.suggested_title.clone(),
            })
            .await
            .unwrap();
        let reveal = engine
            .fill_payload(request("https://www.example.com", false))
            .await
            .unwrap();
        assert!(
            reveal
                .values
                .iter()
                .any(|v| v.purpose == "password" && v.value.as_bytes() == b"secret-2")
        );
        let fresh = engine.propose_save(draft("carol", "x")).await.unwrap();
        assert_eq!(fresh.kind, SaveKind::New);
        engine
            .commit_save(SaveCommit {
                draft: draft("carol", "x-pass"),
                kind: SaveKind::New,
                vault: fresh.vault.clone().unwrap(),
                item: None,
                title: fresh.suggested_title.clone(),
            })
            .await
            .unwrap();
        assert_eq!(engine.items(&vault.id).await.unwrap().len(), 2);
    });
}

#[test]
fn settings_lock_policy_generator_and_events() {
    run(async {
        let world = World::new();
        let engine = engine(&world).await;
        assert!(matches!(
            engine.next_event().await.kind,
            EventKind::Unlocked
        ));

        let mut settings = engine.settings().await.unwrap();
        assert_eq!(settings.lock.idle_minutes, 10);
        settings.secret_tag = Some(SecretTag {
            word: "등대".to_owned(),
            glyph: 5,
        });
        engine.set_settings(settings.clone()).await.unwrap();
        assert_eq!(
            engine.settings().await.unwrap().secret_tag,
            settings.secret_tag
        );
        settings.secret_tag = Some(SecretTag {
            word: "x".repeat(13),
            glyph: 5,
        });
        assert!(engine.set_settings(settings).await.is_err());

        assert!(
            !engine
                .apply_lock_trigger(LockTrigger::Idle, 60)
                .await
                .unwrap()
        );
        assert!(
            engine
                .apply_lock_trigger(LockTrigger::Idle, 600)
                .await
                .unwrap()
        );
        assert_eq!(engine.status().await.unwrap().state, LockState::Locked);
        engine
            .unlock_password(Secret::new(PASSWORD.as_bytes().to_vec()))
            .await
            .unwrap();
        assert_eq!(engine.status().await.unwrap().state, LockState::Unlocked);

        let generated = engine
            .generate(&GeneratorRequest {
                kind: GeneratorKind::Random,
                length: 24,
                lower: true,
                upper: true,
                digits: true,
                symbols: Some("!@#".to_owned()),
                exclude_ambiguous: false,
                words: 5,
                separator: "-".to_owned(),
                capitalize: false,
                append_digit: false,
                origin: None,
                site_rules: Some("minlength: 8; maxlength: 12; required: lower, digit;".to_owned()),
                field_min_length: None,
                field_max_length: None,
            })
            .unwrap();
        assert!((8..=12).contains(&generated.length));
        assert!(generated.site_rules_applied);
        let report = engine.watchtower_report().await.unwrap();
        assert_eq!(report.checked, 0);
    });
}
