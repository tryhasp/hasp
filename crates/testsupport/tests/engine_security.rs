#![expect(
    clippy::unwrap_used,
    clippy::unwrap_in_result,
    reason = "tests assert by unwrapping"
)]

use std::sync::{Arc, Mutex};

use hasp_core::CoreError;
use hasp_core::api::{
    Engine, EngineConfig, FillKind, FillRequest, FrameContext, ItemDraft, Secret, StepUp,
    extension_unlock_code, registrable_domain,
};
use hasp_core::client::{Channel, ChannelError, SignUp};
use hasp_core::platform::{
    Biometric, Clock, ManualClock, MemorySecureStore, Platform, PlatformError, ScriptedBiometric,
};
use hasp_core::store::{Batch, Entry, MemoryStore as ClientStore, Store, StoreError};
use hasp_server::MemoryStore;
use hasp_testsupport::{InProcess, TEST_ORIGIN, World, block_on, cancel};
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

const PASSWORD: &str = "a long engine test password";
const PEER: &str = "chrome:abcdefghijklmnopabcdefghijklmnop";
const DAY: u64 = 86_400;

#[derive(Clone, Debug, Default)]
struct Shared(Arc<Mutex<ClientStore>>);

impl Store for Shared {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.0.lock().unwrap().get(key)
    }

    fn scan(&self, prefix: &[u8]) -> Result<Vec<Entry>, StoreError> {
        self.0.lock().unwrap().scan(prefix)
    }

    fn apply(&mut self, batch: &Batch) -> Result<(), StoreError> {
        self.0.lock().unwrap().apply(batch)
    }
}

type TestEngine = Engine<InProcess<MemoryStore>, Shared>;

struct Rig {
    world: World,
    engine: TestEngine,
    biometric: Arc<ScriptedBiometric>,
    clock: Arc<ManualClock>,
    store: Shared,
}

fn run<F: Future<Output = ()> + Send + 'static>(future: F) {
    std::thread::Builder::new()
        .stack_size(32 << 20)
        .spawn(move || block_on(Box::pin(future)))
        .unwrap()
        .join()
        .unwrap();
}

fn frame() -> FrameContext {
    FrameContext {
        top_frame: true,
        cross_origin_frame: false,
        sandboxed: false,
        obscured: false,
        visibility_check_supported: true,
    }
}

struct Gated {
    inner: Arc<ScriptedBiometric>,
    entered: Mutex<std::sync::mpsc::Sender<()>>,
    proceed: Mutex<std::sync::mpsc::Receiver<()>>,
    armed: Arc<std::sync::atomic::AtomicBool>,
}

impl Biometric for Gated {
    fn available(&self) -> bool {
        true
    }

    fn authenticate(&self, reason: &str) -> Result<(), PlatformError> {
        if self.armed.load(std::sync::atomic::Ordering::SeqCst) {
            self.entered.lock().unwrap().send(()).ok();
            self.proceed.lock().unwrap().recv().ok();
        }
        self.inner.authenticate(reason)
    }
}

async fn rig() -> Rig {
    let scripted = Arc::new(ScriptedBiometric::new(true, true));
    rig_with(scripted.clone(), scripted).await
}

async fn rig_with(biometric: Arc<dyn Biometric>, scripted: Arc<ScriptedBiometric>) -> Rig {
    let world = World::new();
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
    let store = Shared::default();
    let engine = Engine::new(
        world.transport(),
        store.clone(),
        Platform {
            secure: Arc::new(MemorySecureStore::new(true)),
            biometric,
            clock: clock.clone(),
        },
        EngineConfig::new("macos"),
    )
    .unwrap();
    let blob = kit.qr_blob().unwrap();
    Box::pin(engine.sign_in_with_kit_qr(&blob, Secret::new(PASSWORD.as_bytes().to_vec())))
        .await
        .unwrap();
    Rig {
        world,
        engine,
        biometric: scripted,
        clock,
        store,
    }
}

struct Pipe {
    tx: Mutex<std::sync::mpsc::Sender<Vec<u8>>>,
    rx: Mutex<std::sync::mpsc::Receiver<Vec<u8>>>,
}

impl Channel for Pipe {
    fn send(&self, message: Vec<u8>) -> impl Future<Output = Result<(), ChannelError>> + Send {
        std::future::ready(
            self.tx
                .lock()
                .unwrap()
                .send(message)
                .map_err(|_| ChannelError::Closed),
        )
    }

    fn recv(&self) -> impl Future<Output = Result<Vec<u8>, ChannelError>> + Send {
        std::future::ready(
            self.rx
                .lock()
                .unwrap()
                .recv()
                .map_err(|_| ChannelError::Closed),
        )
    }
}

fn pair(rig: &Rig) -> String {
    let mut extension = rig.world.device(false);
    let (to_ext, from_desktop) = std::sync::mpsc::channel();
    let (to_desktop, from_ext) = std::sync::mpsc::channel();
    let desktop_side = Pipe {
        tx: Mutex::new(to_ext),
        rx: Mutex::new(from_ext),
    };
    let ext_side = Pipe {
        tx: Mutex::new(to_desktop),
        rx: Mutex::new(from_desktop),
    };
    std::thread::scope(|scope| {
        let served = scope
            .spawn(|| block_on(rig.engine.serve_extension_pairing(&desktop_side, PEER)).unwrap());
        scope.spawn(|| {
            block_on(
                extension
                    .client
                    .pair_with_desktop(&ext_side, "chrome", &cancel()),
            )
            .unwrap();
        });
        served.join().unwrap()
    })
}

fn nonce(byte: u8) -> String {
    hasp_proto::base64url::encode(&[byte; 16])
}

fn login_draft(engine: &TestEngine, url: &str) -> ItemDraft {
    let mut draft = engine.blank_draft("login").unwrap();
    for field in draft.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        match field.purpose.as_deref() {
            Some("username") => field.value = Secret::new(b"bob".to_vec()),
            Some("password") => field.value = Secret::new(b"secret-1".to_vec()),
            _ => {}
        }
    }
    "Example".clone_into(&mut draft.title);
    draft.urls.push(hasp_core::api::UrlDraft {
        id: None,
        url: url.to_owned(),
        mode: "domain".to_owned(),
        kind: "sign-in".to_owned(),
    });
    draft
}

fn overwrite_note(rig: &Rig, name: &str, plain: &[u8]) {
    let needle = format!("note/{name}");
    let mut batch = Batch::new();
    for (key, _) in rig.store.scan(&[]).unwrap() {
        if key.windows(needle.len()).any(|w| w == needle.as_bytes()) {
            batch.put(key, plain.to_vec());
        }
    }
    assert!(!batch.is_empty(), "the note {name} is stored");
    rig.store.clone().apply(&batch).unwrap();
}

#[test]
fn h2_a_revoked_extension_device_loses_its_key_and_cannot_replay_unlock() {
    run(async {
        let rig = rig().await;
        let device = pair(&rig);
        assert!(rig.engine.extension_paired(&device, PEER).await);
        let prompts = rig.biometric.reasons().len();
        let entry = rig
            .engine
            .devices()
            .await
            .unwrap()
            .into_iter()
            .find(|entry| entry.device == device)
            .unwrap();
        rig.engine
            .revoke_device(&entry.session, &entry.device)
            .await
            .unwrap();
        assert!(!rig.engine.extension_paired(&device, PEER).await);
        let replay = rig
            .engine
            .release_extension_key(&device, PEER, &nonce(1))
            .await;
        assert!(matches!(replay, Err(CoreError::NotFound(_))), "{replay:?}");
        assert_eq!(
            rig.biometric.reasons().len(),
            prompts,
            "no prompt was shown"
        );
    });
}

#[test]
fn h1_the_unlock_prompt_shows_the_code_of_this_device_and_nonce() {
    run(async {
        let rig = rig().await;
        let device = pair(&rig);
        let first = nonce(3);
        rig.engine
            .release_extension_key(&device, PEER, &first)
            .await
            .unwrap();
        let second = nonce(4);
        rig.engine
            .release_extension_key(&device, PEER, &second)
            .await
            .unwrap();
        let reasons = rig.biometric.reasons();
        let (a, b) = (
            extension_unlock_code(&device, &first).unwrap(),
            extension_unlock_code(&device, &second).unwrap(),
        );
        assert_ne!(a, b, "a new nonce gives a new code");
        assert!(reasons[reasons.len() - 2].ends_with(&format!("Code {a}")));
        assert!(reasons[reasons.len() - 1].ends_with(&format!("Code {b}")));
        assert!(reasons[reasons.len() - 1].starts_with("Unlock the chrome extension"));
    });
}

#[test]
fn h1_a_malformed_nonce_or_another_peer_never_reaches_the_prompt() {
    run(async {
        let rig = rig().await;
        let device = pair(&rig);
        let prompts = rig.biometric.reasons().len();
        assert!(
            rig.engine
                .release_extension_key(&device, PEER, "AAAA")
                .await
                .is_err()
        );
        assert!(
            rig.engine
                .release_extension_key(
                    &device,
                    "chrome:otherotherotherotherotherother12",
                    &nonce(5)
                )
                .await
                .is_err()
        );
        assert_eq!(rig.biometric.reasons().len(), prompts);
    });
}

#[test]
fn h1_a_declined_prompt_releases_nothing() {
    run(async {
        let rig = rig().await;
        let device = pair(&rig);
        rig.biometric.set_approve(false);
        assert!(
            rig.engine
                .release_extension_key(&device, PEER, &nonce(6))
                .await
                .is_err()
        );
    });
}

#[test]
fn h1_the_engine_stays_usable_while_the_unlock_prompt_is_open() {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (proceed_tx, proceed_rx) = std::sync::mpsc::channel();
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let scripted = Arc::new(ScriptedBiometric::new(true, true));
    let gated = Arc::new(Gated {
        inner: scripted.clone(),
        entered: Mutex::new(entered_tx),
        proceed: Mutex::new(proceed_rx),
        armed: Arc::clone(&armed),
    });
    let (device, engine) = std::thread::spawn(move || {
        block_on(Box::pin(async move {
            let rig = rig_with(gated, scripted).await;
            let device = pair(&rig);
            (device, Arc::new(rig.engine))
        }))
    })
    .join()
    .unwrap();
    armed.store(true, std::sync::atomic::Ordering::SeqCst);
    let asking = Arc::clone(&engine);
    let release = std::thread::spawn(move || {
        block_on(Box::pin(asking.release_extension_key(
            &device,
            PEER,
            &nonce(7),
        )))
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let probing = Arc::clone(&engine);
    std::thread::spawn(move || {
        done_tx
            .send(block_on(Box::pin(probing.status())).is_ok())
            .ok();
    });
    let answered = done_rx.recv_timeout(std::time::Duration::from_secs(5));
    proceed_tx.send(()).unwrap();
    assert_eq!(
        answered,
        Ok(true),
        "status answered while the prompt was open"
    );
    release.join().unwrap().unwrap();
}

#[test]
fn m10_the_password_rule_blocks_biometric_unlock_and_key_release_before_any_prompt() {
    run(async {
        let rig = rig().await;
        let device = pair(&rig);
        let mut settings = rig.engine.settings().await.unwrap();
        settings.lock.password_every_days = 14;
        rig.engine.set_settings(settings).await.unwrap();
        rig.clock.advance(15 * DAY);
        let prompts = rig.biometric.reasons().len();
        let release = rig
            .engine
            .release_extension_key(&device, PEER, &nonce(8))
            .await;
        assert!(matches!(release, Err(CoreError::Refused(_))), "{release:?}");
        rig.engine.lock().await;
        let unlock = rig.engine.unlock_biometric().await;
        assert!(matches!(unlock, Err(CoreError::Refused(_))), "{unlock:?}");
        assert_eq!(rig.biometric.reasons().len(), prompts);
        rig.engine
            .unlock_password(Secret::new(PASSWORD.as_bytes().to_vec()))
            .await
            .unwrap();
        rig.engine.lock().await;
        rig.engine.unlock_biometric().await.unwrap();
    });
}

#[test]
fn m10_setting_the_clock_back_does_not_stretch_the_password_window() {
    run(async {
        let rig = rig().await;
        let mut settings = rig.engine.settings().await.unwrap();
        settings.lock.password_every_days = 14;
        rig.engine.set_settings(settings).await.unwrap();
        rig.clock.advance(10 * DAY);
        rig.engine.lock().await;
        rig.engine.unlock_biometric().await.unwrap();
        assert!(!rig.engine.status().await.unwrap().password_required);
        rig.clock.set(1_000_000 + DAY);
        assert!(
            rig.engine.status().await.unwrap().password_required,
            "a clock moved back past the high-water mark asks for the password"
        );
        rig.engine.lock().await;
        rig.engine.unlock_biometric().await.unwrap_err();
    });
}

#[test]
fn m1_a_settings_record_written_in_clear_is_rejected_and_reset_to_the_defaults() {
    run(async {
        let rig = rig().await;
        let mut settings = rig.engine.settings().await.unwrap();
        settings.lock.idle_minutes = 5;
        rig.engine.set_settings(settings).await.unwrap();
        overwrite_note(
            &rig,
            "settings",
            br#"{"lock":{"idle_minutes":0,"password_every_days":0}}"#,
        );
        let after = rig.engine.settings().await.unwrap();
        assert_eq!(
            after.lock.idle_minutes, 10,
            "the defaults, not the planted 0"
        );
        assert_ne!(after.lock.password_every_days, 0);
    });
}

#[test]
fn m1_a_planted_last_password_time_cannot_extend_the_window() {
    run(async {
        let rig = rig().await;
        let mut settings = rig.engine.settings().await.unwrap();
        settings.lock.password_every_days = 14;
        rig.engine.set_settings(settings).await.unwrap();
        rig.clock.advance(20 * DAY);
        overwrite_note(&rig, "last-password-unlock", &rig.clock.now().to_be_bytes());
        let device = pair(&rig);
        let refused = rig
            .engine
            .release_extension_key(&device, PEER, &nonce(9))
            .await;
        assert!(refused.is_err(), "a forged timestamp is not trusted");
    });
}

#[test]
fn h3_an_approved_fill_without_remember_host_never_remembers_the_host() {
    run(async {
        let rig = rig().await;
        let vault = rig.engine.vaults().await.unwrap().remove(0);
        let created = rig
            .engine
            .create_item(
                &vault.id,
                login_draft(&rig.engine, "https://www.example.com/login"),
            )
            .await
            .unwrap();
        let request = |approved: bool, remember_host: bool| FillRequest {
            vault: vault.id.clone(),
            item: created.item.clone(),
            origin: "https://accounts.example.com".to_owned(),
            page_url: "https://accounts.example.com".to_owned(),
            kind: FillKind::Login,
            frame: frame(),
            approved,
            remember_host,
            in_iframe_click: true,
        };
        rig.engine.fill_payload(request(true, false)).await.unwrap();
        let plan = rig.engine.fill_plan(request(false, false)).await.unwrap();
        assert_eq!(
            plan.step_up,
            StepUp::InlineConfirmHost,
            "approval alone is one-time"
        );
        rig.engine.fill_payload(request(true, true)).await.unwrap();
        let plan = rig.engine.fill_plan(request(false, false)).await.unwrap();
        assert_eq!(plan.step_up, StepUp::Allow);
    });
}

#[test]
fn m6_the_registrable_domain_uses_the_full_list_with_its_private_section() {
    assert_eq!(
        registrable_domain("login.bank.com.evil.com.tr").as_deref(),
        Some("evil.com.tr")
    );
    assert_eq!(
        registrable_domain("evil.github.io").as_deref(),
        Some("evil.github.io")
    );
    assert_eq!(
        registrable_domain("a.b.example.co.uk").as_deref(),
        Some("example.co.uk")
    );
    assert_eq!(registrable_domain("com"), None);
    assert_eq!(
        registrable_domain("Www.Example.COM").as_deref(),
        Some("example.com")
    );
}
