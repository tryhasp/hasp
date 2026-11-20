#![expect(
    clippy::unwrap_used,
    clippy::print_stderr,
    reason = "a measurement test aborts on any failure and reports its numbers"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hasp_core::api::{
    AttachmentUpload, Engine, EngineConfig, IdentityKind, ItemDraft, OsAssertionRequest,
    OsRegistrationRequest, ProviderPasskeyQuery, ProviderQuery, Secret, TextQuery, UrlDraft,
    UserVerification,
};
use hasp_core::client::SignUp;
use hasp_core::platform::{ManualClock, MemorySecureStore, Platform, ScriptedBiometric};
use hasp_core::store::FileStore;
use hasp_server::MemoryStore;
use hasp_testsupport::{InProcess, TEST_ORIGIN, World, block_on};
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

const PASSWORD: &str = "a long memory test password";
const FULL_ITEMS: usize = 2_000;
const FULL_ATTACHMENTS: usize = 200;
const ATTACHMENT_BYTES: usize = 16 << 10;
const PASSKEY_ITEMS: usize = 40;
const BUDGET: usize = 30 << 20;

#[derive(Debug)]
struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(by: usize) {
    let now = CURRENT.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

#[expect(
    unsafe_code,
    reason = "a counting allocator wraps System to measure peak heap"
)]
// SAFETY: every method forwards to `System` with the caller's layout and only adds counters.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract for `layout`.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            grow(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: `pointer` and `layout` come from a matching `alloc` call of the caller.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc_zeroed` contract for `layout`.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            grow(layout.size());
        }
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::realloc` contract.
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            if new_size >= layout.size() {
                grow(new_size - layout.size());
            } else {
                CURRENT.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn scale() -> (usize, usize) {
    std::env::var("HASP_BENCH_SCALE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map_or((FULL_ITEMS, FULL_ATTACHMENTS), |divisor| {
            (FULL_ITEMS / divisor, FULL_ATTACHMENTS / divisor)
        })
}

fn start_window() -> usize {
    let base = CURRENT.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    base
}

fn window_peak(base: usize) -> usize {
    PEAK.load(Ordering::Relaxed).saturating_sub(base)
}

type BenchEngine = Engine<InProcess<MemoryStore>, FileStore>;

fn run<F: Future<Output = ()> + Send + 'static>(future: F) {
    std::thread::Builder::new()
        .stack_size(32 << 20)
        .spawn(move || block_on(Box::pin(future)))
        .unwrap()
        .join()
        .unwrap();
}

fn directory(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    drop(std::fs::remove_dir_all(&path));
    path
}

fn draft(engine: &BenchEngine, n: usize) -> ItemDraft {
    let mut draft = engine.blank_draft("login").unwrap();
    for field in draft.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        match field.purpose.as_deref() {
            Some("username") => {
                field.value = Secret::new(format!("user{n}@example.com").into_bytes());
            }
            Some("password") => {
                field.value = Secret::new(format!("password-{n}-{}", "x".repeat(24)).into_bytes());
            }
            Some("totp") if n.is_multiple_of(10) => {
                field.value = Secret::new(b"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".to_vec());
            }
            _ => {}
        }
    }
    draft.title = format!("Site number {n}");
    draft.subtitle = format!("user{n}@example.com");
    draft.notes = Some("a note about this account ".repeat(6));
    draft.urls.push(UrlDraft {
        id: None,
        url: format!("https://bench{n}-site.com/login"),
        mode: "domain".to_owned(),
        kind: "sign-in".to_owned(),
    });
    draft
}

fn open(dir: &Path, world: &World, platform: Platform) -> BenchEngine {
    Engine::new(
        world.transport(),
        FileStore::open(dir).unwrap(),
        platform,
        EngineConfig::new("ios"),
    )
    .unwrap()
}

async fn build(world: &World, dir: &Path, platform: Platform) {
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
    let engine = open(dir, world, platform);
    Box::pin(engine.sign_in_with_kit_qr(
        &kit.qr_blob().unwrap(),
        Secret::new(PASSWORD.as_bytes().to_vec()),
    ))
    .await
    .unwrap();
    let vault = engine.vaults().await.unwrap().remove(0).id;
    let (items, attachments) = scale();
    let started = std::time::Instant::now();
    let mut with_files = Vec::new();
    for n in 0..items {
        let created = engine.create_item(&vault, draft(&engine, n)).await.unwrap();
        if n % (items / attachments) == 0 {
            with_files.push(created.item);
        }
    }
    eprintln!("created {items} items in {:?}", started.elapsed());
    engine.sync().await.unwrap();
    eprintln!("synced at {:?}", started.elapsed());
    for (n, item) in with_files.iter().enumerate() {
        engine
            .attach_file(
                &vault,
                item,
                AttachmentUpload {
                    name: format!("scan-{n}.bin"),
                    mime: "application/octet-stream".to_owned(),
                    data: Secret::new(vec![u8::try_from(n % 251).unwrap(); ATTACHMENT_BYTES]),
                },
            )
            .await
            .unwrap();
    }
    eprintln!(
        "attached {} files at {:?}",
        with_files.len(),
        started.elapsed()
    );
    for n in 0..PASSKEY_ITEMS {
        engine
            .provider_passkey_register(OsRegistrationRequest {
                rp_id: format!("passkey{n}.example.org"),
                rp_name: "Example".to_owned(),
                client_data_hash: "mS3k4o5sJ6cRkN3JrF9pQ7mZqk3a9tTQxA2kqj1R0eY".to_owned(),
                user_name: format!("user{n}"),
                user_display_name: format!("User {n}"),
                user_handle: "dXNlci0x".to_owned(),
                algorithms: vec![-7],
                exclude: Vec::new(),
                user_verification: UserVerification::Preferred,
                user_verified: false,
                vault: None,
                item: None,
            })
            .await
            .unwrap();
    }
    eprintln!("passkeys at {:?}", started.elapsed());
    engine.sync().await.unwrap();
    eprintln!("built at {:?}", started.elapsed());
    engine.lock().await;
}

async fn session(engine: &BenchEngine) {
    engine.provider_unlock().await.unwrap();
    let diff = engine.identity_diff().await.unwrap();
    assert!(diff.identities.len() >= scale().0 + PASSKEY_ITEMS);
    assert!(
        diff.identities
            .iter()
            .any(|i| i.kind == IdentityKind::Passkey)
    );
    let hits = engine
        .provider_candidates(ProviderQuery {
            identifiers: vec!["bench120-site.com".to_owned()],
            limit: 10,
        })
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);
    let password = engine
        .provider_password(
            &hits[0].vault,
            &hits[0].item,
            Some("bench120-site.com".to_owned()),
            false,
            false,
        )
        .await
        .unwrap();
    assert!(password.password.as_bytes().starts_with(b"password-120"));
    let code = engine
        .totp(&hits[0].vault, &hits[0].item, None)
        .await
        .unwrap();
    assert_eq!(code.digits, 6);
    let text = engine
        .text_candidates(TextQuery {
            text: "site number 1".to_owned(),
            limit: 20,
        })
        .await
        .unwrap();
    assert!(!text.is_empty());
    let keys = engine
        .provider_passkeys(ProviderPasskeyQuery {
            rp_id: "passkey7.example.org".to_owned(),
            allow: Vec::new(),
        })
        .await
        .unwrap();
    assert_eq!(keys.len(), 1);
    engine
        .provider_passkey_assert(OsAssertionRequest {
            rp_id: "passkey7.example.org".to_owned(),
            client_data_hash: "mS3k4o5sJ6cRkN3JrF9pQ7mZqk3a9tTQxA2kqj1R0eY".to_owned(),
            allow: Vec::new(),
            user_verification: UserVerification::Preferred,
            user_verified: false,
            vault: None,
            item: None,
            credential_id: None,
        })
        .await
        .unwrap();
}

fn platform() -> Platform {
    Platform {
        secure: Arc::new(MemorySecureStore::new(true)),
        biometric: Arc::new(ScriptedBiometric::new(true, true)),
        clock: Arc::new(ManualClock::new(1_000_000)),
    }
}

#[test]
fn a_provider_session_over_two_thousand_items_stays_under_the_budget() {
    run(async {
        let world = World::new();
        let dir = directory("provider-memory-warm");
        let device = platform();
        Box::pin(build(&world, &dir, device.clone())).await;

        let base = start_window();
        let engine = open(&dir, &world, device);
        session(&engine).await;
        let peak = window_peak(base);
        let opened = engine.items_opened_for_tests().await;
        eprintln!(
            "provider warm index: peak heap {} KiB, {opened} items opened, store {} bytes",
            peak / 1024,
            std::fs::metadata(dir.join("snapshot")).map_or(0, |m| m.len())
                + std::fs::metadata(dir.join("log")).map_or(0, |m| m.len())
        );
        assert!(peak < BUDGET, "peak {peak} bytes");
        assert!(opened < 40, "{opened} items opened");
        drop(std::fs::remove_dir_all(&dir));
    });
}

#[test]
fn building_the_index_from_nothing_streams_and_stays_under_the_budget() {
    run(async {
        let world = World::new();
        let dir = directory("provider-memory-cold");
        let device = platform();
        Box::pin(build(&world, &dir, device.clone())).await;
        let engine = open(&dir, &world, device.clone());
        engine.provider_unlock().await.unwrap();
        engine.drop_provider_index_for_tests().await.unwrap();
        engine.lock().await;
        drop(engine);

        let base = start_window();
        let engine = open(&dir, &world, device);
        session(&engine).await;
        let peak = window_peak(base);
        eprintln!(
            "provider cold index: peak heap {} KiB, {} items opened",
            peak / 1024,
            engine.items_opened_for_tests().await
        );
        assert!(peak < BUDGET, "peak {peak} bytes");
        drop(std::fs::remove_dir_all(&dir));
    });
}
