#![expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use hasp_core::api::{Engine, EngineConfig, Secret};
use hasp_core::client::SignUp;
use hasp_core::platform::{ManualClock, MemorySecureStore, Platform, ScriptedBiometric};
use hasp_core::store::{Cache, FileStore, Records};
use hasp_core::transport::{Transport, TransportError};
use hasp_proto::wire::{Operation, SessionToken};
use hasp_server::MemoryStore;
use hasp_testsupport::{InProcess, TEST_ORIGIN, World, block_on};
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

const PASSWORD: &str = "a long race test password";

#[derive(Debug)]
struct Rewriting {
    inner: InProcess<MemoryStore>,
    dir: PathBuf,
    commits: Arc<AtomicUsize>,
    armed: Arc<AtomicBool>,
}

impl Transport for Rewriting {
    fn call<O: Operation + Sync>(
        &self,
        token: Option<&SessionToken>,
        request: &O,
    ) -> impl Future<Output = Result<O::Response, TransportError>> + Send {
        if std::any::type_name::<O>().ends_with("Commit") {
            self.commits.fetch_add(1, Ordering::Relaxed);
            if self.armed.swap(false, Ordering::Relaxed) {
                let mut cache = Cache::new(FileStore::open(&self.dir).unwrap());
                let vault = cache.vaults().unwrap().remove(0).vault_id;
                let mut op = cache.pending(&vault).unwrap().remove(0);
                op.base_ver = op.base_ver.checked_next().unwrap();
                let mut batch = hasp_core::store::Batch::new();
                Records::put_pending(&mut batch, &op).unwrap();
                cache.commit(&batch).unwrap();
            }
        }
        self.inner.call(token, request)
    }
}

#[test]
fn an_operation_rewritten_during_the_network_call_is_not_deleted_by_the_sync() {
    std::thread::Builder::new()
        .stack_size(32 << 20)
        .spawn(|| {
            block_on(Box::pin(async {
                let world = World::new();
                let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("sync-race");
                drop(std::fs::remove_dir_all(&dir));
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
                let commits = Arc::new(AtomicUsize::new(0));
                let armed = Arc::new(AtomicBool::new(false));
                let platform = Platform {
                    secure: Arc::new(MemorySecureStore::new(true)),
                    biometric: Arc::new(ScriptedBiometric::new(true, true)),
                    clock: Arc::new(ManualClock::new(1_000_000)),
                };
                let engine = Engine::new(
                    Rewriting {
                        inner: world.transport(),
                        dir: dir.clone(),
                        commits: Arc::clone(&commits),
                        armed: Arc::clone(&armed),
                    },
                    FileStore::open(&dir).unwrap(),
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
                engine.sync().await.unwrap();
                let vault = engine.vaults().await.unwrap().remove(0).id;
                let mut draft = engine.blank_draft("login").unwrap();
                draft.title = "Raced".to_owned();
                engine.create_item(&vault, draft).await.unwrap();
                commits.store(0, Ordering::Relaxed);
                armed.store(true, Ordering::Relaxed);
                engine.sync().await.unwrap();
                assert_eq!(
                    commits.load(Ordering::Relaxed),
                    2,
                    "the operation rewritten during the call is committed again, not deleted"
                );
                engine.sync().await.unwrap();
                assert_eq!(
                    commits.load(Ordering::Relaxed),
                    2,
                    "nothing is left pending"
                );
            }));
        })
        .unwrap()
        .join()
        .unwrap();
}
