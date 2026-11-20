use std::sync::Arc;

use hasp_boundary::SnapshotStore;
use hasp_core::api::{Engine, EngineConfig, LockState, Secret, SignUpRequest};
use hasp_core::platform::{ManualClock, Platform};
use hasp_proto::base64url;
use hasp_testsupport::{InProcess, TEST_ORIGIN, World, block_on};

type Standalone = Engine<InProcess<hasp_server::MemoryStore>, SnapshotStore>;

const PASSWORD: &str = "Caf\u{e9} \u{c5}ngstr\u{f6}m long standalone password";

fn engine(world: &World, store: SnapshotStore) -> Standalone {
    Engine::new(
        world.transport(),
        store,
        Platform::password_only_for_tests(Arc::new(ManualClock::new(1_000_000))),
        EngineConfig::new("chrome"),
    )
    .unwrap()
}

fn forms(text: &str) -> Vec<Vec<u8>> {
    let decomposed: String = hasp_core::normalise_password(text).to_string();
    let mut out = Vec::new();
    for form in [text.to_owned(), decomposed] {
        out.push(form.as_bytes().to_vec());
        out.push(base64url::encode(form.as_bytes()).into_bytes());
        out.push(hasp_crypto::to_hex(form.as_bytes()).into_bytes());
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn the_account_password_never_appears_in_any_blob_the_extension_persists() {
    std::thread::Builder::new()
        .stack_size(32 << 20)
        .spawn(|| {
            block_on(Box::pin(async {
                let world = World::new();
                let code = world.server.issue_bootstrap_token().unwrap().to_text();
                let store = SnapshotStore::new();
                let engine = engine(&world, store.clone());
                let kit = Box::pin(engine.sign_up(SignUpRequest {
                    origin: TEST_ORIGIN.to_owned(),
                    login: "alice".to_owned(),
                    code: Secret::new(code.into_bytes()),
                    password: Secret::new(PASSWORD.as_bytes().to_vec()),
                    server_fingerprint: hasp_proto::format_fingerprint(&world.fingerprint()),
                }))
                .await
                .unwrap();
                let secret_key = kit.secret_key.take();
                engine.lock().await;
                let session = engine
                    .unlock_with_password(Secret::new(PASSWORD.as_bytes().to_vec()))
                    .await
                    .unwrap();
                let blob = session.session_blob.take();

                let persisted = store.export();
                for needle in forms(PASSWORD) {
                    assert!(
                        !contains(&persisted, &needle),
                        "password in the exported store"
                    );
                    assert!(!contains(&blob, &needle), "password in the session blob");
                }
                assert!(
                    !contains(&persisted, &secret_key),
                    "Secret Key in the exported store"
                );
                assert!(
                    !contains(&persisted, &blob[1..]),
                    "session key in the exported store"
                );
                assert!(!contains(&blob, &secret_key));

                engine.lock().await;
                let after_eviction =
                    self::engine(&world, SnapshotStore::restore(&store.export()).unwrap());
                assert_eq!(
                    after_eviction.status().await.unwrap().state,
                    LockState::Locked,
                    "the store alone does not unlock"
                );
                after_eviction
                    .resume_session(Secret::new(blob.clone()))
                    .await
                    .unwrap();
                assert_eq!(
                    after_eviction.status().await.unwrap().state,
                    LockState::Unlocked
                );
                assert!(!contains(&store.export(), &forms(PASSWORD)[0]));

                let again = after_eviction
                    .unlock_with_password(Secret::new(PASSWORD.as_bytes().to_vec()))
                    .await
                    .unwrap();
                assert_eq!(
                    again.session_blob.as_bytes(),
                    blob.as_slice(),
                    "same device and password, same key"
                );
            }));
        })
        .unwrap()
        .join()
        .unwrap();
}
