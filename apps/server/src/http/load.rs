use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hasp_proto::wire::{OpId, Pull, SessionList, SessionToken};
use hasp_proto::{Uint53, Wire};
use tower::ServiceExt;

use super::app::Gateway;
use super::loopback::request;
use super::options::HttpOptions;
use crate::fixture::{HarnessOf, TestStore};
use crate::store::{
    AccountRow, AttachmentRow, EnrolRow, InviteRow, ItemKey, ItemRow, ManifestRow, MemberRow,
    NoticeRow, OpaqueRow, RecoveryRow, RecoverySessionRow, RosterRow, SessionRow, ShareRow, Store,
    StoreResult, Table, TokenRow, VaultRow,
};
use crate::{SqliteStore, Unlimited};

const COMMIT_DELAY_MS: u64 = 800;

#[derive(Debug)]
struct SlowCommit {
    inner: SqliteStore,
    delay_ms: Arc<AtomicU64>,
}

impl TestStore for SlowCommit {
    fn fresh() -> (Self, Box<dyn std::any::Any + Send>) {
        let (inner, scratch) = SqliteStore::fresh();
        (
            Self {
                inner,
                delay_ms: Arc::new(AtomicU64::new(0)),
            },
            scratch,
        )
    }
}

macro_rules! delegate {
    ($name:ident, $key:ty, $value:ty) => {
        fn $name(&mut self) -> &mut dyn Table<$key, $value> {
            self.inner.$name()
        }
    };
}

impl Store for SlowCommit {
    fn begin(&mut self) -> StoreResult<()> {
        self.inner.begin()
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "the test holds a blocking-pool thread on purpose"
    )]
    fn commit(&mut self) -> StoreResult<()> {
        std::thread::sleep(Duration::from_millis(self.delay_ms.load(Ordering::SeqCst)));
        self.inner.commit()
    }

    fn rollback(&mut self) -> StoreResult<()> {
        self.inner.rollback()
    }

    delegate!(accounts, hasp_proto::AccountId, AccountRow);
    delegate!(logins, String, hasp_proto::AccountId);
    delegate!(
        account_records,
        (hasp_proto::AccountId, hasp_proto::Seq),
        hasp_proto::Signed<hasp_proto::AccountRecord>
    );
    delegate!(opaque_records, hasp_proto::AccountId, OpaqueRow);
    delegate!(keysets, hasp_proto::AccountId, hasp_proto::Keyset);
    delegate!(signup_tokens, hasp_proto::Hash32, TokenRow);
    delegate!(sessions, hasp_proto::wire::SessionId, SessionRow);
    delegate!(
        session_tokens,
        hasp_proto::Hash32,
        hasp_proto::wire::SessionId
    );
    delegate!(enrol_channels, hasp_proto::Esid, EnrolRow);
    delegate!(
        recovery_enrolments,
        (hasp_proto::AccountId, u64),
        RecoveryRow
    );
    delegate!(
        recovery_sessions,
        hasp_proto::wire::RecoveryId,
        RecoverySessionRow
    );
    delegate!(notices, (hasp_proto::AccountId, u64), NoticeRow);
    delegate!(vaults, hasp_proto::VaultId, VaultRow);
    delegate!(rosters, (hasp_proto::VaultId, hasp_proto::Rver), RosterRow);
    delegate!(
        manifests,
        (hasp_proto::VaultId, hasp_proto::Seq),
        ManifestRow
    );
    delegate!(
        members,
        (hasp_proto::VaultId, hasp_proto::AccountId),
        MemberRow
    );
    delegate!(
        memberships,
        (hasp_proto::AccountId, hasp_proto::VaultId),
        ()
    );
    delegate!(
        shares,
        (
            hasp_proto::VaultId,
            hasp_proto::Epoch,
            hasp_proto::AccountId
        ),
        ShareRow
    );
    delegate!(
        self_wraps,
        (
            hasp_proto::AccountId,
            hasp_proto::VaultId,
            hasp_proto::Epoch
        ),
        hasp_proto::SealedRaw
    );
    delegate!(items, ItemKey, ItemRow);
    delegate!(invites, hasp_proto::InviteId, InviteRow);
    delegate!(attachments, hasp_proto::AttId, AttachmentRow);
    delegate!(attachment_chunks, (hasp_proto::AttId, u64), Arc<Vec<u8>>);
    delegate!(
        commit_log,
        (hasp_proto::VaultId, hasp_proto::Seq),
        hasp_proto::Hash32
    );
}

async fn send(
    gateway: &Gateway<SlowCommit>,
    token: &SessionToken,
    op: OpId,
    body: &[u8],
) -> StatusCode {
    let response = gateway
        .router()
        .oneshot(request(op, Some(token), body, [10, 0, 0, 1]))
        .await
        .unwrap();
    response.status()
}

fn plain_get(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

#[test]
fn a_slow_commit_never_starves_the_async_runtime() {
    let delay = Arc::new(AtomicU64::new(0));
    let (mut store, scratch) = SlowCommit::fresh();
    store.delay_ms = Arc::clone(&delay);
    let mut h = HarnessOf::<SlowCommit>::over(store, scratch, Arc::new(Unlimited));
    let mut alice = h.signup("alice");
    let bundle = alice.vault.put_item(&alice.person, 1, b"data");
    let commit = alice.vault.commit(bundle).to_cbor().unwrap();
    let pull = Pull {
        vaults: Vec::new(),
        notices_after: Uint53::ZERO,
        limit: Uint53::ZERO,
    }
    .to_cbor()
    .unwrap();
    let list = SessionList {}.to_cbor().unwrap();
    let gateway = Gateway::new(Arc::clone(&h.server), HttpOptions::default());
    delay.store(COMMIT_DELAY_MS, Ordering::SeqCst);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let token = alice.token.clone();
    runtime.block_on(async move {
        let started = Instant::now();
        let slow = {
            let (gateway, token) = (gateway.clone(), token.clone());
            tokio::spawn(async move { send(&gateway, &token, OpId::Commit, &commit).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;

        let ticker = tokio::spawn(async move {
            let mut worst = Duration::ZERO;
            let mut mark = Instant::now();
            while mark.duration_since(started) < Duration::from_millis(COMMIT_DELAY_MS) {
                tokio::time::sleep(Duration::from_millis(10)).await;
                worst = worst.max(mark.elapsed());
                mark = Instant::now();
            }
            worst
        });

        let mut unrelated = Vec::new();
        for _ in 0..50 {
            let gateway = gateway.clone();
            unrelated.push(tokio::spawn(async move {
                let begun = Instant::now();
                let response = gateway.router().oneshot(plain_get("/no/such/route")).await;
                (response.unwrap().status(), begun.elapsed())
            }));
        }
        for answer in unrelated {
            let (status, took) = answer.await.unwrap();
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert!(took < Duration::from_millis(250), "{took:?}");
        }

        let mut queued = Vec::new();
        for n in 0..20 {
            let (gateway, token) = (gateway.clone(), token.clone());
            let (op, body) = if n % 2 == 0 {
                (OpId::Pull, pull.clone())
            } else {
                (OpId::SessionList, list.clone())
            };
            queued.push(tokio::spawn(async move {
                send(&gateway, &token, op, &body).await
            }));
        }

        let worst_gap = ticker.await.unwrap();
        assert!(
            worst_gap < Duration::from_millis(250),
            "the runtime stalled for {worst_gap:?} behind a {COMMIT_DELAY_MS} ms commit"
        );
        assert_eq!(slow.await.unwrap(), StatusCode::OK);
        assert!(started.elapsed() >= Duration::from_millis(COMMIT_DELAY_MS));
        for answer in queued {
            assert_eq!(answer.await.unwrap(), StatusCode::OK);
        }
    });
}

#[test]
fn a_saturated_worker_pool_answers_429_instead_of_queueing_without_bound() {
    let delay = Arc::new(AtomicU64::new(0));
    let (mut store, scratch) = SlowCommit::fresh();
    store.delay_ms = Arc::clone(&delay);
    let mut h = HarnessOf::<SlowCommit>::over(store, scratch, Arc::new(Unlimited));
    let mut alice = h.signup("alice");
    let bundle = alice.vault.put_item(&alice.person, 1, b"data");
    let commit = alice.vault.commit(bundle).to_cbor().unwrap();
    let list = SessionList {}.to_cbor().unwrap();
    let options = HttpOptions {
        capacity: super::options::Capacity {
            workers: 1,
            queue_wait: Duration::from_millis(50),
            ..super::options::Capacity::default()
        },
        ..HttpOptions::default()
    };
    let gateway = Gateway::new(Arc::clone(&h.server), options);
    delay.store(COMMIT_DELAY_MS, Ordering::SeqCst);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let token = alice.token.clone();
    runtime.block_on(async move {
        let slow = {
            let (gateway, token) = (gateway.clone(), token.clone());
            tokio::spawn(async move { send(&gateway, &token, OpId::Commit, &commit).await })
        };
        tokio::time::sleep(Duration::from_millis(150)).await;
        let begun = Instant::now();
        let refused = send(&gateway, &token, OpId::SessionList, &list).await;
        assert_eq!(refused, StatusCode::TOO_MANY_REQUESTS);
        assert!(begun.elapsed() < Duration::from_millis(400));
        assert_eq!(slow.await.unwrap(), StatusCode::OK);
        assert_eq!(
            send(&gateway, &token, OpId::SessionList, &list).await,
            StatusCode::OK
        );
    });
}
