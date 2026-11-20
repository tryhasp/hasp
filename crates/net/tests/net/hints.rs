use std::time::Duration;

use hasp_core::testing::login_item;
use hasp_net::{Hint, HintClient, HintConfig, HintEnd, RetryPolicy, next_wake};
use hasp_proto::VaultId;
use hasp_proto::wire::SessionToken;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::gateway::Live;
use crate::stub::{SocketMode, Stub};

const QUICK: Duration = Duration::from_millis(40);

fn fast() -> HintConfig {
    let mut config = HintConfig::standard();
    config.reconnect = RetryPolicy {
        max_attempts: u32::MAX,
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(5),
    };
    config
}

fn cancel() -> CancellationToken {
    CancellationToken::new()
}

#[tokio::test]
async fn a_commit_on_another_device_wakes_this_one_and_a_sync_picks_it_up() {
    let mut live = Live::start().await;
    let (mut alice, secret_key) = live.signup("alice@example.com").await;
    let mut phone = live.sign_in("alice@example.com", &secret_key).await;
    phone.sync(&cancel()).await.unwrap();
    let private = alice.private_vault().unwrap();
    assert!(phone.items(&private).unwrap().is_empty());

    let hints = HintClient::new(live.origin(), fast()).unwrap();
    let (tx, mut rx) = hints.channel();
    let token = phone.session_token().unwrap();
    let stop = cancel();
    let socket = {
        let stop = stop.clone();
        async move { hints.run(&token, &tx, &stop).await }
    };
    let work = async {
        tokio::time::sleep(QUICK).await;
        alice
            .create_item(&private, &login_item("Bank", "pw"))
            .unwrap();
        alice.sync(&cancel()).await.unwrap();
        let wake = timeout(Duration::from_secs(5), next_wake(&mut rx, QUICK))
            .await
            .unwrap()
            .unwrap();
        assert!(wake.vaults.contains(&private));
        phone.sync(&cancel()).await.unwrap();
        assert_eq!(phone.items(&private).unwrap().len(), 1);
        stop.cancel();
    };
    let (end, ()) = tokio::join!(socket, work);
    assert_eq!(end, HintEnd::Cancelled);
    live.stop().await;
}

#[tokio::test]
async fn the_server_refusing_the_token_ends_the_socket_as_rejected() {
    let live = Live::start().await;
    let hints = HintClient::new(live.origin(), fast()).unwrap();
    let (tx, _rx) = hints.channel();
    let token = SessionToken::from_bytes([9; 32]);
    let end = timeout(Duration::from_secs(5), hints.run(&token, &tx, &cancel()))
        .await
        .unwrap();
    assert_eq!(end, HintEnd::Rejected);
    live.stop().await;
}

#[tokio::test]
async fn revoking_the_session_tells_the_socket_and_stops_it() {
    let mut live = Live::start().await;
    let (mut alice, secret_key) = live.signup("alice@example.com").await;
    let mut phone = live.sign_in("alice@example.com", &secret_key).await;
    phone.sync(&cancel()).await.unwrap();
    let hints = HintClient::new(live.origin(), fast()).unwrap();
    let (tx, mut rx) = hints.channel();
    let token = phone.session_token().unwrap();
    let stop = cancel();
    let socket = hints.run(&token, &tx, &stop);
    let work = async {
        tokio::time::sleep(QUICK).await;
        let listed = alice.devices(&cancel()).await.unwrap();
        let victim = listed.iter().find(|device| !device.current).unwrap();
        alice
            .revoke_device(&victim.session_id, &victim.device_id, &cancel())
            .await
            .unwrap();
    };
    let (end, ()) = tokio::join!(
        async { timeout(Duration::from_secs(5), socket).await.unwrap() },
        work
    );
    assert_eq!(end, HintEnd::SessionRevoked);
    assert_eq!(rx.recv().await, Some(Hint::SessionRevoked));
    live.stop().await;
}

#[tokio::test]
async fn a_dropped_socket_reconnects_and_keeps_delivering() {
    let stub = Stub::start().await;
    let hints = HintClient::new(stub.origin(), fast()).unwrap();
    let (tx, mut rx) = hints.channel();
    let token = SessionToken::from_bytes([1; 32]);
    let stop = cancel();
    let socket = hints.run(&token, &tx, &stop);
    let work = async {
        for _ in 0..3 {
            let hint = timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                hint,
                Hint::Vault {
                    vault: VaultId::from_bytes([1; 16]),
                    seq: 3
                }
            );
        }
        stop.cancel();
    };
    let (end, ()) = tokio::join!(socket, work);
    assert_eq!(end, HintEnd::Cancelled);
    assert!(stub.sockets() >= 3);
}

#[tokio::test]
async fn a_socket_that_goes_silent_is_replaced() {
    let stub = Stub::start().await;
    stub.socket_mode(SocketMode::Silent);
    let mut config = fast();
    config.ping_every = Duration::from_millis(20);
    config.silence_limit = Duration::from_millis(60);
    let hints = HintClient::new(stub.origin(), config).unwrap();
    let (tx, _rx) = hints.channel();
    let token = SessionToken::from_bytes([1; 32]);
    let stop = cancel();
    let socket = hints.run(&token, &tx, &stop);
    let work = async {
        timeout(Duration::from_secs(5), async {
            while stub.sockets() < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        stop.cancel();
    };
    let (end, ()) = tokio::join!(socket, work);
    assert_eq!(end, HintEnd::Cancelled);
}

#[tokio::test]
async fn an_unreachable_server_is_retried_until_cancelled() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let origin = hasp_net::Origin::parse(&format!("http://{addr}")).unwrap();
    let hints = HintClient::new(origin, fast()).unwrap();
    let (tx, _rx) = hints.channel();
    let token = SessionToken::from_bytes([1; 32]);
    let stop = cancel();
    let socket = hints.run(&token, &tx, &stop);
    let work = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        stop.cancel();
    };
    let (end, ()) = tokio::join!(socket, work);
    assert_eq!(end, HintEnd::Cancelled);
}
