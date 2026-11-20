use super::*;

struct Live {
    api: Api,
    url: String,
    stop: tokio::sync::oneshot::Sender<()>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Live {
    fn start(options: HttpOptions, harness: Harness) -> Self {
        let api = Api::with(options, harness);
        let listener = api
            .rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
        let (stop, signal) = tokio::sync::oneshot::channel::<()>();
        let gateway = api.gateway.clone();
        let server = api.rt.spawn(async move {
            gateway
                .run(listener, async move {
                    let _fired = signal.await;
                })
                .await
        });
        Self {
            api,
            url,
            stop,
            server,
        }
    }
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn open(url: &str) -> Socket {
    tokio_tungstenite::connect_async(url).await.unwrap().0
}

async fn authed(url: &str, token: &SessionToken) -> Socket {
    let mut socket = open(url).await;
    let frame = serde_json::json!({"t": "auth", "token": base64url::encode(token.as_bytes())});
    socket.send(Message::text(frame.to_string())).await.unwrap();
    socket.send(Message::text(r#"{"t":"ping"}"#)).await.unwrap();
    let pong = next_text(&mut socket).await;
    assert_eq!(pong["t"], "pong");
    socket
}

async fn next_text(socket: &mut Socket) -> serde_json::Value {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("frame in time")
            .expect("open")
            .expect("frame");
        match message {
            Message::Text(text) => return serde_json::from_str(text.as_str()).unwrap(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
}

async fn closed_with(socket: &mut Socket) -> u16 {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("close in time")
        {
            Some(Ok(Message::Close(Some(frame)))) => return frame.code.into(),
            Some(Ok(Message::Text(_) | Message::Ping(_) | Message::Pong(_))) => {}
            Some(Ok(other)) => panic!("unexpected {other:?}"),
            Some(Err(_)) | None => return 0,
        }
    }
}

#[test]
fn a_commit_sends_a_content_free_hint_to_every_member_socket() {
    let mut h = Harness::new().direct();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let carol = h.signup("carol");
    let mut model = shared_vault(&h, &alice);
    add_member(&h, &alice, &bob, &mut model);
    let live = Live::start(HttpOptions::default(), h);
    live.api.rt.block_on(async {
        let mut bob_socket = authed(&live.url, &bob.token).await;
        let mut alice_socket = authed(&live.url, &alice.token).await;
        let mut carol_socket = authed(&live.url, &carol.token).await;
        let commit = model.commit(model.clone().put_item(&alice.person, 1, b"secret"));
        live.api.ok_async(&alice.token, &commit).await;
        for socket in [&mut bob_socket, &mut alice_socket] {
            let hint = next_text(socket).await;
            assert_eq!(hint["t"], "hint");
            assert_eq!(hint["vault"], base64url::encode(model.id.as_bytes()));
            assert_eq!(hint["seq"], 3);
            assert_eq!(hint.as_object().unwrap().len(), 3);
        }
        carol_socket
            .send(Message::text(r#"{"t":"ping"}"#))
            .await
            .unwrap();
        assert_eq!(next_text(&mut carol_socket).await["t"], "pong");
    });
    live.stop.send(()).unwrap();
    live.api.rt.block_on(live.server).unwrap().unwrap();
}

#[test]
fn notices_and_revocation_reach_sockets() {
    let mut h = Harness::new().direct();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let mut model = shared_vault(&h, &alice);
    add_member(&h, &alice, &bob, &mut model);
    let (second_id, second_token) = h.try_login(&alice.person).unwrap();
    let live = Live::start(HttpOptions::default(), h);
    live.api.rt.block_on(async {
        let mut alice_socket = authed(&live.url, &alice.token).await;
        let mut second = authed(&live.url, &second_token).await;
        let leave = Signed::sign(
            SigLabel::Leave,
            &LeaveRequest {
                vault_id: model.id,
                account_id: bob.person.account_id,
                rver: Rver::new(model.rver).unwrap(),
                epoch: Epoch::new(model.epoch).unwrap(),
            },
            &bob.person.signing,
        )
        .unwrap();
        live.api
            .ok_async(&bob.token, &Leave { request: leave })
            .await;
        assert_eq!(next_text(&mut alice_socket).await["t"], "notice");
        assert_eq!(next_text(&mut second).await["t"], "notice");

        live.api
            .ok_async(
                &alice.token,
                &SessionRevoke {
                    session_id: second_id,
                },
            )
            .await;
        assert_eq!(next_text(&mut second).await["t"], "session_revoked");
        assert_eq!(closed_with(&mut second).await, 1000);
        alice_socket
            .send(Message::text(r#"{"t":"ping"}"#))
            .await
            .unwrap();
        assert_eq!(next_text(&mut alice_socket).await["t"], "pong");
    });
    live.stop.send(()).unwrap();
    live.api.rt.block_on(live.server).unwrap().unwrap();
}

#[test]
fn sockets_need_a_valid_first_frame() {
    let mut h = Harness::new().direct();
    let alice = h.signup("alice");
    let options = HttpOptions {
        socket: SocketOptions {
            auth_timeout: Duration::from_millis(300),
            ..SocketOptions::default()
        },
        ..HttpOptions::default()
    };
    let live = Live::start(options, h);
    live.api.rt.block_on(async {
        let mut wrong = open(&live.url).await;
        let bad = serde_json::json!({"t": "auth", "token": base64url::encode(&[1; 32])});
        wrong.send(Message::text(bad.to_string())).await.unwrap();
        assert_eq!(closed_with(&mut wrong).await, 1008);

        let mut not_auth = open(&live.url).await;
        not_auth
            .send(Message::text(r#"{"t":"ping"}"#))
            .await
            .unwrap();
        assert_eq!(closed_with(&mut not_auth).await, 1008);

        let mut silent = open(&live.url).await;
        assert_eq!(closed_with(&mut silent).await, 1008);

        let mut ok = authed(&live.url, &alice.token).await;
        ok.close(None).await.unwrap();
    });
    live.stop.send(()).unwrap();
    live.api.rt.block_on(live.server).unwrap().unwrap();
}

#[test]
fn a_session_may_hold_five_sockets_and_idle_ones_close() {
    let mut h = Harness::new().direct();
    let alice = h.signup("alice");
    let options = HttpOptions {
        socket: SocketOptions {
            idle_timeout: Duration::from_millis(400),
            ..SocketOptions::default()
        },
        ..HttpOptions::default()
    };
    let live = Live::start(options, h);
    live.api.rt.block_on(async {
        let mut held = Vec::new();
        for _ in 0..5 {
            held.push(authed(&live.url, &alice.token).await);
        }
        let mut sixth = open(&live.url).await;
        let frame =
            serde_json::json!({"t": "auth", "token": base64url::encode(alice.token.as_bytes())});
        sixth.send(Message::text(frame.to_string())).await.unwrap();
        assert_eq!(closed_with(&mut sixth).await, 1008);
        for socket in &mut held {
            assert_eq!(closed_with(socket).await, 1000);
        }
    });
    live.stop.send(()).unwrap();
    live.api.rt.block_on(live.server).unwrap().unwrap();
}

#[test]
fn socket_connects_are_rate_limited_per_ip() {
    let mut h = Harness::with_limiter(Arc::new(WindowLimiter::new(Limits {
        socket_per_peer: 2,
        ..Limits::default()
    })))
    .direct();
    let alice = h.signup("alice");
    let live = Live::start(HttpOptions::default(), h);
    live.api.rt.block_on(async {
        let _first = authed(&live.url, &alice.token).await;
        let _second = authed(&live.url, &alice.token).await;
        let refused = tokio_tungstenite::connect_async(&live.url)
            .await
            .unwrap_err();
        match refused {
            tokio_tungstenite::tungstenite::Error::Http(response) => {
                assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            }
            other => panic!("unexpected {other:?}"),
        }
    });
    live.stop.send(()).unwrap();
    live.api.rt.block_on(live.server).unwrap().unwrap();
}

#[test]
fn shutdown_closes_sockets_and_returns() {
    let mut h = Harness::new().direct();
    let alice = h.signup("alice");
    let live = Live::start(HttpOptions::default(), h);
    live.api.rt.block_on(async {
        let mut socket = authed(&live.url, &alice.token).await;
        live.stop.send(()).unwrap();
        assert_eq!(closed_with(&mut socket).await, 1001);
        tokio::time::timeout(Duration::from_secs(5), live.server)
            .await
            .expect("server stops")
            .unwrap()
            .unwrap();
    });
}

#[test]
fn a_slow_socket_is_dropped_when_its_queue_overflows() {
    let mut h = Harness::new().direct();
    let alice = h.signup("alice");
    let model = shared_vault(&h, &alice);
    let hub = crate::http::hub::Hub::default();
    let who = crate::http::hub::Subscriber {
        session: alice.session_id,
        account: alice.person.account_id,
        last_notice: 0,
    };
    let mut registration = hub.register(who, 5, 1).unwrap();
    hub.reconcile(&h.server, &[model.id]);
    hub.reconcile(&h.server, &[model.id]);
    assert!(matches!(
        registration.rx.try_recv(),
        Ok(crate::http::hub::Frame::Hint { .. })
    ));
    assert!(registration.rx.try_recv().is_err());
    assert!(hub.register(who, 5, 1).is_some());
    let _ = Health {};
}

#[test]
fn a_socket_that_floods_messages_is_closed() {
    let mut h = Harness::new().direct();
    let alice = h.signup("alice");
    let options = HttpOptions {
        socket: SocketOptions {
            max_messages: 5,
            ..SocketOptions::default()
        },
        ..HttpOptions::default()
    };
    let live = Live::start(options, h);
    live.api.rt.block_on(async {
        let mut socket = authed(&live.url, &alice.token).await;
        for _ in 0..20 {
            if socket.send(Message::text(r#"{"t":"ping"}"#)).await.is_err() {
                break;
            }
        }
        assert_eq!(closed_with(&mut socket).await, 1008);
    });
    live.stop.send(()).unwrap();
    live.api.rt.block_on(live.server).unwrap().unwrap();
}
