use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::extract::Request;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade, close_code};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use hasp_proto::base64url;
use hasp_proto::wire::{ErrorCode, SessionToken, WireError};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until, timeout};

use super::app::App;
use super::hub::{Frame, Subscriber, latest_notice, live_session_by_hash};
use super::request::{client_of, failure};
use crate::rate::{RateClass, RateKey};
use crate::store::Store;

#[derive(Deserialize)]
struct ClientFrame {
    t: String,
    token: Option<String>,
}

pub(crate) async fn upgrade<S: Store + 'static>(app: Arc<App<S>>, request: Request) -> Response {
    let (mut parts, _body) = request.into_parts();
    let peer = client_of(
        &parts,
        &app.options.trusted_proxies,
        app.options.client_ip_header.as_ref(),
    );
    let admitted = app.server.limiter.admit(
        RateClass::Socket,
        &RateKey {
            peer,
            subject: None,
        },
        app.server.clock.now(),
    );
    if let Err(limited) = admitted {
        let error = WireError::retry_after(ErrorCode::RateLimited, limited.retry_after);
        return super::request::failure_response(StatusCode::TOO_MANY_REQUESTS, &error);
    }
    let Ok(upgrade) = WebSocketUpgrade::from_request_parts(&mut parts, &()).await else {
        return failure(StatusCode::BAD_REQUEST, ErrorCode::Format);
    };
    let limits = app.options.socket;
    upgrade
        .max_message_size(limits.max_frame)
        .max_frame_size(limits.max_frame)
        .on_upgrade(move |socket| session(app, socket))
        .into_response()
}

async fn close(mut socket: WebSocket, code: u16, reason: &'static str) {
    let frame = CloseFrame {
        code,
        reason: reason.into(),
    };
    let _sent = socket.send(Message::Close(Some(frame))).await;
}

async fn text(socket: &mut WebSocket, value: &serde_json::Value) -> bool {
    socket
        .send(Message::Text(value.to_string().into()))
        .await
        .is_ok()
}

async fn authenticate<S: Store + 'static>(
    app: &Arc<App<S>>,
    socket: &mut WebSocket,
) -> Option<Subscriber> {
    let first = timeout(app.options.socket.auth_timeout, socket.recv())
        .await
        .ok()??
        .ok()?;
    let Message::Text(raw) = first else {
        return None;
    };
    let frame: ClientFrame = serde_json::from_str(raw.as_str()).ok()?;
    if frame.t != "auth" {
        return None;
    }
    let bytes = base64url::decode_array::<{ hasp_proto::wire::SESSION_TOKEN_LEN }>(&frame.token?)?;
    let hash = SessionToken::from_bytes(bytes).hash();
    let now = app.server.clock.now();
    let worker = Arc::clone(app);
    app.blocking(app.options.request_timeout, move || {
        worker
            .server
            .with_store(|store| {
                let row = live_session_by_hash(store, &hash, now)?;
                Some(Subscriber {
                    session: row.session_id,
                    account: row.account_id,
                    last_notice: latest_notice(store, &row.account_id),
                })
            })
            .ok()
            .flatten()
    })
    .await
    .ok()
    .flatten()
}

async fn session<S: Store + 'static>(app: Arc<App<S>>, mut socket: WebSocket) {
    let Some(who) = authenticate(&app, &mut socket).await else {
        close(socket, close_code::POLICY, "auth").await;
        return;
    };
    let limits = app.options.socket;
    let Some(mut registration) = app.hub.register(who, limits.max_per_session, limits.queue) else {
        close(socket, close_code::POLICY, "too many sockets").await;
        return;
    };
    let mut stopped = app.stop_signal();
    let mut idle = deadline(limits.idle_timeout);
    let mut window = Instant::now();
    let mut received = 0_u32;
    loop {
        tokio::select! {
            frame = registration.rx.recv() => match frame {
                Some(Frame::Hint { vault, seq }) => {
                    let sent = text(&mut socket, &json!({"t": "hint", "vault": base64url::encode(vault.as_bytes()), "seq": seq})).await;
                    if !sent { break; }
                }
                Some(Frame::Notice) => {
                    if !text(&mut socket, &json!({"t": "notice"})).await { break; }
                }
                Some(Frame::Revoked) => {
                    let _sent = text(&mut socket, &json!({"t": "session_revoked"})).await;
                    app.hub.unregister(registration.id);
                    close(socket, close_code::NORMAL, "revoked").await;
                    return;
                }
                None => {
                    close(socket, close_code::AGAIN, "closed").await;
                    return;
                }
            },
            message = socket.recv() => {
                if window.elapsed() >= limits.message_window {
                    window = Instant::now();
                    received = 0;
                }
                received = received.saturating_add(1);
                if received > limits.max_messages {
                    app.hub.unregister(registration.id);
                    close(socket, close_code::POLICY, "too many messages").await;
                    return;
                }
                match message {
                Some(Ok(Message::Text(raw))) => {
                    idle = deadline(limits.idle_timeout);
                    let ping = serde_json::from_str::<ClientFrame>(raw.as_str()).is_ok_and(|frame| frame.t == "ping");
                    if ping && !text(&mut socket, &json!({"t": "pong"})).await { break; }
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                    idle = deadline(limits.idle_timeout);
                }
                Some(Ok(Message::Binary(_))) => {
                    app.hub.unregister(registration.id);
                    close(socket, close_code::UNSUPPORTED, "text only").await;
                    return;
                }
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                }
            },
            () = sleep_until(idle) => {
                app.hub.unregister(registration.id);
                close(socket, close_code::NORMAL, "idle").await;
                return;
            }
            () = wait_stop(&mut stopped) => {
                app.hub.unregister(registration.id);
                close(socket, close_code::AWAY, "shutdown").await;
                return;
            }
        }
    }
    app.hub.unregister(registration.id);
}

async fn wait_stop(stopped: &mut watch::Receiver<bool>) {
    let _seen = stopped.wait_for(|stop| *stop).await;
}

fn deadline(after: std::time::Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(after).unwrap_or(now)
}
