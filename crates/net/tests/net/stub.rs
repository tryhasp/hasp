use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use hasp_net::{HttpTransport, NetConfig, Origin, RetryPolicy};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub(crate) enum Reply {
    Raw {
        status: u16,
        content_type: Option<&'static str>,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    },
    Hang,
}

impl Reply {
    pub(crate) fn status(status: u16) -> Self {
        Self::Raw {
            status,
            content_type: None,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub(crate) fn cbor(status: u16, body: Vec<u8>) -> Self {
        Self::Raw {
            status,
            content_type: Some("application/cbor"),
            headers: Vec::new(),
            body,
        }
    }

    pub(crate) fn with_header(mut self, name: &'static str, value: &str) -> Self {
        if let Self::Raw { headers, .. } = &mut self {
            headers.push((name, value.to_owned()));
        }
        self
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Seen {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Vec<u8>,
}

#[derive(Default)]
struct Script {
    replies: Mutex<VecDeque<Reply>>,
    fallback: Mutex<Option<Reply>>,
    seen: Mutex<Vec<Seen>>,
    hits: AtomicUsize,
    sockets: AtomicUsize,
    socket_mode: Mutex<SocketMode>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) enum SocketMode {
    #[default]
    HintThenClose,
    Silent,
}

pub(crate) struct Stub {
    pub(crate) addr: SocketAddr,
    script: Arc<Script>,
    task: JoinHandle<()>,
}

impl Stub {
    pub(crate) async fn start() -> Self {
        let script = Arc::new(Script::default());
        let router = Router::new()
            .route("/v1/ws", axum::routing::any(socket))
            .fallback(handle)
            .with_state(Arc::clone(&script));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _served = axum::serve(listener, router).await;
        });
        Self { addr, script, task }
    }

    pub(crate) fn queue(&self, replies: impl IntoIterator<Item = Reply>) {
        self.script.replies.lock().unwrap().extend(replies);
    }

    pub(crate) fn always(&self, reply: Reply) {
        *self.script.fallback.lock().unwrap() = Some(reply);
    }

    pub(crate) fn socket_mode(&self, mode: SocketMode) {
        *self.script.socket_mode.lock().unwrap() = mode;
    }

    pub(crate) fn hits(&self) -> usize {
        self.script.hits.load(Ordering::SeqCst)
    }

    pub(crate) fn sockets(&self) -> usize {
        self.script.sockets.load(Ordering::SeqCst)
    }

    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.script.seen.lock().unwrap().clone()
    }

    pub(crate) fn origin(&self) -> Origin {
        Origin::parse(&format!("http://{}", self.addr)).unwrap()
    }

    pub(crate) fn transport(&self) -> HttpTransport {
        self.transport_with(|_| {})
    }

    pub(crate) fn transport_with(&self, adjust: impl FnOnce(&mut NetConfig)) -> HttpTransport {
        let mut config = NetConfig::new("hasp-net-test");
        config.retry = RetryPolicy {
            max_attempts: 3,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(4),
        };
        config.request_timeout = Duration::from_millis(300);
        adjust(&mut config);
        HttpTransport::new(self.origin(), config).unwrap()
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle(State(script): State<Arc<Script>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap()
        .to_vec();
    script.hits.fetch_add(1, Ordering::SeqCst);
    script.seen.lock().unwrap().push(Seen {
        method: parts.method.to_string(),
        path: parts.uri.path().to_owned(),
        headers: parts.headers,
        body,
    });
    let next = script.replies.lock().unwrap().pop_front();
    let reply = next
        .or_else(|| script.fallback.lock().unwrap().clone())
        .unwrap_or_else(|| Reply::status(500));
    match reply {
        Reply::Hang => {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Response::new(Body::empty())
        }
        Reply::Raw {
            status,
            content_type,
            headers,
            body,
        } => {
            let mut response = Response::new(Body::from(body));
            *response.status_mut() = StatusCode::from_u16(status).unwrap();
            if let Some(content_type) = content_type {
                response
                    .headers_mut()
                    .insert("content-type", content_type.parse().unwrap());
            }
            for (name, value) in headers {
                response.headers_mut().insert(name, value.parse().unwrap());
            }
            response
        }
    }
}

async fn socket(State(script): State<Arc<Script>>, upgrade: WebSocketUpgrade) -> Response {
    upgrade.on_upgrade(move |socket| serve_socket(script, socket))
}

async fn serve_socket(script: Arc<Script>, mut socket: WebSocket) {
    script.sockets.fetch_add(1, Ordering::SeqCst);
    let mode = *script.socket_mode.lock().unwrap();
    let _auth = socket.recv().await;
    match mode {
        SocketMode::HintThenClose => {
            let vault = "AQEBAQEBAQEBAQEBAQEBAQ";
            let frame = format!(r#"{{"t":"hint","vault":"{vault}","seq":3}}"#);
            let _sent = socket.send(Message::text(frame)).await;
            let _closed = socket.send(Message::Close(None)).await;
        }
        SocketMode::Silent => while socket.recv().await.is_some() {},
    }
}
