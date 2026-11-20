use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{ConnectInfo, Request};
use axum::http::header::{ALLOW, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, RETRY_AFTER};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::Response;
use hasp_proto::wire::{
    Ack, ErrorCode, OpId, PROTOCOL_VERSION, SessionToken, WireError, encode_reply,
};
use hasp_proto::{ProtoError, Reader, VaultId};
use http_body_util::BodyExt;

use super::app::App;
use super::identity::{Cidr, client_ip, header_client_ip};
use super::peer_gate::PeerPermit;
use super::routes::{self, RouteSpec};
use crate::server::Caller;
use crate::store::Store;

const CBOR: HeaderValue = HeaderValue::from_static("application/cbor");
const X_PROTOCOL: HeaderName = HeaderName::from_static("x-protocol");
const X_PROTOCOL_MIN: HeaderName = HeaderName::from_static("x-protocol-min");
const X_PROTOCOL_MAX: HeaderName = HeaderName::from_static("x-protocol-max");
const X_METHOD_OVERRIDE: HeaderName = HeaderName::from_static("x-http-method-override");
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

pub(crate) fn failure(status: StatusCode, code: ErrorCode) -> Response {
    failure_response(status, &WireError::new(code))
}

pub(crate) fn failure_response(status: StatusCode, error: &WireError) -> Response {
    let body = encode_reply::<Ack>(&Err(*error)).unwrap_or_default();
    let mut response = reply_response(status, body);
    if let Some(after) = error.retry_after
        && let Ok(value) = HeaderValue::from_str(&after.get().to_string())
    {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
}

fn reply_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(CONTENT_TYPE, CBOR);
    response
}

fn status_of(code: ErrorCode) -> StatusCode {
    StatusCode::from_u16(code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

pub(crate) fn peer_of(parts: &Parts) -> Option<IpAddr> {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip())
}

pub(crate) fn client_of(
    parts: &Parts,
    trusted: &[Cidr],
    header: Option<&HeaderName>,
) -> Option<IpAddr> {
    if let Some(header) = header {
        let values: Vec<&str> = parts
            .headers
            .get_all(header)
            .iter()
            .map(|value| value.to_str().unwrap_or("invalid"))
            .collect();
        return peer_of(parts).map(|peer| header_client_ip(peer, &values, trusted));
    }
    let lines: Vec<&str> = parts
        .headers
        .get_all(X_FORWARDED_FOR)
        .iter()
        .map(|value| value.to_str().unwrap_or("invalid"))
        .collect();
    let joined = (!lines.is_empty()).then(|| lines.join(","));
    peer_of(parts).map(|peer| client_ip(peer, joined.as_deref(), trusted))
}

fn effective_method(parts: &Parts) -> Method {
    if parts.method != Method::POST {
        return parts.method.clone();
    }
    parts
        .headers
        .get(X_METHOD_OVERRIDE)
        .and_then(|value| Method::from_bytes(value.as_bytes()).ok())
        .unwrap_or(Method::POST)
}

fn bearer(headers: &HeaderMap) -> Option<SessionToken> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let text = value.strip_prefix("Bearer ")?;
    hasp_proto::base64url::decode_array::<{ hasp_proto::wire::SESSION_TOKEN_LEN }>(text.trim())
        .map(SessionToken::from_bytes)
}

fn protocol_mismatch(headers: &HeaderMap) -> bool {
    headers.get(X_PROTOCOL).is_some_and(|value| {
        value
            .to_str()
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
            != Some(PROTOCOL_VERSION)
    })
}

fn unsupported_protocol() -> Response {
    let mut response = failure(StatusCode::UPGRADE_REQUIRED, ErrorCode::Unsupported);
    let version = HeaderValue::from(PROTOCOL_VERSION);
    response
        .headers_mut()
        .insert(X_PROTOCOL_MIN, version.clone());
    response.headers_mut().insert(X_PROTOCOL_MAX, version);
    response
}

fn declared_length(headers: &HeaderMap) -> Option<usize> {
    headers
        .get(CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse::<usize>()
        .ok()
}

async fn read_body(
    headers: &HeaderMap,
    mut body: Body,
    limit: usize,
    within: Duration,
    idle: Duration,
) -> Result<Vec<u8>, Box<Response>> {
    if declared_length(headers).is_some_and(|length| length > limit) {
        return Err(Box::new(failure(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::TooLarge,
        )));
    }
    let started = Instant::now();
    let mut bytes = Vec::with_capacity(declared_length(headers).unwrap_or(0).min(limit));
    loop {
        let wait = idle.min(within.saturating_sub(started.elapsed()));
        let frame = match tokio::time::timeout(wait, body.frame()).await {
            Ok(Some(Ok(frame))) => frame,
            Ok(Some(Err(_))) => {
                return Err(Box::new(failure(
                    StatusCode::BAD_REQUEST,
                    ErrorCode::Format,
                )));
            }
            Ok(None) => return Ok(bytes),
            Err(_) => {
                return Err(Box::new(failure(
                    StatusCode::REQUEST_TIMEOUT,
                    ErrorCode::Internal,
                )));
            }
        };
        if let Ok(data) = frame.into_data() {
            if bytes.len().saturating_add(data.len()) > limit {
                return Err(Box::new(failure(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    ErrorCode::TooLarge,
                )));
            }
            bytes.extend_from_slice(&data);
        }
    }
}

pub(crate) fn inspect(reply: &[u8]) -> Option<WireError> {
    let mut reader = Reader::new(reply);
    reader
        .map(|r, _| {
            r.key(0)?;
            match r.uint()?.get() {
                0 => Ok(None),
                1 => Ok(Some(r.field::<WireError>(1)?)),
                _ => Err(ProtoError::Format),
            }
        })
        .ok()
        .flatten()
}

fn target_vault(op: OpId, body: &[u8]) -> Option<VaultId> {
    if !matches!(op, OpId::Commit | OpId::RepairPublish) {
        return None;
    }
    Reader::new(body).map(|r, _| r.field::<VaultId>(0)).ok()
}

fn is_read_only(op: OpId) -> bool {
    matches!(
        op,
        OpId::Health
            | OpId::ServerKey
            | OpId::Prelogin
            | OpId::RecoverPrelogin
            | OpId::RegisterStart
            | OpId::ReregisterStart
            | OpId::LoginStart
            | OpId::ReauthStart
            | OpId::AccountGet
            | OpId::AccountLookup
            | OpId::ChangeCredentialStart
            | OpId::SessionList
            | OpId::EnrolMsgGet
            | OpId::Pull
            | OpId::InviteGet
            | OpId::InviteList
            | OpId::AttachmentGet
            | OpId::AdminAccountList
            | OpId::RecoverRegisterStart
    )
}

struct Admission {
    _peer: PeerPermit,
    _bytes: tokio::sync::OwnedSemaphorePermit,
    _transfer: Option<tokio::sync::OwnedSemaphorePermit>,
}

async fn admit_request<S: Store + 'static>(
    app: &Arc<App<S>>,
    op: OpId,
    parts: &Parts,
    reserve: usize,
) -> Result<Admission, Box<Response>> {
    let client = client_of(
        parts,
        &app.options.trusted_proxies,
        app.options.client_ip_header.as_ref(),
    );
    let Some(peer) = app.peers.enter(client, reserve) else {
        return Err(Box::new(busy()));
    };
    let Some(bytes) = u32::try_from(reserve)
        .ok()
        .and_then(|n| Arc::clone(&app.inflight).try_acquire_many_owned(n).ok())
    else {
        return Err(Box::new(busy()));
    };
    let transfer = if routes::is_chunk_transfer(op) {
        match Arc::clone(&app.transfers).try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => return Err(Box::new(busy())),
        }
    } else {
        None
    };
    if let Some(recovery) = routes::early_bearer(op) {
        let denied = || Box::new(failure(status_of(ErrorCode::Auth), ErrorCode::Auth));
        let Some(presented) = bearer(&parts.headers) else {
            return Err(denied());
        };
        let server = Arc::clone(&app.server);
        let live = app
            .blocking(app.options.request_timeout, move || {
                server.bearer_live(&presented, recovery)
            })
            .await?;
        if !live {
            return Err(denied());
        }
    }
    Ok(Admission {
        _peer: peer,
        _bytes: bytes,
        _transfer: transfer,
    })
}

pub(super) async fn serve_operation<S: Store + 'static>(
    app: Arc<App<S>>,
    spec: &'static RouteSpec,
    request: Request,
) -> Response {
    let started = Instant::now();
    let (parts, body) = request.into_parts();
    let Some(op) = spec.op_for(&effective_method(&parts)) else {
        return method_not_allowed(spec);
    };
    if protocol_mismatch(&parts.headers) {
        return unsupported_protocol();
    }
    let within = if routes::is_long(op) {
        app.options.transfer_timeout
    } else {
        app.options.request_timeout
    };
    let limit = routes::body_limit(op);
    let declared = declared_length(&parts.headers);
    if declared.is_some_and(|length| length > limit) {
        return failure(StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::TooLarge);
    }
    let reserve = declared.unwrap_or(limit).max(1);
    let _admission = match admit_request(&app, op, &parts, reserve).await {
        Ok(admission) => admission,
        Err(response) => return *response,
    };
    let caller = Caller {
        token: bearer(&parts.headers),
        peer: client_of(
            &parts,
            &app.options.trusted_proxies,
            app.options.client_ip_header.as_ref(),
        ),
    };
    let idle = app.options.body_idle_timeout;
    let bytes = match read_body(&parts.headers, body, limit, within, idle).await {
        Ok(bytes) => bytes,
        Err(response) => return *response,
    };
    let body = if bytes.is_empty() { vec![0xa0] } else { bytes };
    let worker = Arc::clone(&app);
    let reply = match app
        .blocking(within, move || run_operation(&worker, &caller, op, &body))
        .await
    {
        Ok(reply) => reply,
        Err(response) => return *response,
    };
    answer(op, reply, started)
}

fn method_not_allowed(spec: &RouteSpec) -> Response {
    let mut response = failure(StatusCode::METHOD_NOT_ALLOWED, ErrorCode::Format);
    let allowed: Vec<&str> = spec
        .methods
        .iter()
        .map(|(method, _)| method.as_str())
        .collect();
    if let Ok(value) = HeaderValue::from_str(&allowed.join(", ")) {
        response.headers_mut().insert(ALLOW, value);
    }
    response
}

fn answer(op: OpId, reply: Vec<u8>, started: Instant) -> Response {
    let failure_of = inspect(&reply);
    let (status, retry_after) = match &failure_of {
        None => (StatusCode::OK, None),
        Some(error) if op == OpId::Health && error.code == ErrorCode::Internal => {
            (StatusCode::SERVICE_UNAVAILABLE, error.retry_after)
        }
        Some(error) => (status_of(error.code), error.retry_after),
    };
    tracing::info!(
        op = routes::name(op),
        status = status.as_u16(),
        code = failure_of.map_or("ok", |error| error.code.name()),
        ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "request"
    );
    let mut response = reply_response(status, reply);
    if let Some(after) = retry_after
        && let Ok(value) = HeaderValue::from_str(&after.get().to_string())
    {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
}

fn run_operation<S: Store + 'static>(
    app: &App<S>,
    caller: &Caller,
    op: OpId,
    body: &[u8],
) -> Vec<u8> {
    if op == OpId::Health && !app.server.writable() {
        return encode_reply::<Ack>(&Err(WireError::new(ErrorCode::Internal))).unwrap_or_default();
    }
    let reply = app.server.handle(caller, op, body);
    if !is_read_only(op) && inspect(&reply).is_none() {
        let vaults: Vec<VaultId> = target_vault(op, body).into_iter().collect();
        app.hub.reconcile(&app.server, &vaults);
    }
    reply
}

pub(super) fn busy() -> Response {
    failure_response(
        StatusCode::TOO_MANY_REQUESTS,
        &WireError::retry_after(ErrorCode::RateLimited, 1),
    )
}
