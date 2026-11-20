use std::time::Duration;

use hasp_core::transport::{Transport, TransportError};
use hasp_proto::wire::{
    Ack, ErrorCode, Health, HealthResponse, SessionId, SessionRevoke, SessionToken, WireError,
    encode_reply,
};
use hasp_proto::{MAX_RECORD, ProtoError, Uint53};
use tokio::net::TcpListener;

use crate::stub::{Reply, Stub};

fn health() -> HealthResponse {
    HealthResponse {
        min_protocol: Uint53::new(1).unwrap(),
        max_protocol: Uint53::new(1).unwrap(),
        server_version: "test".to_owned(),
        features: Vec::new(),
    }
}

fn ok(status: u16) -> Reply {
    Reply::cbor(status, encode_reply(&Ok(health())).unwrap())
}

fn failure(status: u16, error: WireError) -> Reply {
    Reply::cbor(status, encode_reply::<HealthResponse>(&Err(error)).unwrap())
}

fn revoke() -> SessionRevoke {
    SessionRevoke {
        session_id: SessionId::from_bytes([5; 16]),
    }
}

fn server_error<T>(result: Result<T, TransportError>) -> WireError {
    result
        .err()
        .and_then(|error| match error {
            TransportError::Server(wire) => Some(wire),
            TransportError::Codec(_) | TransportError::Unreachable => None,
        })
        .unwrap()
}

fn is_codec<T>(result: &Result<T, TransportError>) -> bool {
    matches!(result, Err(TransportError::Codec(ProtoError::Format)))
}

#[tokio::test]
async fn a_reply_envelope_decodes_into_the_response() {
    let stub = Stub::start().await;
    stub.queue([ok(200)]);
    let reply = stub.transport().call(None, &Health).await.unwrap();
    assert_eq!(reply, health());
}

#[tokio::test]
async fn a_request_is_a_cbor_post_with_the_protocol_header_and_the_method_override() {
    let stub = Stub::start().await;
    stub.queue([ok(200)]);
    stub.transport().call(None, &Health).await.unwrap();
    let seen = stub.seen().remove(0);
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.path, "/healthz");
    assert_eq!(seen.headers["x-http-method-override"], "GET");
    assert_eq!(seen.headers["content-type"], "application/cbor");
    assert_eq!(seen.headers["accept"], "application/cbor");
    assert_eq!(seen.headers["x-protocol"], "1");
    assert!(seen.headers.get("authorization").is_none());
    assert_eq!(seen.body, [0xa0]);
}

#[tokio::test]
async fn the_session_token_travels_as_unpadded_base64url_and_never_in_the_url() {
    let stub = Stub::start().await;
    stub.queue([Reply::cbor(200, encode_reply(&Ok(Ack)).unwrap())]);
    let token = SessionToken::from_bytes([0xfb; 32]);
    stub.transport()
        .call(Some(&token), &revoke())
        .await
        .unwrap();
    let seen = stub.seen().remove(0);
    let header = seen.headers["authorization"].to_str().unwrap();
    assert_eq!(header, format!("Bearer {}-_s", "-_v7".repeat(10)));
    assert_eq!(seen.headers["x-http-method-override"], "DELETE");
    assert_eq!(seen.path, "/v1/sessions/BQUFBQUFBQUFBQUFBQUFBQ");
    assert!(!seen.path.contains("v7"));
}

#[tokio::test]
async fn every_error_code_in_an_envelope_reaches_the_caller_unchanged() {
    for code in ErrorCode::ALL {
        let stub = Stub::start().await;
        let wire = WireError::retry_after(*code, 3);
        stub.queue([failure(code.http_status(), wire)]);
        let got = server_error(stub.transport().call(None, &Health).await);
        assert_eq!(got, wire, "{code:?}");
    }
}

#[tokio::test]
async fn a_retry_after_header_fills_in_a_rate_limit_without_one() {
    let stub = Stub::start().await;
    stub.queue([
        failure(429, WireError::new(ErrorCode::RateLimited)).with_header("retry-after", "7")
    ]);
    let got = server_error(stub.transport().call(None, &Health).await);
    assert_eq!(got, WireError::retry_after(ErrorCode::RateLimited, 7));
}

#[tokio::test]
async fn a_reply_without_an_envelope_maps_by_status() {
    let table = [
        (401, ErrorCode::Auth),
        (403, ErrorCode::Authz),
        (404, ErrorCode::NotFound),
        (413, ErrorCode::TooLarge),
        (426, ErrorCode::Unsupported),
        (500, ErrorCode::Internal),
    ];
    for (status, code) in table {
        let stub = Stub::start().await;
        stub.queue([Reply::status(status)]);
        let got = server_error(stub.transport().call(None, &Health).await);
        assert_eq!(got, WireError::new(code), "{status}");
    }
    let stub = Stub::start().await;
    stub.queue([Reply::status(429).with_header("retry-after", "7")]);
    let got = server_error(stub.transport().call(None, &Health).await);
    assert_eq!(got, WireError::retry_after(ErrorCode::RateLimited, 7));
}

#[tokio::test]
async fn an_unexpected_status_or_a_malformed_body_is_a_codec_error() {
    for reply in [
        Reply::status(400),
        Reply::status(418),
        Reply::status(200),
        Reply::cbor(200, vec![0xff, 0xff]),
        Reply::cbor(200, vec![0xa0]),
        ok(500),
    ] {
        let stub = Stub::start().await;
        stub.queue([reply.clone()]);
        let result = stub.transport().call(None, &Health).await;
        assert!(is_codec(&result), "{reply:?}");
    }
}

#[tokio::test]
async fn a_non_canonical_envelope_is_refused() {
    let stub = Stub::start().await;
    let mut body = encode_reply(&Ok(health())).unwrap();
    body.push(0);
    stub.queue([Reply::cbor(200, body)]);
    assert!(is_codec(&stub.transport().call(None, &Health).await));
}

#[tokio::test]
async fn a_body_over_the_record_limit_is_refused_without_being_decoded() {
    let stub = Stub::start().await;
    stub.queue([Reply::cbor(200, vec![0xa0; MAX_RECORD + 8192])]);
    assert!(is_codec(&stub.transport().call(None, &Health).await));
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let elsewhere = Stub::start().await;
    elsewhere.always(ok(200));
    let stub = Stub::start().await;
    stub.queue([
        Reply::status(302).with_header("location", &format!("http://{}/healthz", elsewhere.addr))
    ]);
    assert!(is_codec(&stub.transport().call(None, &Health).await));
    assert_eq!(elsewhere.hits(), 0);
}

#[tokio::test]
async fn an_idempotent_read_retries_a_gateway_failure_and_then_succeeds() {
    let stub = Stub::start().await;
    stub.queue([Reply::status(503), Reply::status(502), ok(200)]);
    let reply = stub.transport().call(None, &Health).await.unwrap();
    assert_eq!(reply, health());
    assert_eq!(stub.hits(), 3);
}

#[tokio::test]
async fn retries_stop_at_the_attempt_limit_and_report_unreachable() {
    let stub = Stub::start().await;
    stub.always(Reply::status(503));
    let result = stub.transport().call(None, &Health).await;
    assert!(
        matches!(result, Err(TransportError::Unreachable)),
        "{result:?}"
    );
    assert_eq!(stub.hits(), 3);
}

#[tokio::test]
async fn a_write_that_is_not_idempotent_is_sent_once() {
    let stub = Stub::start().await;
    stub.always(Reply::status(503));
    let token = SessionToken::from_bytes([1; 32]);
    let result = stub.transport().call(Some(&token), &revoke()).await;
    assert!(
        matches!(result, Err(TransportError::Unreachable)),
        "{result:?}"
    );
    assert_eq!(stub.hits(), 1);
}

#[tokio::test]
async fn a_server_answer_with_an_envelope_is_final_even_on_a_503() {
    let stub = Stub::start().await;
    stub.always(failure(503, WireError::new(ErrorCode::Internal)));
    let got = server_error(stub.transport().call(None, &Health).await);
    assert_eq!(got, WireError::new(ErrorCode::Internal));
    assert_eq!(stub.hits(), 1);
}

#[tokio::test]
async fn a_server_that_never_answers_times_out_as_unreachable() {
    let stub = Stub::start().await;
    stub.always(Reply::Hang);
    let transport = stub.transport_with(|config| {
        config.request_timeout = Duration::from_millis(80);
    });
    let result = transport.call(None, &Health).await;
    assert!(
        matches!(result, Err(TransportError::Unreachable)),
        "{result:?}"
    );
    assert_eq!(stub.hits(), 3);
}

#[tokio::test]
async fn a_timed_out_write_that_is_not_idempotent_is_not_replayed() {
    let stub = Stub::start().await;
    stub.always(Reply::Hang);
    let transport = stub.transport_with(|config| {
        config.request_timeout = Duration::from_millis(80);
    });
    let token = SessionToken::from_bytes([1; 32]);
    let result = transport.call(Some(&token), &revoke()).await;
    assert!(
        matches!(result, Err(TransportError::Unreachable)),
        "{result:?}"
    );
    assert_eq!(stub.hits(), 1);
}

#[tokio::test]
async fn a_closed_port_is_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let origin = hasp_net::Origin::parse(&format!("http://{addr}")).unwrap();
    let transport = hasp_net::HttpTransport::new(origin, hasp_net::NetConfig::new("test")).unwrap();
    let result = transport.call(None, &Health).await;
    assert!(
        matches!(result, Err(TransportError::Unreachable)),
        "{result:?}"
    );
}

#[tokio::test]
async fn https_to_a_server_without_tls_fails_the_handshake() {
    let stub = Stub::start().await;
    stub.always(ok(200));
    let origin =
        hasp_net::Origin::parse(&format!("https://127.0.0.1:{}", stub.addr.port())).unwrap();
    let transport = hasp_net::HttpTransport::new(origin, hasp_net::NetConfig::new("test")).unwrap();
    let result = transport.call(None, &Health).await;
    assert!(
        matches!(result, Err(TransportError::Unreachable)),
        "{result:?}"
    );
}
