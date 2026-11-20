use super::*;
use axum::http::HeaderName;

#[test]
fn oversized_bodies_are_refused_with_413_per_route_class() {
    let mut api = Api::new();
    let alice = api.h.signup("alice");
    let cases = [
        (OpId::Prelogin, routes::SMALL_BODY),
        (OpId::RegisterFinish, routes::REGISTER_BODY),
        (OpId::EnrolMsgPut, routes::SLOT_BODY),
        (OpId::AttachmentPut, routes::CHUNK_BODY),
        (OpId::Commit, routes::LARGE_BODY),
    ];
    for (op, limit) in cases {
        let big = vec![0_u8; limit + 1];
        let token = routes::early_bearer(op).map(|_| &alice.token);
        let (status, _, body) = api.raw(request(op, token, &big, [10, 0, 0, 1]));
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{op:?} streamed");
        assert_eq!(
            decode_reply::<Ack>(&body).unwrap().unwrap_err().code,
            ErrorCode::TooLarge
        );

        let mut declared = request(op, None, &[], [10, 0, 0, 1]);
        declared.headers_mut().insert(
            header::CONTENT_LENGTH,
            (limit + 1).to_string().parse().unwrap(),
        );
        let (status, ..) = api.raw(declared);
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{op:?} declared");
    }
    let at_limit = vec![0xff_u8; routes::SMALL_BODY];
    let (status, ..) = api.raw(request(OpId::Prelogin, None, &at_limit, [10, 0, 0, 1]));
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[test]
fn a_body_that_stalls_between_frames_is_cut_off_with_408() {
    let api = Api::with(
        HttpOptions {
            body_idle_timeout: Duration::from_millis(100),
            ..HttpOptions::default()
        },
        Harness::new().direct(),
    );
    let mut stalled = request(OpId::Prelogin, None, &[], [10, 0, 0, 1]);
    let first = futures_util::stream::once(async {
        Ok::<_, std::io::Error>(axum::body::Bytes::from_static(&[0xa0]))
    });
    *stalled.body_mut() = Body::from_stream(first.chain(futures_util::stream::pending()));
    let started = std::time::Instant::now();
    let (status, ..) = api.raw(stalled);
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn login_attempts_are_limited_per_client_ip() {
    let limiter = Arc::new(WindowLimiter::new(Limits::default()));
    let api = Api::with(
        HttpOptions::default(),
        Harness::with_limiter(limiter).direct(),
    );
    let prelogin = hasp_proto::wire::Prelogin {
        login: "nobody".to_owned(),
    };
    for _ in 0..10 {
        assert_eq!(
            api.send_from(None, [198, 51, 100, 1], &prelogin).status,
            StatusCode::OK
        );
    }
    let blocked = api.send_from(None, [198, 51, 100, 1], &prelogin);
    assert_eq!(blocked.status, StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = blocked.headers[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry > 0);
    let error = blocked.result.unwrap_err();
    assert_eq!(error.code, ErrorCode::RateLimited);
    assert_eq!(error.retry_after.unwrap().get(), retry);
    assert_eq!(
        api.send_from(None, [198, 51, 100, 2], &prelogin).status,
        StatusCode::OK
    );
}

#[test]
fn forwarded_for_counts_only_behind_a_trusted_proxy() {
    let options = HttpOptions {
        trusted_proxies: vec![Cidr::parse("172.16.0.0/12").unwrap()],
        ..HttpOptions::default()
    };
    let limiter = Arc::new(WindowLimiter::new(Limits::default()));
    let api = Api::with(options, Harness::with_limiter(limiter).direct());
    let prelogin = hasp_proto::wire::Prelogin {
        login: "nobody".to_owned(),
    }
    .to_cbor()
    .unwrap();
    let hit = |peer: [u8; 4], forwarded: &str| {
        let mut req = request(OpId::Prelogin, None, &prelogin, peer);
        req.headers_mut()
            .insert("x-forwarded-for", forwarded.parse().unwrap());
        api.raw(req).0
    };
    for _ in 0..10 {
        assert_eq!(hit([172, 17, 0, 2], "203.0.113.7"), StatusCode::OK);
    }
    assert_eq!(
        hit([172, 17, 0, 2], "203.0.113.7"),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(hit([172, 17, 0, 2], "203.0.113.8"), StatusCode::OK);
    for i in 0..10 {
        assert_eq!(
            hit([192, 0, 2, 9], &format!("203.0.113.{}", 100 + i)),
            StatusCode::OK
        );
    }
    assert_eq!(
        hit([192, 0, 2, 9], "203.0.113.200"),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[test]
fn session_rate_limit_and_chunk_slots_answer_429() {
    let mut api = Api::with(
        HttpOptions {
            chunk_transfers: 0,
            ..HttpOptions::default()
        },
        Harness::with_limiter(Arc::new(WindowLimiter::new(Limits {
            general_per_subject: 3,
            ..Limits::default()
        })))
        .direct(),
    );
    let alice = api.h.signup("alice");
    let model = shared_vault(&api.h, &alice);
    let get = AttachmentGet {
        vault_id: model.id,
        att_id: AttId::from_bytes([1; 16]),
        index: Uint53::ZERO,
    };
    let (status, code) = error_of(api.send(Some(&alice.token), &get));
    assert_eq!(
        (status, code),
        (StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited)
    );

    let api = Api::with(
        HttpOptions::default(),
        Harness::with_limiter(Arc::new(WindowLimiter::new(Limits {
            general_per_subject: 3,
            ..Limits::default()
        })))
        .direct(),
    );
    let mut api = api;
    let alice = api.h.signup("alice");
    for _ in 0..3 {
        assert_eq!(
            api.send(Some(&alice.token), &SessionList {}).status,
            StatusCode::OK
        );
    }
    let blocked = api.send(Some(&alice.token), &SessionList {});
    assert_eq!(blocked.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(blocked.headers.contains_key(header::RETRY_AFTER));
}

#[test]
fn maintenance_sweeps_expired_sessions() {
    let mut api = Api::new();
    let alice = api.h.signup("alice");
    api.h.clock.advance(200 * 24 * 3600);
    api.rt.block_on(api.gateway.maintain_once());
    let (status, code) = error_of(api.send(Some(&alice.token), &SessionList {}));
    assert_eq!((status, code), (StatusCode::UNAUTHORIZED, ErrorCode::Auth));
}

#[test]
fn a_dead_bearer_is_refused_before_a_large_body_is_read() {
    let api = Api::new();
    let body = vec![0x00_u8; 4096];
    let stranger = SessionToken::from_bytes([7; 32]);
    for op in OpId::ALL {
        if routes::early_bearer(*op).is_none() {
            continue;
        }
        let (status, _, reply) = api.raw(request(*op, Some(&stranger), &body, [10, 0, 0, 1]));
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{op:?}");
        assert_eq!(
            decode_reply::<Ack>(&reply).unwrap().unwrap_err().code,
            ErrorCode::Auth
        );
    }
}

#[test]
fn in_flight_byte_caps_answer_429_globally_and_per_peer() {
    let prelogin = hasp_proto::wire::Prelogin {
        login: "nobody".to_owned(),
    }
    .to_cbor()
    .unwrap();
    for capacity in [
        Capacity {
            inflight_bytes: 1000,
            ..Capacity::default()
        },
        Capacity {
            peer_inflight_bytes: 1000,
            ..Capacity::default()
        },
        Capacity {
            peer_requests: 0,
            ..Capacity::default()
        },
    ] {
        let api = Api::with(
            HttpOptions {
                capacity,
                ..HttpOptions::default()
            },
            Harness::new().direct(),
        );
        let (status, headers, body) =
            api.raw(request(OpId::Prelogin, None, &prelogin, [10, 0, 0, 1]));
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(headers.contains_key(header::RETRY_AFTER));
        assert_eq!(
            decode_reply::<Ack>(&body).unwrap().unwrap_err().code,
            ErrorCode::RateLimited
        );
    }
    let api = Api::new();
    let (status, ..) = api.raw(request(OpId::Prelogin, None, &prelogin, [10, 0, 0, 1]));
    assert_eq!(status, StatusCode::OK);
}

#[test]
fn permits_are_returned_after_each_request() {
    let api = Api::with(
        HttpOptions {
            capacity: Capacity {
                peer_requests: 1,
                inflight_bytes: routes::SMALL_BODY,
                ..Capacity::default()
            },
            ..HttpOptions::default()
        },
        Harness::new().direct(),
    );
    for _ in 0..5 {
        assert_eq!(api.raw(request_for_health()).0, StatusCode::OK);
    }
}

#[test]
fn every_forwarded_for_line_counts_and_the_last_one_wins() {
    let options = HttpOptions {
        trusted_proxies: vec![Cidr::parse("172.16.0.0/12").unwrap()],
        ..HttpOptions::default()
    };
    let api = Api::with(
        options,
        Harness::with_limiter(Arc::new(WindowLimiter::new(Limits::default()))).direct(),
    );
    let prelogin = hasp_proto::wire::Prelogin {
        login: "nobody".to_owned(),
    }
    .to_cbor()
    .unwrap();
    let hit = |first: &str, second: &str| {
        let mut req = request(OpId::Prelogin, None, &prelogin, [172, 17, 0, 2]);
        req.headers_mut()
            .append("x-forwarded-for", first.parse().unwrap());
        req.headers_mut()
            .append("x-forwarded-for", second.parse().unwrap());
        api.raw(req).0
    };
    for i in 0..10 {
        assert_eq!(
            hit(&format!("198.51.100.{i}"), "203.0.113.7"),
            StatusCode::OK
        );
    }
    assert_eq!(
        hit("198.51.100.200", "203.0.113.7"),
        StatusCode::TOO_MANY_REQUESTS
    );
}

fn header_api() -> Api {
    let options = HttpOptions {
        trusted_proxies: vec![Cidr::parse("172.16.0.0/12").unwrap()],
        client_ip_header: Some(HeaderName::from_static("cf-connecting-ip")),
        ..HttpOptions::default()
    };
    Api::with(
        options,
        Harness::with_limiter(Arc::new(WindowLimiter::new(Limits::default()))).direct(),
    )
}

fn header_hit(api: &Api, peer: [u8; 4], lines: &[(&str, &str)]) -> StatusCode {
    let prelogin = hasp_proto::wire::Prelogin {
        login: "nobody".to_owned(),
    }
    .to_cbor()
    .unwrap();
    let mut req = request(OpId::Prelogin, None, &prelogin, peer);
    for (name, value) in lines {
        req.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    api.raw(req).0
}

#[test]
fn configured_header_from_a_trusted_peer_selects_the_bucket() {
    let api = header_api();
    let line = |ip: &'static str| [("cf-connecting-ip", ip), ("x-forwarded-for", "10.9.9.9")];
    for _ in 0..10 {
        assert_eq!(
            header_hit(&api, [172, 17, 0, 2], &line("203.0.113.7")),
            StatusCode::OK
        );
    }
    assert_eq!(
        header_hit(&api, [172, 17, 0, 2], &line("203.0.113.7")),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        header_hit(&api, [172, 17, 0, 2], &line("203.0.113.8")),
        StatusCode::OK
    );
}

#[test]
fn configured_header_is_ignored_from_an_untrusted_peer() {
    let api = header_api();
    for i in 0..10 {
        let forged = format!("203.0.113.{}", 100 + i);
        assert_eq!(
            header_hit(&api, [192, 0, 2, 9], &[("cf-connecting-ip", &forged)]),
            StatusCode::OK
        );
    }
    assert_eq!(
        header_hit(
            &api,
            [192, 0, 2, 9],
            &[("cf-connecting-ip", "203.0.113.200")]
        ),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[test]
fn malformed_configured_header_shares_the_peer_bucket() {
    let api = header_api();
    for i in 0..10 {
        let bad = format!("garbage-{i}");
        assert_eq!(
            header_hit(&api, [172, 17, 0, 2], &[("cf-connecting-ip", &bad)]),
            StatusCode::OK
        );
    }
    assert_eq!(
        header_hit(&api, [172, 17, 0, 2], &[("cf-connecting-ip", "also bad")]),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[test]
fn configured_header_ipv6_clients_share_a_slash_64_bucket() {
    let api = header_api();
    for i in 0..10 {
        let ip = format!("2001:db8:1:2::{i:x}");
        assert_eq!(
            header_hit(&api, [172, 17, 0, 2], &[("cf-connecting-ip", &ip)]),
            StatusCode::OK
        );
    }
    assert_eq!(
        header_hit(
            &api,
            [172, 17, 0, 2],
            &[("cf-connecting-ip", "2001:db8:1:2:ffff::1")]
        ),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        header_hit(
            &api,
            [172, 17, 0, 2],
            &[("cf-connecting-ip", "2001:db8:1:3::1")]
        ),
        StatusCode::OK
    );
}
