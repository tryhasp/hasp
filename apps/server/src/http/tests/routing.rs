use super::*;

#[test]
fn health_answers_on_both_paths_with_the_protocol_range() {
    let api = Api::new();
    for path in ["/healthz", "/.well-known/hasp"] {
        let request = Request::get(path).body(Body::empty()).unwrap();
        let (status, headers, body) = api.raw(request);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE], "application/cbor");
        let health: HealthResponse = decode_reply(&body).unwrap().unwrap();
        assert_eq!(health.min_protocol.get(), PROTOCOL_VERSION);
        assert_eq!(health.max_protocol.get(), PROTOCOL_VERSION);
    }
}

#[test]
fn server_key_is_public_and_matches_the_origin() {
    let api = Api::new();
    let answer = api.send(None, &ServerKey {});
    assert_eq!(answer.status, StatusCode::OK);
    let key = answer.result.unwrap();
    assert_eq!(key.origin, crate::fixture::ORIGIN);
    assert_eq!(key.public_key.as_slice(), api.h.server.server_public_key());
}

#[test]
fn unknown_paths_and_wrong_methods_answer_envelopes() {
    let api = Api::new();
    let (status, _, body) = api.raw(Request::get("/v1/nothing").body(Body::empty()).unwrap());
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        decode_reply::<Ack>(&body).unwrap().unwrap_err().code,
        ErrorCode::NotFound
    );
    let (status, headers, body) =
        api.raw(Request::put("/v1/prelogin").body(Body::empty()).unwrap());
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(headers[header::ALLOW], "POST");
    assert!(decode_reply::<Ack>(&body).unwrap().is_err());
    let (status, ..) = api.raw(Request::delete("/healthz").body(Body::empty()).unwrap());
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

#[test]
fn post_with_method_override_reaches_get_and_delete_routes() {
    let mut api = Api::new();
    let alice = api.h.signup("alice");
    let body = SessionList {}.to_cbor().unwrap();
    let mut get = request(OpId::SessionList, Some(&alice.token), &body, [10, 0, 0, 1]);
    *get.method_mut() = Method::POST;
    get.headers_mut()
        .insert("x-http-method-override", "GET".parse().unwrap());
    let (status, _, reply) = api.raw(get);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        decode_reply::<hasp_proto::wire::SessionListResponse>(&reply)
            .unwrap()
            .unwrap()
            .sessions
            .len(),
        1
    );

    let mut bare = request(OpId::SessionList, Some(&alice.token), &body, [10, 0, 0, 1]);
    *bare.method_mut() = Method::POST;
    let (status, ..) = api.raw(bare);
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);

    let mut delete = request(
        OpId::SessionRevoke,
        Some(&alice.token),
        &SessionRevoke {
            session_id: alice.session_id,
        }
        .to_cbor()
        .unwrap(),
        [10, 0, 0, 1],
    );
    *delete.method_mut() = Method::POST;
    delete
        .headers_mut()
        .insert("x-http-method-override", "DELETE".parse().unwrap());
    let (status, ..) = api.raw(delete);
    assert_eq!(status, StatusCode::OK);
}

#[test]
fn an_empty_body_is_the_empty_message() {
    let mut api = Api::new();
    let alice = api.h.signup("alice");
    let mut request = request(OpId::AccountGet, Some(&alice.token), &[], [10, 0, 0, 1]);
    *request.body_mut() = Body::empty();
    let (status, ..) = api.raw(request);
    assert_eq!(status, StatusCode::OK);
}

#[test]
fn unsupported_protocol_gets_426_with_the_range() {
    let api = Api::new();
    let mut request = request(OpId::Health, None, &[], [10, 0, 0, 1]);
    request
        .headers_mut()
        .insert("x-protocol", "2".parse().unwrap());
    let (status, headers, body) = api.raw(request);
    assert_eq!(status, StatusCode::UPGRADE_REQUIRED);
    assert_eq!(headers["x-protocol-min"], "1");
    assert_eq!(headers["x-protocol-max"], "1");
    assert_eq!(
        decode_reply::<Ack>(&body).unwrap().unwrap_err().code,
        ErrorCode::Unsupported
    );
    let mut ok = request_for_health();
    ok.headers_mut().insert("x-protocol", "1".parse().unwrap());
    assert_eq!(api.raw(ok).0, StatusCode::OK);
}

#[test]
fn garbage_bodies_get_format_on_every_route() {
    let api = Api::new();
    for op in OpId::ALL {
        let (status, headers, body) = api.raw(request(*op, None, &[0xff, 0x00], [10, 0, 0, 1]));
        let (want_status, want_code) = if routes::early_bearer(*op).is_some() {
            (StatusCode::UNAUTHORIZED, ErrorCode::Auth)
        } else {
            (StatusCode::BAD_REQUEST, ErrorCode::Format)
        };
        assert_eq!(status, want_status, "{op:?}");
        assert_eq!(headers[header::CONTENT_TYPE], "application/cbor", "{op:?}");
        let error = decode_reply::<Ack>(&body).unwrap().unwrap_err();
        assert_eq!(error.code, want_code, "{op:?}");
    }
}

#[test]
fn every_route_in_the_table_is_reachable() {
    let api = Api::new();
    for spec in routes::ROUTES {
        for (method, op) in spec.methods {
            let (m, path) = route_of(*op);
            let mut request = Request::builder()
                .method(method.clone())
                .uri(path.clone())
                .body(Body::from(vec![0xff]))
                .unwrap();
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 1))));
            let (status, ..) = api.raw(request);
            assert_ne!(status, StatusCode::NOT_FOUND, "{} {}", method, spec.path);
            assert_ne!(status, StatusCode::METHOD_NOT_ALLOWED, "{m} {path}");
        }
    }
}

#[test]
fn errors_map_to_their_documented_statuses() {
    let mut api = Api::new();
    let alice = api.h.signup("alice");
    let bob = api.h.signup("bob");
    let model = shared_vault(&api.h, &alice);

    let (status, code) = error_of(api.send(None, &AccountGet {}));
    assert_eq!((status, code), (StatusCode::UNAUTHORIZED, ErrorCode::Auth));

    let (status, code) = error_of(api.send(Some(&bob.token), &AdminAccountList {}));
    assert_eq!((status, code), (StatusCode::FORBIDDEN, ErrorCode::Authz));

    let first = model.commit(model.clone().put_item(&alice.person, 1, b"x"));
    api.ok(&alice.token, &first);
    let stale = model.commit(model.clone().put_item(&alice.person, 2, b"z"));
    let (status, code) = error_of(api.send(Some(&alice.token), &stale));
    assert_eq!(code, ErrorCode::StaleHead);
    assert_eq!(status, StatusCode::CONFLICT);

    let foreign = model.commit(model.clone().put_item(&bob.person, 2, b"y"));
    let (status, code) = error_of(api.send(Some(&bob.token), &foreign));
    assert_eq!(
        (status, code),
        (StatusCode::FORBIDDEN, ErrorCode::NotMember)
    );

    let (status, code) = error_of(api.send(
        Some(&alice.token),
        &AttachmentPut {
            vault_id: model.id,
            att_id: AttId::from_bytes([1; 16]),
            index: Uint53::ZERO,
            data: Blob(vec![0; (1 << 20) + 17]),
        },
    ));
    assert_eq!(
        (status, code),
        (StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::TooLarge)
    );

    let (status, code) = error_of(api.send(
        Some(&alice.token),
        &AttachmentGet {
            vault_id: model.id,
            att_id: AttId::from_bytes([9; 16]),
            index: Uint53::ZERO,
        },
    ));
    assert_eq!((status, code), (StatusCode::NOT_FOUND, ErrorCode::NotFound));

    let (status, code) = error_of(api.send(
        Some(&alice.token),
        &AccountDelete {
            account: alice.person.next_record(0, AccountStatus::Deleted),
        },
    ));
    assert_eq!(
        (status, code),
        (StatusCode::UNAUTHORIZED, ErrorCode::ReauthRequired)
    );
}

#[expect(
    clippy::too_many_lines,
    reason = "one table of a valid body per operation"
)]
fn dummy_bodies(person: &mut Person, model: &VaultModel) -> Vec<(OpId, Vec<u8>)> {
    let device = person.device_info("test");
    let esid = Esid::from_bytes([3; 16]);
    let att = AttId::from_bytes([4; 16]);
    let invite = InviteId::from_bytes([5; 16]);
    let blob = || Blob(vec![1, 2, 3]);
    let (_, rc_set) = person.recovery_material();
    let genesis = {
        let mut fresh = VaultModel::new(VaultKind::Shared, person);
        let bundle = fresh.genesis(person);
        fresh.genesis_commit(person, bundle)
    };
    let leave = Signed::sign(
        SigLabel::Leave,
        &LeaveRequest {
            vault_id: model.id,
            account_id: person.account_id,
            rver: Rver::new(1).unwrap(),
            epoch: Epoch::ZERO,
        },
        &person.signing,
    )
    .unwrap();
    let dissolve = Signed::sign(
        SigLabel::Dissolve,
        &Dissolve {
            vault_id: model.id,
            rver: Rver::new(1).unwrap(),
            epoch: Epoch::ZERO,
            seq: hasp_proto::Seq::new(1).unwrap(),
            head: Hash32::from_bytes([0; 32]),
        },
        &person.signing,
    )
    .unwrap();
    let mut out: Vec<(OpId, Vec<u8>)> = Vec::new();
    macro_rules! push {
        ($op:expr, $message:expr) => {
            out.push(($op, $message.to_cbor().unwrap()))
        };
    }
    push!(OpId::ReauthStart, ReauthStart { ke1: blob() });
    push!(
        OpId::ReauthFinish,
        ReauthFinish {
            handle: LoginHandle::from_bytes([0; 16]),
            ke3: blob()
        }
    );
    push!(OpId::AccountGet, AccountGet {});
    push!(
        OpId::AccountLookup,
        AccountLookup {
            login: "someone".to_owned()
        }
    );
    push!(
        OpId::AccountDelete,
        AccountDelete {
            account: person.next_record(0, AccountStatus::Deleted)
        }
    );
    push!(
        OpId::ChangeCredentialStart,
        ChangeCredentialStart { request: blob() }
    );
    push!(
        OpId::ChangeCredentialFinish,
        ChangeCredentialFinish {
            record: blob(),
            keyset: person.keyset(),
            account: None
        }
    );
    push!(OpId::SessionList, SessionList {});
    push!(
        OpId::SessionRevoke,
        SessionRevoke {
            session_id: hasp_proto::wire::SessionId::from_bytes([6; 16])
        }
    );
    push!(OpId::EnrolOpen, EnrolOpen { esid });
    push!(
        OpId::EnrolApprove,
        EnrolApprove {
            esid,
            device: device.clone()
        }
    );
    push!(OpId::RcSet, rc_set.clone());
    push!(OpId::RecoverAbort, RecoverAbort::by_session());
    push!(
        OpId::RecoverRegisterStart,
        RecoverRegisterStart {
            recovery_id: RecoveryId::from_bytes([7; 16]),
            request: blob()
        }
    );
    push!(
        OpId::RecoverComplete,
        RecoverComplete {
            recovery_id: RecoveryId::from_bytes([7; 16]),
            record: blob(),
            keyset: person.keyset(),
            account: rc_set.account.clone(),
            rc: rc_set.rc.clone(),
            rc_wrap: rc_set.rc_wrap.clone(),
            h_auth: rc_set.h_auth,
            device,
        }
    );
    push!(
        OpId::Pull,
        Pull {
            vaults: Vec::new(),
            notices_after: Uint53::ZERO,
            limit: Uint53::ZERO
        }
    );
    push!(OpId::Commit, genesis.clone());
    push!(
        OpId::RepairPublish,
        RepairPublish {
            vault_id: genesis.vault_id,
            bundle: genesis.bundle.clone()
        }
    );
    push!(
        OpId::SelfWrapPut,
        SelfWrapPut {
            vault_id: model.id,
            entry: SelfWrapEntry {
                epoch: Epoch::ZERO,
                wrap: person.self_wrap(model, 0)
            },
        }
    );
    push!(
        OpId::InviteCreate,
        InviteCreate {
            vault_id: model.id,
            role: Role::Editor
        }
    );
    push!(OpId::InviteGet, InviteGet { invite_id: invite });
    push!(OpId::InviteList, InviteList { vault_id: model.id });
    push!(
        OpId::InviteAccept,
        InviteAccept {
            invite_id: invite,
            accept: blob()
        }
    );
    push!(OpId::InviteDecline, InviteDecline { invite_id: invite });
    push!(OpId::Leave, Leave { request: leave });
    push!(OpId::VaultDissolve, VaultDissolve { record: dissolve });
    push!(
        OpId::AttachmentPut,
        AttachmentPut {
            vault_id: model.id,
            att_id: att,
            index: Uint53::ZERO,
            data: blob()
        }
    );
    push!(
        OpId::AttachmentGet,
        AttachmentGet {
            vault_id: model.id,
            att_id: att,
            index: Uint53::ZERO
        }
    );
    push!(
        OpId::AttachmentComplete,
        AttachmentComplete {
            vault_id: model.id,
            att_id: att,
            chunks: Uint53::new(1).unwrap()
        }
    );
    push!(
        OpId::AdminTokenCreate,
        AdminTokenCreate {
            kind: TokenKind::Signup
        }
    );
    push!(OpId::AdminAccountList, AdminAccountList {});
    push!(
        OpId::AdminAccountUpdate,
        AdminAccountUpdate {
            account_id: person.account_id,
            disabled: false,
            is_admin: false
        }
    );
    push!(
        OpId::AdminAccountDelete,
        AdminAccountDelete {
            account_id: person.account_id
        }
    );
    out
}

#[test]
fn session_routes_answer_auth_and_admin_routes_answer_authz() {
    let mut api = Api::new();
    let admin = api.h.signup("admin");
    let mut bob = api.h.signup("bob");
    let model = shared_vault(&api.h, &admin);
    let bodies = dummy_bodies(&mut bob.person, &model);
    assert!(bodies.len() >= 30);
    for (op, body) in &bodies {
        let (status, _, reply) = api.raw(request(*op, None, body, [10, 0, 0, 1]));
        let error = decode_reply::<Ack>(&reply).unwrap().unwrap_err();
        assert_eq!(error.code, ErrorCode::Auth, "{op:?} without token");
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{op:?}");

        let stranger = SessionToken::from_bytes([9; 32]);
        let (_, _, reply) = api.raw(request(*op, Some(&stranger), body, [10, 0, 0, 1]));
        let error = decode_reply::<Ack>(&reply).unwrap().unwrap_err();
        assert_eq!(error.code, ErrorCode::Auth, "{op:?} with unknown token");
    }
    for (op, body) in bodies.iter().filter(|(op, _)| {
        matches!(
            op,
            OpId::AdminTokenCreate
                | OpId::AdminAccountList
                | OpId::AdminAccountUpdate
                | OpId::AdminAccountDelete
        )
    }) {
        let (status, _, reply) = api.raw(request(*op, Some(&bob.token), body, [10, 0, 0, 1]));
        let error = decode_reply::<Ack>(&reply).unwrap().unwrap_err();
        assert_eq!(
            (status, error.code),
            (StatusCode::FORBIDDEN, ErrorCode::Authz),
            "{op:?}"
        );
    }
}

#[test]
fn malformed_bearer_headers_are_treated_as_no_token() {
    let mut api = Api::new();
    let alice = api.h.signup("alice");
    let body = AccountGet {}.to_cbor().unwrap();
    for value in [
        format!("Bearer {}", base64url::encode(&[1; 31])),
        format!("Basic {}", base64url::encode(alice.token.as_bytes())),
        "Bearer ***".to_owned(),
        base64url::encode(alice.token.as_bytes()),
    ] {
        let mut req = request(OpId::AccountGet, None, &body, [10, 0, 0, 1]);
        req.headers_mut()
            .insert(header::AUTHORIZATION, value.parse().unwrap());
        let (status, ..) = api.raw(req);
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{value}");
    }
    let good = api.send(Some(&alice.token), &AccountGet {});
    assert_eq!(good.status, StatusCode::OK);
}

#[test]
fn logs_never_contain_tokens_logins_or_bodies() {
    use tracing_subscriber::layer::SubscriberExt;
    let sink = Sink::default();
    let subscriber = tracing_subscriber::registry().with(RedactingLayer::new(sink.clone()));
    let mut api = Api::new();
    let alice = api.h.signup("distinctive-login-name");
    api.rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tracing::subscriber::with_default(subscriber, || {
        api.ok(&alice.token, &SessionList {});
        let _ = api.send(
            None,
            &hasp_proto::wire::Prelogin {
                login: "distinctive-login-name".to_owned(),
            },
        );
        let _ = api.send(Some(&SessionToken::from_bytes([8; 32])), &AccountGet {});
    });
    let text = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("\"op\":\"session_list\""));
    assert!(text.contains("\"code\":\"E_AUTH\""));
    assert!(!text.contains("distinctive-login-name"));
    assert!(!text.contains(&base64url::encode(alice.token.as_bytes())));
    assert!(!text.contains(&base64url::encode(&[8; 32])));
    assert!(!text.contains("Bearer"));
}
