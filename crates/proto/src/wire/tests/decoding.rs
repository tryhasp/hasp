use super::*;

fn map(entries: &[(u64, Entry)]) -> Vec<u8> {
    let mut w = Writer::new();
    w.map(entries.len()).unwrap();
    for (key, entry) in entries {
        w.uint(*key).unwrap();
        match entry {
            Entry::Text(t) => w.text(t).unwrap(),
            Entry::Uint(v) => w.uint(*v).unwrap(),
            Entry::Null => w.null(),
            Entry::Raw(bytes) => w.bytes(bytes).unwrap(),
        }
    }
    w.into_bytes()
}

enum Entry {
    Text(&'static str),
    Uint(u64),
    Null,
    Raw(Vec<u8>),
}

#[test]
fn strict_decoding_rejects_every_deviation() {
    assert!(Prelogin::from_cbor(&map(&[(0, Entry::Text("a"))])).is_ok());
    assert!(Prelogin::from_cbor(&map(&[])).is_err());
    assert!(Prelogin::from_cbor(&map(&[(0, Entry::Text("a")), (1, Entry::Text("b"))])).is_err());
    assert!(Prelogin::from_cbor(&map(&[(1, Entry::Text("a"))])).is_err());
    assert!(Prelogin::from_cbor(&map(&[(0, Entry::Uint(1))])).is_err());
    assert!(Prelogin::from_cbor(&map(&[(0, Entry::Null)])).is_err());
    assert!(Prelogin::from_cbor(&[0xbf, 0x00, 0x61, b'a', 0xff]).is_err());
    assert!(Prelogin::from_cbor(&[0xb8, 0x01, 0x00, 0x61, b'a']).is_err());
    assert!(Prelogin::from_cbor(&[0xa1, 0x18, 0x00, 0x61, b'a']).is_err());
    assert!(Prelogin::from_cbor(&[0xa1, 0x00, 0x7a, 0, 0, 0, 1, b'a']).is_err());
    assert!(Prelogin::from_cbor(&[0xa1, 0x00, 0x62, 0xff, 0xfe]).is_err());
    assert!(Prelogin::from_cbor(&[0xc1, 0xa1, 0x00, 0x61, b'a']).is_err());

    let two = |a: u64, b: u64| map(&[(a, Entry::Raw(vec![1; 16])), (b, Entry::Uint(1))]);
    assert!(SessionRevoke::from_cbor(&two(0, 1)).is_err());
    let swapped = [
        0xa2, 0x01, 0x01, 0x00, 0x50, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    ];
    assert!(LoginFinishResponse::from_cbor(&swapped).is_err());

    let mut ok = Writer::new();
    ok.map(1).unwrap();
    ok.key(0).unwrap();
    ok.bytes(&[1; 16]).unwrap();
    assert!(SessionRevoke::from_cbor(&ok.into_bytes()).is_ok());
    let mut short = Writer::new();
    short.map(1).unwrap();
    short.key(0).unwrap();
    short.bytes(&[1; 15]).unwrap();
    assert!(SessionRevoke::from_cbor(&short.into_bytes()).is_err());

    assert!(OpId::from_cbor(&[0x00]).is_err());
    assert!(ErrorCode::from_cbor(&[0x18, 0x63]).is_err());
    assert!(TokenKind::from_cbor(&[0x04]).is_err());
    let mut flag = Writer::new();
    flag.map(2).unwrap();
    flag.key(0).unwrap();
    flag.bytes(&[1; 16]).unwrap();
    flag.key(1).unwrap();
    flag.uint(1).unwrap();
    assert!(AttachmentGetResponse::from_cbor(&flag.into_bytes()).is_err());
}

#[test]
fn unknown_or_missing_nested_fields_are_rejected() {
    let ok = PreloginResponse {
        account_id: AccountId::from_bytes([1; 16]),
        kdf: KdfWire {
            m: 65_536,
            t: 3,
            p: 4,
        },
        cred_gen: uint(1),
        v: uint(1),
    };
    let bytes = ok.to_cbor().unwrap();
    let mut extra_kdf = bytes.clone();
    let position = extra_kdf.iter().position(|b| *b == 0xa3).unwrap();
    extra_kdf[position] = 0xa4;
    assert!(PreloginResponse::from_cbor(&extra_kdf).is_err());
}

#[test]
fn bearer_values_never_print_their_bytes() {
    let token = SessionToken::from_bytes([0xab; 32]);
    assert_eq!(format!("{token:?}"), "SessionToken(..)");
    assert_eq!(
        format!("{:?}", RcAuthKey::from_bytes([0xcd; 32])),
        "RcAuthKey(..)"
    );
    assert_eq!(token, token.clone());
    assert_ne!(token, SessionToken::from_bytes([0xac; 32]));
    assert_eq!(token.hash(), Hash32::digest(&[&[0xab; 32]]));
}

#[test]
fn signup_tokens_use_the_text_form() {
    let token = SignupToken::from_bytes([0x5a; 20]);
    let text = token.to_text();
    assert!(text.starts_with("SGN1-"));
    assert_eq!(SignupToken::parse(&text).unwrap(), token);
    assert_eq!(SignupToken::parse(&text.to_lowercase()).unwrap(), token);
    assert!(SignupToken::parse(&text.replace("SGN1-", "SGN2-")).is_err());
    let mut short = text.clone();
    short.pop();
    assert!(SignupToken::parse(&short).is_err());
    assert!(SignupToken::parse("SGN1-").is_err());
}

#[test]
fn opaque_context_is_the_specified_map() {
    let account = AccountId::from_bytes([1; 16]);
    let kdf = KdfWire {
        m: 65_536,
        t: 3,
        p: 4,
    };
    let login = opaque_context(OpaquePurpose::Login, &account, &kdf).unwrap();
    let reauth = opaque_context(OpaquePurpose::Reauth, &account, &kdf).unwrap();
    assert_ne!(login, reauth);
    assert_eq!(login[0], 0xa6);
    assert_eq!(&login[..5], [0xa6, 0x00, 0x01, 0x01, 0x01]);
    let id = credential_id(&account).unwrap();
    assert_eq!(&id[..7], [0x82, 0x64, b'a', b'c', b'c', b't', 0x50]);
}

#[test]
fn session_token_depends_on_key_and_session_id() {
    let sid = SessionId::from_bytes([1; 16]);
    let a = session_token(&[1; 64], &sid).unwrap();
    assert_eq!(a, session_token(&[1; 64], &sid).unwrap());
    assert_ne!(a, session_token(&[2; 64], &sid).unwrap());
    assert_ne!(
        a,
        session_token(&[1; 64], &SessionId::from_bytes([2; 16])).unwrap()
    );
}

#[test]
fn recover_abort_round_trips_by_session_and_by_recovery_code() {
    roundtrip(&RecoverAbort::by_session());
    roundtrip(&RecoverAbort::by_recovery_code(
        RecoveryId::from_bytes([5; 16]),
        RcAuthKey::from_bytes([4; 32]),
    ));
}
