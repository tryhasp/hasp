use std::collections::BTreeSet;

use hasp_crypto::{SecretBytes, SecretKey};

use super::*;
use crate::testkit::{Person, Vault};
use crate::{
    Aad, AccountId, AccountRecord, AccountStatus, AttId, DeviceId, Dissolve, Epoch, Esid, Hash32,
    InviteId, KdfWire, Keyset, KeysetKeys, LeaveRequest, Role, Rtype, Rver, Sealed, SealedRaw, Seq,
    SigLabel, Signed, Uint53, VaultId, VaultKind, Wire, Writer,
};

fn uint(value: u64) -> Uint53 {
    Uint53::new(value).unwrap()
}

fn sealed() -> SealedRaw {
    SealedRaw::seal(
        &SecretKey::from_bytes([3; 32]),
        b"payload",
        &Aad::new(Rtype::Recovery),
    )
    .unwrap()
}

fn account_record(person: &Person) -> Signed<AccountRecord> {
    let record = AccountRecord {
        account_id: person.account,
        seq: Seq::new(1).unwrap(),
        prev: None,
        ik_pk: person.ik_pk,
        kem_pk: person.kem_pk.clone(),
        kdf: KdfWire {
            m: 65_536,
            t: 3,
            p: 4,
        },
        status: AccountStatus::Active,
        rc_gen: Uint53::ZERO,
        min_v: uint(1),
        created: uint(10),
    };
    Signed::sign(SigLabel::Account, &record, &person.signing).unwrap()
}

fn keyset(person: &Person) -> Keyset {
    let key = SecretKey::from_bytes([4; 32]);
    Keyset {
        account_id: person.account,
        generation: uint(1),
        ak_wrap: sealed(),
        keys: Sealed::seal(
            &key,
            &KeysetKeys {
                ik_seed: SecretKey::from_bytes([5; 32]),
                kem_seed: SecretKey::from_bytes([6; 32]),
                sk_ascii: SecretBytes::from_vec(b"secret".to_vec()),
                retired: Vec::new(),
            },
            &Aad::keyset_keys(person.account, uint(1)),
        )
        .unwrap(),
    }
}

fn bundle() -> (CommitBundle, Vault) {
    let mut vault = Vault::new(VaultKind::Private, 1);
    let genesis = vault.genesis();
    let wire = vault.seal(1, 1, 0, b"overview");
    let put = vault.finish(1, None, Vec::new(), vec![wire]);
    drop(put);
    let bundle = CommitBundle {
        manifest: genesis.manifest,
        roster: genesis.roster,
        shares: genesis.shares,
        ops: Vec::new(),
    };
    (bundle, vault)
}

fn roundtrip<T: Wire + PartialEq + core::fmt::Debug>(value: &T) {
    let bytes = value.to_cbor().unwrap();
    assert_eq!(&T::from_cbor(&bytes).unwrap(), value);
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(T::from_cbor(&longer).is_err());
    for cut in 0..bytes.len() {
        assert!(T::from_cbor(&bytes[..cut]).is_err(), "prefix {cut}");
    }
}

fn device() -> DeviceInfo {
    DeviceInfo {
        device_id: DeviceId::from_bytes([9; 16]),
        platform: "macos".to_owned(),
        label: Some(sealed()),
    }
}

#[test]
fn op_ids_and_error_codes_are_unique_and_decodable() {
    let ids: BTreeSet<_> = OpId::ALL.iter().map(|op| op.code()).collect();
    assert_eq!(ids.len(), OpId::ALL.len());
    for op in OpId::ALL {
        assert_eq!(OpId::from_code(op.code()), Some(*op));
    }
    let codes: BTreeSet<_> = ErrorCode::ALL.iter().map(|c| c.code()).collect();
    let names: BTreeSet<_> = ErrorCode::ALL.iter().map(|c| c.name()).collect();
    assert_eq!(codes.len(), ErrorCode::ALL.len());
    assert_eq!(names.len(), ErrorCode::ALL.len());
    assert_eq!(OpId::from_code(0), None);
    assert_eq!(ErrorCode::from_code(99), None);
}

#[test]
fn spec_error_names_are_present() {
    let names: BTreeSet<_> = ErrorCode::ALL.iter().map(|c| c.name()).collect();
    for name in [
        "E_FORMAT",
        "E_VERSION",
        "E_SIG",
        "E_AEAD",
        "E_PIN",
        "E_ROLLBACK",
        "E_FORK",
        "E_ROSTER",
        "E_KDF_PARAMS",
        "E_EPOCH",
        "E_ROOT",
        "E_AUTH",
        "E_SERVER_KEY",
        "E_AUTHZ",
        "E_INVITE",
        "stale_head",
        "epoch_stale",
        "not_member",
        "read_only",
    ] {
        assert!(names.contains(name), "{name}");
    }
}

#[test]
fn proto_errors_map_to_wire_codes() {
    use crate::ProtoError;
    for (error, code) in [
        (ProtoError::Format, ErrorCode::Format),
        (ProtoError::Sig, ErrorCode::Sig),
        (ProtoError::Epoch, ErrorCode::Epoch),
        (ProtoError::Authz, ErrorCode::Authz),
        (ProtoError::Invite, ErrorCode::Invite),
        (ProtoError::Internal("x"), ErrorCode::Internal),
    ] {
        assert_eq!(WireError::from(error).code, code);
    }
}

#[test]
fn replies_round_trip_and_reject_noise() {
    let ok: Result<Ack, WireError> = Ok(Ack);
    let bytes = encode_reply(&ok).unwrap();
    assert_eq!(decode_reply::<Ack>(&bytes).unwrap(), ok);

    let err: Result<Ack, WireError> = Err(WireError::retry_after(ErrorCode::RateLimited, 30));
    let bytes = encode_reply(&err).unwrap();
    assert_eq!(decode_reply::<Ack>(&bytes).unwrap(), err);

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_reply::<Ack>(&trailing).is_err());
    assert!(decode_reply::<Ack>(&bytes[..bytes.len() - 1]).is_err());

    let mut w = Writer::new();
    w.map(2).unwrap();
    w.key(0).unwrap();
    w.uint(2).unwrap();
    w.key(1).unwrap();
    w.map(0).unwrap();
    assert!(decode_reply::<Ack>(&w.into_bytes()).is_err());
}

#[test]
fn login_messages_round_trip() {
    let account = AccountId::from_bytes([1; 16]);
    roundtrip(&Prelogin {
        login: "alice".to_owned(),
    });
    roundtrip(&PreloginResponse {
        account_id: account,
        kdf: KdfWire {
            m: 65_536,
            t: 3,
            p: 4,
        },
        cred_gen: uint(1),
        v: uint(1),
    });
    roundtrip(&RecoverPreloginResponse {
        account_id: account,
        rgen: uint(2),
    });
    roundtrip(&RegisterStart {
        token: SignupToken::from_bytes([7; 20]),
        login: "alice".to_owned(),
        account_id: account,
        request: Blob(vec![1, 2, 3]),
    });
    roundtrip(&LoginStart {
        account_id: account,
        ke1: Blob(vec![9; 96]),
    });
    roundtrip(&LoginStartResponse {
        handle: LoginHandle::from_bytes([2; 16]),
        ke2: Blob(vec![8; 200]),
    });
    roundtrip(&LoginFinish {
        handle: LoginHandle::from_bytes([2; 16]),
        ke3: Blob(vec![1; 64]),
        device: device(),
    });
    roundtrip(&LoginFinishResponse {
        session_id: SessionId::from_bytes([3; 16]),
        idle_expires: uint(100),
        abs_expires: uint(200),
    });
    roundtrip(&ReauthFinishResponse {
        reauth_until: uint(300),
    });
    roundtrip(&SessionRevoke {
        session_id: SessionId::from_bytes([3; 16]),
    });
}

#[test]
fn recovery_and_admin_messages_round_trip() {
    let account = AccountId::from_bytes([1; 16]);
    roundtrip(&RecoverStart {
        account_id: account,
        k_rc_auth: RcAuthKey::from_bytes([4; 32]),
    });
    roundtrip(&RecoverStartResponse {
        recovery_id: RecoveryId::from_bytes([5; 16]),
        release_at: uint(86_400),
    });
    roundtrip(&SessionGrant {
        session_id: SessionId::from_bytes([3; 16]),
        token: SessionToken::from_bytes([6; 32]),
        idle_expires: uint(1),
        abs_expires: uint(2),
    });
    roundtrip(&AdminTokenCreate {
        kind: TokenKind::Signup,
    });
    roundtrip(&AdminAccount {
        account_id: account,
        login: "alice".to_owned(),
        disabled: false,
        is_admin: true,
        created: uint(5),
    });
    roundtrip(&AdminAccountUpdate {
        account_id: account,
        disabled: true,
        is_admin: false,
    });
    roundtrip(&HealthResponse {
        min_protocol: uint(1),
        max_protocol: uint(1),
        server_version: "0.0.0".to_owned(),
        features: vec!["a".to_owned()],
    });
    roundtrip(&Notice {
        id: uint(3),
        kind: NoticeKind::VaultDissolved,
        created: uint(9),
        vault_id: Some(VaultId::from_bytes([4; 16])),
        at: None,
    });
    roundtrip(&Health);
    roundtrip(&ServerKey);
    roundtrip(&ServerKeyResponse {
        public_key: Blob(vec![7; 32]),
        origin: "https://hasp.test".to_owned(),
    });
    roundtrip(&Ack);
}

#[test]
fn enrolment_messages_round_trip() {
    let esid = Esid::from_bytes([1; 16]);
    roundtrip(&EnrolOpen { esid });
    roundtrip(&EnrolOpenResponse { expires: uint(300) });
    roundtrip(&EnrolApprove {
        esid,
        device: device(),
    });
    roundtrip(&EnrolAbort { esid });
    for slot in EnrolSlot::ALL {
        roundtrip(&EnrolMsgPut {
            esid,
            slot: *slot,
            data: Blob(vec![1; 40]),
        });
        roundtrip(&EnrolMsgGet { esid, slot: *slot });
    }
    roundtrip(&EnrolMsgGetResponse { data: None });
    roundtrip(&EnrolMsgGetResponse {
        data: Some(Blob(vec![])),
    });
}

#[test]
fn record_carrying_messages_round_trip() {
    let alice = Person::new(1);
    let record = account_record(&alice);
    let keyset = keyset(&alice);
    let (vault_bundle, mut vault) = bundle();
    roundtrip(&vault_bundle);
    roundtrip(&RegisterFinish {
        token: SignupToken::from_bytes([7; 20]),
        login: "alice".to_owned(),
        account_id: alice.account,
        record: Blob(vec![1; 192]),
        account: record.clone(),
        keyset: keyset.clone(),
        vault: vault_bundle.clone(),
        self_wrap: sealed(),
    });
    roundtrip(&AccountGetResponse {
        records: vec![record.clone()],
        keyset: keyset.clone(),
        memberships: vec![Membership {
            vault_id: vault.id,
            kind: VaultKind::Private,
            role: Role::Owner,
            state: MemberState::Active,
        }],
    });
    roundtrip(&AccountLookupResponse {
        account: Some(record.clone()),
    });
    roundtrip(&AccountLookupResponse { account: None });
    roundtrip(&ChangeCredentialFinish {
        record: Blob(vec![1; 10]),
        keyset: keyset.clone(),
        account: Some(record.clone()),
    });
    roundtrip(&SessionInfo {
        session_id: SessionId::from_bytes([1; 16]),
        device_id: DeviceId::from_bytes([2; 16]),
        platform: "ios".to_owned(),
        label: None,
        created: uint(1),
        last_seen: uint(2),
        idle_expires: uint(3),
        abs_expires: uint(4),
        current: true,
    });
    recovery_messages_round_trip(&alice, &record, &keyset);
    commit_messages_round_trip(&vault_bundle, &mut vault);
}

fn recovery_messages_round_trip(alice: &Person, record: &Signed<AccountRecord>, keyset: &Keyset) {
    let enrolment = crate::RecoveryEnrolment {
        account_id: alice.account,
        rgen: uint(1),
        h_wrap: Hash32::from_bytes([1; 32]),
    };
    let signed = Signed::sign(SigLabel::Recovery, &enrolment, &alice.signing).unwrap();
    roundtrip(&RcSet {
        rc: signed.clone(),
        rc_wrap: sealed(),
        h_auth: Hash32::from_bytes([2; 32]),
        account: record.clone(),
    });
    roundtrip(&RecoverFetchResponse {
        token: SessionToken::from_bytes([1; 32]),
        enrolment: signed.clone(),
        rc_wrap: sealed(),
        keyset: keyset.clone(),
        records: vec![record.clone()],
    });
    roundtrip(&RecoverRegisterStart {
        recovery_id: RecoveryId::from_bytes([4; 16]),
        request: Blob(vec![5; 5]),
    });
    roundtrip(&ReregisterStart {
        token: SignupToken::from_bytes([6; SIGNUP_TOKEN_LEN]),
        request: Blob(vec![7; 7]),
    });
    roundtrip(&ReregisterFinish {
        token: SignupToken::from_bytes([6; SIGNUP_TOKEN_LEN]),
        record: Blob(vec![8; 8]),
    });
    roundtrip(&RecoverComplete {
        recovery_id: RecoveryId::from_bytes([4; 16]),
        record: Blob(vec![3; 3]),
        keyset: keyset.clone(),
        account: record.clone(),
        rc: signed,
        rc_wrap: sealed(),
        h_auth: Hash32::from_bytes([2; 32]),
        device: device(),
    });
    roundtrip(&AccountDelete {
        account: record.clone(),
    });
}

fn commit_messages_round_trip(vault_bundle: &CommitBundle, vault: &mut Vault) {
    let wire = vault.seal(1, 1, 0, b"x");
    let push = Commit {
        vault_id: vault.id,
        base_seq: Seq::new(1).unwrap(),
        bundle: CommitBundle {
            ops: vec![wire],
            ..vault_bundle.clone()
        },
        self_wraps: vec![SelfWrapEntry {
            epoch: Epoch::ZERO,
            wrap: sealed(),
        }],
    };
    roundtrip(&push);
    roundtrip(&RepairPublish {
        vault_id: vault.id,
        bundle: vault_bundle.clone(),
    });
    roundtrip(&SelfWrapPut {
        vault_id: vault.id,
        entry: SelfWrapEntry {
            epoch: Epoch::ZERO,
            wrap: sealed(),
        },
    });
    roundtrip(&CommitResponse {
        head_seq: Seq::new(2).unwrap(),
        head_hash: Hash32::from_bytes([1; 32]),
    });
}

#[test]
fn pull_messages_round_trip() {
    let alice = Person::new(1);
    let vault_id = VaultId::from_bytes([8; 16]);
    roundtrip(&Pull {
        vaults: vec![VaultCursor {
            vault_id,
            seq: Seq::ZERO,
        }],
        notices_after: Uint53::ZERO,
        limit: uint(100),
    });
    let dissolve = Dissolve {
        vault_id,
        rver: Rver::new(1).unwrap(),
        epoch: Epoch::ZERO,
        seq: Seq::new(1).unwrap(),
        head: Hash32::from_bytes([1; 32]),
    };
    let dissolve = Signed::sign(SigLabel::Dissolve, &dissolve, &alice.signing).unwrap();
    let leave = LeaveRequest {
        vault_id,
        account_id: alice.account,
        rver: Rver::new(1).unwrap(),
        epoch: Epoch::ZERO,
    };
    let leave = Signed::sign(SigLabel::Leave, &leave, &alice.signing).unwrap();
    roundtrip(&PullResponse {
        vaults: vec![VaultPull {
            vault_id,
            status: VaultStatus::Dissolved,
            head_seq: Seq::new(3).unwrap(),
            head_hash: Some(Hash32::from_bytes([3; 32])),
            has_more: true,
            commits: Vec::new(),
            shares: Vec::new(),
            self_wraps: vec![SelfWrapEntry {
                epoch: Epoch::ZERO,
                wrap: sealed(),
            }],
            leave_requests: vec![leave.clone()],
            dissolve: Some(dissolve.clone()),
        }],
        memberships: Vec::new(),
        notices: Vec::new(),
    });
    roundtrip(&Leave { request: leave });
    roundtrip(&VaultDissolve { record: dissolve });
}

#[test]
fn invite_and_attachment_messages_round_trip() {
    let record = account_record(&Person::new(1));
    let vault_id = VaultId::from_bytes([8; 16]);
    roundtrip(&InviteCreate {
        vault_id,
        role: Role::Editor,
    });
    roundtrip(&InviteView {
        invite_id: InviteId::from_bytes([1; 16]),
        vault_id,
        role: Role::Viewer,
        state: InviteState::Open,
        expires: uint(9),
        inviter: record.clone(),
    });
    roundtrip(&InviteListResponse {
        invites: vec![InviteEntry {
            invite_id: InviteId::from_bytes([1; 16]),
            role: Role::Viewer,
            state: InviteState::Accepted,
            expires: uint(9),
            invitee: Some(record),
            accept: Some(Blob(vec![1])),
        }],
    });
    roundtrip(&InviteAccept {
        invite_id: InviteId::from_bytes([1; 16]),
        accept: Blob(vec![]),
    });
    roundtrip(&AttachmentPut {
        vault_id,
        att_id: AttId::from_bytes([1; 16]),
        index: uint(0),
        data: Blob(vec![7; 1000]),
    });
    roundtrip(&AttachmentGetResponse {
        data: Blob(vec![]),
        last: true,
    });
    roundtrip(&AttachmentComplete {
        vault_id,
        att_id: AttId::from_bytes([1; 16]),
        chunks: uint(2),
    });
}

mod decoding;
