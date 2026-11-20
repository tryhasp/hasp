use hasp_core::CoreError;
use hasp_crypto::{SecretKey, SigningKey, hkdf_extract};
use hasp_proto::wire::{
    AccountGet, AccountGetResponse, OpId, RcSet, RecoverFetchResponse, RecoverStartResponse,
    RecoveryId, SessionToken,
};
use hasp_proto::{
    Aad, Hash32, Kdf, ProtoError, RecoveryEnrolment, SecretKind, SigLabel, Signed, Uint53, Wire,
    derive, parse_secret_key,
};
use hasp_server::fixture::Person;
use hasp_testsupport::World;

use super::lab::{
    ORIGIN, PASSWORD, Phone, SharedStore, Victim, cancel, kit_device, login_item, phone, run,
    secret,
};
use super::mallory::{Mallory, Verdict};

struct Scene {
    world: World,
    mallory: Mallory,
    alice: Phone,
    old_code: String,
    new_code: String,
    old_set: RcSet,
    fresh: Victim,
    account: AccountGetResponse,
}

async fn scene() -> Scene {
    let mut world = World::new();
    let mallory = Mallory::new(&world.server);
    let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
    let private = alice.private();
    alice.add_login(&private, "Mail", "pw");
    alice.client.sync(&cancel()).await.unwrap();
    let old_code = alice
        .client
        .create_recovery_code(&secret(PASSWORD), &cancel())
        .await
        .unwrap()
        .expose()
        .to_owned();
    let old_set = mallory
        .seen_op(OpId::RcSet)
        .pop()
        .map(|seen| RcSet::from_cbor(&seen.request).unwrap())
        .unwrap();
    let new_code = alice
        .client
        .create_recovery_code(&secret(PASSWORD), &cancel())
        .await
        .unwrap()
        .expose()
        .to_owned();
    let token = mallory.stolen_token();
    let account = mallory.as_thief(&token, &AccountGet {}).unwrap();
    let (fresh, _) = world.client_on(mallory.clone(), SharedStore::default(), true);
    Scene {
        world,
        mallory,
        alice,
        old_code,
        new_code,
        old_set,
        fresh,
        account,
    }
}

fn recovery_keys(code: &str, account: &hasp_proto::AccountId) -> (SecretKey, SecretKey) {
    let (kind, rc) = parse_secret_key(code).unwrap();
    assert_eq!(kind, SecretKind::RecoveryCode);
    let mut ikm = rc.expose().to_vec();
    ikm.extend_from_slice(account.as_bytes());
    let prk = hkdf_extract(Kdf::RcPrk.name().as_bytes(), &ikm).into_secret();
    (
        derive(&prk, Kdf::RcWrap, &[]).unwrap(),
        derive(&prk, Kdf::RcAuth, &[]).unwrap(),
    )
}

fn fake_service(
    mallory: &Mallory,
    enrolment: Signed<RecoveryEnrolment>,
    wrap: hasp_proto::SealedRaw,
    account: &AccountGetResponse,
    release_in: u64,
) {
    let (keyset, records) = (account.keyset.clone(), account.records.clone());
    mallory.on_request(OpId::RecoverStart, move |_| {
        Verdict::Reply(
            RecoverStartResponse {
                recovery_id: RecoveryId::from_bytes([4; 16]),
                release_at: Uint53::new(release_in).unwrap(),
            }
            .to_cbor()
            .unwrap(),
        )
    });
    mallory.on_request(OpId::RecoverFetch, move |_| {
        Verdict::Reply(
            RecoverFetchResponse {
                token: SessionToken::from_bytes([3; 32]),
                enrolment: enrolment.clone(),
                rc_wrap: wrap.clone(),
                keyset: keyset.clone(),
                records: records.clone(),
            }
            .to_cbor()
            .unwrap(),
        )
    });
}

#[test]
fn e17_an_old_recovery_code_is_refused_by_the_server_and_by_a_relay_serving_old_material() {
    run(async {
        let mut s = Box::pin(scene()).await;
        let honest = s
            .fresh
            .recover_start(ORIGIN, "alice@example.com", &s.old_code)
            .await;
        assert!(matches!(honest, Err(CoreError::Credentials)), "{honest:?}");

        fake_service(
            &s.mallory,
            s.old_set.rc.clone(),
            s.old_set.rc_wrap.clone(),
            &s.account,
            0,
        );
        let ticket = s
            .fresh
            .recover_start(ORIGIN, "alice@example.com", &s.old_code)
            .await
            .unwrap();
        let outcome = s
            .fresh
            .recover_finish(&ticket, &secret("brand new password"), &cancel())
            .await;
        assert!(
            matches!(outcome, Err(CoreError::Proto(ProtoError::Rollback))),
            "{outcome:?}"
        );

        let record = s.account.records.last().unwrap().unverified().unwrap();
        let enrolment = s.old_set.rc.unverified().unwrap();
        let (wrap_key, _) = recovery_keys(&s.old_code, &record.account_id);
        let ak = s
            .old_set
            .rc_wrap
            .open(
                &wrap_key,
                &Aad::recovery_wrap(record.account_id, enrolment.rgen),
            )
            .unwrap();
        let ak = SecretKey::from_bytes(ak.expose().try_into().unwrap());
        let k_keyset = derive(&ak, Kdf::KeysetSeal, &[]).unwrap();
        let keys = s
            .account
            .keyset
            .keys
            .open(
                &k_keyset,
                &Aad::keyset_keys(record.account_id, s.account.keyset.generation),
            )
            .unwrap();
        assert_eq!(
            SigningKey::from_seed(&keys.ik_seed).verifying_key(),
            record.ik_pk
        );
        assert_ne!(enrolment.rgen, record.rc_gen);
    });
}

#[test]
fn e17_a_forged_rc_wrap_or_an_enrolment_signed_by_another_key_is_refused() {
    run(async {
        let mut s = Box::pin(scene()).await;
        s.world.clock.advance(25 * 3600);
        let old_wrap = s.old_set.rc_wrap.clone();
        s.mallory.on_response(OpId::RecoverFetch, move |bytes| {
            super::mallory::edit::<RecoverFetchResponse>(bytes, |r| r.rc_wrap = old_wrap.clone());
        });
        let ticket = s
            .fresh
            .recover_start(ORIGIN, "alice@example.com", &s.new_code)
            .await
            .unwrap();
        s.world.clock.advance(25 * 3600);
        let forged = s
            .fresh
            .recover_finish(&ticket, &secret("brand new password"), &cancel())
            .await;
        assert!(
            matches!(forged, Err(CoreError::Proto(ProtoError::Rollback))),
            "{forged:?}"
        );

        s.mallory.passthrough();
        let thief = Person::new("thief");
        let record = s.account.records.last().unwrap().unverified().unwrap();
        let wrap = s.old_set.rc_wrap.clone();
        let body = RecoveryEnrolment {
            account_id: record.account_id,
            rgen: record.rc_gen,
            h_wrap: Hash32::digest(&[&wrap.to_cbor().unwrap()]),
        };
        let unsigned_by_owner = Signed::sign(SigLabel::Recovery, &body, &thief.signing).unwrap();
        fake_service(&s.mallory, unsigned_by_owner, wrap, &s.account, 0);
        let ticket = s
            .fresh
            .recover_start(ORIGIN, "alice@example.com", &s.new_code)
            .await
            .unwrap();
        let outcome = s
            .fresh
            .recover_finish(&ticket, &secret("brand new password"), &cancel())
            .await;
        assert!(
            matches!(outcome, Err(CoreError::Proto(ProtoError::Sig))),
            "{outcome:?}"
        );
    });
}

#[test]
fn e17_the_delay_holds_and_a_relay_cannot_mint_the_recovery_session() {
    run(async {
        let mut s = Box::pin(scene()).await;
        let ticket = s
            .fresh
            .recover_start(ORIGIN, "alice@example.com", &s.new_code)
            .await
            .unwrap();
        let early = s
            .fresh
            .recover_finish(&ticket, &secret("brand new password"), &cancel())
            .await;
        assert!(matches!(early, Err(CoreError::Pending { .. })), "{early:?}");
        let notice = s.alice.client.sync(&cancel()).await.unwrap();
        assert!(
            notice
                .events
                .iter()
                .any(|e| matches!(e.kind, hasp_core::store::EventKind::Server { kind: 1, .. }))
        );

        let enrolment = mallory_enrolment(&s);
        s.mallory.passthrough();
        fake_service(&s.mallory, enrolment.0, enrolment.1, &s.account, 0);
        let faked = s
            .fresh
            .recover_finish(&ticket, &secret("brand new password"), &cancel())
            .await;
        assert!(faked.is_err(), "{faked:?}");
        s.mallory.passthrough();
        s.alice.client.sync(&cancel()).await.unwrap();
        s.alice
            .client
            .create_item(&s.alice.private(), &login_item("still mine", "pw"))
            .unwrap();
        s.alice.client.sync(&cancel()).await.unwrap();
    });
}

fn mallory_enrolment(s: &Scene) -> (Signed<RecoveryEnrolment>, hasp_proto::SealedRaw) {
    let last = s.mallory.seen_op(OpId::RcSet).pop().unwrap();
    let set = RcSet::from_cbor(&last.request).unwrap();
    (set.rc, set.rc_wrap)
}

#[test]
fn e17_a_normal_sign_in_during_the_delay_aborts_the_recovery() {
    run(async {
        let mut s = Box::pin(scene()).await;
        let ticket = s
            .fresh
            .recover_start(ORIGIN, "alice@example.com", &s.new_code)
            .await
            .unwrap();
        let laptop = kit_device(
            &s.world,
            &s.mallory,
            s.alice.kit(),
            "alice@example.com",
            PASSWORD,
        )
        .await
        .unwrap();
        drop(laptop);
        s.world.clock.advance(25 * 3600);
        let late = s
            .fresh
            .recover_finish(&ticket, &secret("brand new password"), &cancel())
            .await;
        assert!(late.is_err(), "{late:?}");
        let report = s.alice.client.sync(&cancel()).await.unwrap();
        assert!(
            report
                .events
                .iter()
                .any(|e| matches!(e.kind, hasp_core::store::EventKind::Server { kind: 2, .. }))
        );
    });
}
