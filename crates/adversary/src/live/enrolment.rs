use std::sync::{Arc, Mutex};

use hasp_core::CoreError;
use hasp_crypto::{SecretKey, X25519Secret};
use hasp_proto::Wire;
use hasp_proto::wire::{Blob, EnrolMsgPut, EnrolSlot, OpId};
use hasp_testsupport::World;

use super::enrol_model::{
    Qr, code_of, commit_of, fresh, mac, pair, parse_qr, read_request, request_body, transcript,
    unpair,
};
use super::lab::{Phone, SharedStore, Victim, cancel, phone, run};
use super::mallory::{Mallory, Verdict};

struct Relay {
    qr: Qr,
    c_b_real: Option<hasp_proto::Hash32>,
    b_real: Option<[u8; 32]>,
    a_prime: Option<(X25519Secret, [u8; 32])>,
    b_prime: (X25519Secret, [u8; 32]),
}

impl Relay {
    fn code_for_joiner(&self) -> String {
        let (secret, public) = self.a_prime.as_ref().unwrap();
        let b = self.b_real.unwrap();
        let shared = secret.diffie_hellman(&b).unwrap();
        let t = transcript(&self.qr, &self.c_b_real.unwrap(), public, &b);
        code_of(&self.qr.e, &shared, &t)
    }
}

fn arm(mallory: &Mallory, qr_bytes: &[u8]) -> Arc<Mutex<Relay>> {
    let relay = Arc::new(Mutex::new(Relay {
        qr: parse_qr(qr_bytes),
        c_b_real: None,
        b_real: None,
        a_prime: None,
        b_prime: fresh(),
    }));
    mallory.passthrough();
    let hooked = Arc::clone(&relay);
    mallory.on_request(OpId::EnrolMsgPut, move |bytes| {
        let mut msg = EnrolMsgPut::from_cbor(bytes).unwrap();
        let mut relay = hooked.lock().unwrap();
        let esid = relay.qr.esid;
        let e = SecretKey::from_bytes(*relay.qr.e.expose());
        let (first, _) = unpair(&msg.data.0);
        match msg.slot {
            EnrolSlot::Request => {
                let (c_b, platform, device) = read_request(&first);
                relay.c_b_real = Some(c_b);
                let forged = commit_of(&relay.b_prime.1, &esid);
                let body = request_body(&forged, &platform, &device);
                let tag = mac(&e, &[&body, esid.as_bytes()]);
                msg.data = Blob(pair(&body, &tag));
            }
            EnrolSlot::Offer => {
                let (secret, public) = fresh();
                let c_b = relay.c_b_real.unwrap();
                let tag = mac(&e, &[&public, esid.as_bytes(), c_b.as_bytes()]);
                msg.data = Blob(pair(&public, &tag));
                relay.a_prime = Some((secret, public));
            }
            EnrolSlot::Reveal => {
                relay.b_real = first.as_slice().try_into().ok();
                let public = relay.b_prime.1;
                let tag = mac(&e, &[&public, esid.as_bytes()]);
                msg.data = Blob(pair(&public, &tag));
            }
            EnrolSlot::Payload => {}
        }
        *bytes = msg.to_cbor().unwrap();
        Verdict::Forward
    });
    relay
}

async fn pair_up(world: &mut World, mallory: &Mallory) -> (Phone, Victim) {
    let first = phone(world, mallory, "alice@example.com", true).await;
    let (second, _) = world.client_on(mallory.clone(), SharedStore::default(), true);
    (first, second)
}

fn corrupt_slot(mallory: &Mallory, slot: EnrolSlot) {
    mallory.passthrough();
    mallory.on_request(OpId::EnrolMsgPut, move |bytes| {
        let mut msg = EnrolMsgPut::from_cbor(bytes).unwrap();
        if msg.slot == slot
            && let Some(last) = msg.data.0.last_mut()
        {
            *last ^= 1;
        }
        *bytes = msg.to_cbor().unwrap();
        Verdict::Forward
    });
}

#[test]
fn e15_a_relay_without_the_qr_secret_cannot_alter_any_message() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let (mut first, mut second) = pair_up(&mut world, &mallory).await;

        corrupt_slot(&mallory, EnrolSlot::Request);
        let invite = first.client.enrol_open(&cancel()).await.unwrap();
        second.enrol_join(&invite.qr, &cancel()).await.unwrap();
        let error = first
            .client
            .enrol_poll_request(&cancel())
            .await
            .unwrap_err();
        assert!(matches!(error, CoreError::Credentials), "{error:?}");

        corrupt_slot(&mallory, EnrolSlot::Offer);
        let invite = first.client.enrol_open(&cancel()).await.unwrap();
        second.enrol_join(&invite.qr, &cancel()).await.unwrap();
        first.client.enrol_poll_request(&cancel()).await.unwrap();
        let error = second.enrol_reveal(&cancel()).await.unwrap_err();
        assert!(matches!(error, CoreError::Credentials), "{error:?}");

        corrupt_slot(&mallory, EnrolSlot::Reveal);
        let invite = first.client.enrol_open(&cancel()).await.unwrap();
        second.enrol_join(&invite.qr, &cancel()).await.unwrap();
        first.client.enrol_poll_request(&cancel()).await.unwrap();
        let code = second.enrol_reveal(&cancel()).await.unwrap();
        let error = first
            .client
            .enrol_confirm(&code, &cancel())
            .await
            .unwrap_err();
        assert!(matches!(error, CoreError::Credentials), "{error:?}");
        let again = first
            .client
            .enrol_confirm(&code, &cancel())
            .await
            .unwrap_err();
        assert!(matches!(again, CoreError::Refused(_)), "{again:?}");
        assert!(mallory.seen_op(OpId::EnrolApprove).is_empty());
    });
}

#[test]
fn e15_a_request_replayed_from_another_channel_fails_its_mac() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let (mut first, mut second) = pair_up(&mut world, &mallory).await;
        let invite = first.client.enrol_open(&cancel()).await.unwrap();
        second.enrol_join(&invite.qr, &cancel()).await.unwrap();
        let captured = mallory
            .seen_op(OpId::EnrolMsgPut)
            .into_iter()
            .map(|seen| EnrolMsgPut::from_cbor(&seen.request).unwrap())
            .find(|msg| msg.slot == EnrolSlot::Request)
            .unwrap();
        mallory.on_request(OpId::EnrolMsgPut, move |bytes| {
            let mut msg = EnrolMsgPut::from_cbor(bytes).unwrap();
            if msg.slot == EnrolSlot::Request {
                msg.data = captured.data.clone();
            }
            *bytes = msg.to_cbor().unwrap();
            Verdict::Forward
        });
        let fresh_invite = first.client.enrol_open(&cancel()).await.unwrap();
        second
            .enrol_join(&fresh_invite.qr, &cancel())
            .await
            .unwrap();
        let error = first
            .client
            .enrol_poll_request(&cancel())
            .await
            .unwrap_err();
        assert!(matches!(error, CoreError::Credentials), "{error:?}");
    });
}

#[test]
fn e15_three_wrong_codes_abort_the_channel_and_the_right_code_is_too_late() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let (mut first, mut second) = pair_up(&mut world, &mallory).await;
        let invite = first.client.enrol_open(&cancel()).await.unwrap();
        second.enrol_join(&invite.qr, &cancel()).await.unwrap();
        first.client.enrol_poll_request(&cancel()).await.unwrap();
        let code = second.enrol_reveal(&cancel()).await.unwrap();
        let wrong = if code == "000000" { "000001" } else { "000000" };
        for _ in 0..3 {
            assert!(first.client.enrol_confirm(wrong, &cancel()).await.is_err());
        }
        assert!(first.client.enrol_confirm(&code, &cancel()).await.is_err());
        assert_eq!(mallory.seen_op(OpId::EnrolAbort).len(), 1);
        assert!(mallory.seen_op(OpId::EnrolApprove).is_empty());
        assert!(second.enrol_finish(None, &cancel()).await.is_err());
    });
}

#[test]
fn e15_a_stolen_qr_needs_the_code_only_the_real_new_device_shows() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let (mut first, mut real_device) = pair_up(&mut world, &mallory).await;
        let (mut thief, _) = world.client_on(mallory.clone(), SharedStore::default(), false);
        let invite = first.client.enrol_open(&cancel()).await.unwrap();
        thief.enrol_join(&invite.qr, &cancel()).await.unwrap();
        assert!(real_device.enrol_join(&invite.qr, &cancel()).await.is_err());
        let request = first
            .client
            .enrol_poll_request(&cancel())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request.platform, "linux");
        let thief_code = thief.enrol_reveal(&cancel()).await.unwrap();
        assert!(
            first
                .client
                .enrol_confirm("000000", &cancel())
                .await
                .is_err()
                || thief_code == "000000"
        );
        let early = thief.enrol_finish(None, &cancel()).await;
        assert!(
            matches!(
                early,
                Err(CoreError::Pending { .. } | CoreError::Refused(_))
            ),
            "{early:?}"
        );
    });
}

#[test]
fn e15_e24_a_relay_that_knows_the_qr_secret_fails_every_attempt_against_commit_reveal() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let (mut first, mut second) = pair_up(&mut world, &mallory).await;
        let attempts = 150;
        let mut successes = 0;
        for attempt in 0..attempts {
            let invite = first.client.enrol_open(&cancel()).await.unwrap();
            let relay = arm(&mallory, &invite.qr);
            second.enrol_join(&invite.qr, &cancel()).await.unwrap();
            first.client.enrol_poll_request(&cancel()).await.unwrap();
            let shown = second.enrol_reveal(&cancel()).await.unwrap();
            if attempt == 0 {
                assert_eq!(relay.lock().unwrap().code_for_joiner(), shown);
            }
            if first.client.enrol_confirm(&shown, &cancel()).await.is_ok() {
                successes += 1;
            }
        }
        assert_eq!(successes, 0);
        assert!(mallory.seen_op(OpId::EnrolApprove).is_empty());
    });
}

fn grinding_qr() -> Qr {
    Qr {
        origin: "https://hasp.test".to_owned(),
        account: hasp_proto::AccountId::from_bytes([1; 16]),
        esid: hasp_proto::Esid::from_bytes([2; 16]),
        e: SecretKey::from_bytes([7; 32]),
    }
}

fn grind_without_commitment(digits: usize, budget: u32) -> Option<u32> {
    let qr = grinding_qr();
    let none = hasp_proto::Hash32::from_bytes([0; 32]);
    let (_, a_pub) = fresh();
    let (_, b_real) = fresh();
    let (relay_b, b_relay) = fresh();
    let initiator = code_of(
        &qr.e,
        &relay_b.diffie_hellman(&a_pub).unwrap(),
        &transcript(&qr, &none, &a_pub, &b_relay),
    );
    let wanted = &initiator[initiator.len() - digits..];
    (1..=budget).find(|_| {
        let (candidate, candidate_pub) = fresh();
        let shared = candidate.diffie_hellman(&b_real).unwrap();
        code_of(
            &qr.e,
            &shared,
            &transcript(&qr, &none, &candidate_pub, &b_real),
        )
        .ends_with(wanted)
    })
}

fn guess_against_commitment(attempts: u32) -> u32 {
    let qr = grinding_qr();
    let (_, forged_offer) = fresh();
    let (_, forged_reveal) = fresh();
    let c_relay = commit_of(&forged_reveal, &qr.esid);
    (0..attempts)
        .filter(|_| {
            let (a, a_pub) = fresh();
            let (b, b_pub) = fresh();
            let c_b = commit_of(&b_pub, &qr.esid);
            let initiator = code_of(
                &qr.e,
                &a.diffie_hellman(&forged_reveal).unwrap(),
                &transcript(&qr, &c_relay, &a_pub, &forged_reveal),
            );
            let joiner = code_of(
                &qr.e,
                &b.diffie_hellman(&forged_offer).unwrap(),
                &transcript(&qr, &c_b, &forged_offer, &b_pub),
            );
            initiator == joiner
        })
        .count()
        .try_into()
        .unwrap()
}

#[test]
fn e24_without_the_commitment_a_relay_grinds_a_truncated_code() {
    assert!(grind_without_commitment(4, 200 * 10_u32.pow(4)).is_some());
}

#[test]
#[ignore = "slow: grinds the full six digit code, about a million trials"]
fn e24_without_the_commitment_a_relay_grinds_the_full_six_digit_code() {
    let trials = grind_without_commitment(6, 50 * 10_u32.pow(6)).expect("ground a match");
    assert!(trials > 1);
}

#[test]
fn e24_with_the_commitment_a_relay_that_knows_the_qr_secret_only_guesses() {
    assert!(guess_against_commitment(2_000) <= 2);
}

#[test]
#[ignore = "slow: a million attempts to measure the one in a million success rate"]
fn e24_with_the_commitment_the_relay_success_rate_stays_near_one_in_a_million() {
    assert!(guess_against_commitment(1_000_000) <= 8);
}
