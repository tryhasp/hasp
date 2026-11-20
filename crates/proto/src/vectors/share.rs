use super::*;

pub(super) fn share_fixture() -> (Vault, Vec<Commit>) {
    let mut vault = Vault::new(VaultKind::Shared, 1);
    let commits = vec![vault.genesis(), vault.add_member(2, Role::Editor)];
    (vault, commits)
}

pub(super) fn invite_for(owner: &Person, fp: Option<[u8; 15]>) -> InviteCode {
    InviteCode {
        invite_id: InviteId::from_bytes([5; 16]),
        fp_owner: fp.unwrap_or_else(|| fingerprint(&owner.ik_pk, &owner.kem_pk)),
        origin: "https://hasp.example".to_owned(),
    }
}

#[expect(clippy::unwrap_in_result, reason = "replay reads trusted fixtures")]
pub(super) fn replay_share_inputs(case: &Value) -> Result<Value, ProtoError> {
    let commits: Vec<Commit> = field(case, "commits")
        .as_array()
        .unwrap()
        .iter()
        .map(commit_from)
        .collect();
    let own_value = field(case, "own");
    let state = run_chain(own_value, &json!([]), &commits).unwrap();
    let share = Signed::<Share>::from_cbor(&bytes_of(case, "share")).unwrap();
    let invite = field(case, "invite")
        .as_str()
        .map(|t| InviteCode::parse(t).unwrap());
    let own = own_from(own_value);
    let roster = state.verified_roster();
    let verified = verify_share(
        &share,
        &own,
        &roster,
        invite.as_ref(),
        &pins_from(field(case, "pins")),
    )?;
    let kem_seed = SecretKey::from_bytes(array32(case, "kem_seed"));
    let kem = hasp_crypto::KemSecretKey::from_seed(&kem_seed).unwrap();
    let vk = open_share(&verified, &kem, &roster)?;
    Ok(json!({ "vk": hex(vk.expose()) }))
}

#[expect(clippy::too_many_arguments, reason = "vector case inputs")]
pub(super) fn share_case(
    name: &str,
    commits: &[Commit],
    share: &Signed<Share>,
    own: &Person,
    invite: Option<&InviteCode>,
    pins: &[&Person],
) -> Value {
    let mut case = json!({
        "kind": "share",
        "name": name,
        "commits": commits.iter().map(commit_json).collect::<Vec<_>>(),
        "share": hex(&share.to_cbor().unwrap()),
        "own": own_json(own),
        "invite": invite.map(|i| i.to_text().unwrap()),
        "pins": pins_json(pins),
        "kem_seed": hex(&[own.n.wrapping_add(0x80); 32]),
    });
    let outcome = replay_share_inputs(&case);
    case["expect"] = expected(outcome);
    case
}

pub(super) fn share_cases() -> Vec<Value> {
    let (_, commits) = share_fixture();
    let (owner, member, stranger) = (Person::new(1), Person::new(2), Person::new(3));
    let share = commits[1].shares[0].clone();
    let good_invite = invite_for(&owner, None);
    let wrong_invite = invite_for(&owner, Some([9; 15]));
    let mut forged = share.clone();
    let mut sig = *forged.sig.as_bytes();
    sig[7] ^= 0x01;
    forged.sig = hasp_crypto::Signature::from_bytes(sig);
    let mut body = share.unverified().unwrap();
    body.ct[0] ^= 1;
    let tampered = Signed::sign(SigLabel::Share, &body, &owner.signing).unwrap();
    let imposter = Person::new(7);
    let mut changed_pin = share_case(
        "pinned_owner_key_changed",
        &commits,
        &share,
        &member,
        None,
        &[],
    );
    changed_pin["pins"] = json!([{
        "account_id": hex(owner.account.as_bytes()),
        "ik_pk": hex(imposter.ik_pk.as_bytes()),
        "kem_pk": hex(imposter.kem_pk.as_bytes()),
    }]);
    changed_pin["expect"] = expected(replay_share_inputs(&changed_pin));
    let case =
        |name: &str,
         share: &Signed<Share>,
         who: &Person,
         invite: Option<&InviteCode>,
         pins: &[&Person]| { share_case(name, &commits, share, who, invite, pins) };
    vec![
        case("with_invite", &share, &member, Some(&good_invite), &[]),
        case("with_pinned_owner", &share, &member, None, &[&owner]),
        case("no_invite_no_pin", &share, &member, None, &[]),
        case(
            "wrong_invite_fingerprint",
            &share,
            &member,
            Some(&wrong_invite),
            &[],
        ),
        changed_pin,
        case(
            "addressed_to_someone_else",
            &share,
            &stranger,
            Some(&good_invite),
            &[],
        ),
        case(
            "signature_bit_flipped",
            &forged,
            &member,
            Some(&good_invite),
            &[],
        ),
        case(
            "ciphertext_tampered_and_resigned",
            &tampered,
            &member,
            Some(&good_invite),
            &[],
        ),
    ]
}

pub(super) fn replay_share(case: &Value) {
    check_outcome(
        replay_share_inputs(case),
        field(case, "expect"),
        |ok, expect| assert_eq!(ok, expect),
    );
}
