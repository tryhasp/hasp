use super::*;

pub(super) fn lifecycle_case(kind: &str, name: &str, commits: &[Commit], record: &[u8]) -> Value {
    let mut case = json!({
        "kind": kind,
        "name": name,
        "commits": commits.iter().map(commit_json).collect::<Vec<_>>(),
        "record": hex(record),
    });
    case["expect"] = expected(replay_lifecycle_inputs(&case));
    case
}

#[expect(clippy::unwrap_in_result, reason = "replay reads trusted fixtures")]
pub(super) fn replay_lifecycle_inputs(case: &Value) -> Result<Value, ProtoError> {
    let commits: Vec<Commit> = field(case, "commits")
        .as_array()
        .unwrap()
        .iter()
        .map(commit_from)
        .collect();
    let state = run_chain(&own_json(&Person::new(1)), &json!([]), &commits).unwrap();
    let record = bytes_of(case, "record");
    match field(case, "kind").as_str().unwrap() {
        "dissolve" => verify_dissolve(&Signed::<Dissolve>::from_cbor(&record)?, &state)
            .map(|d| json!({ "seq": d.seq.get(), "head": hex(d.head.as_bytes()) })),
        _ => verify_leave(&Signed::<LeaveRequest>::from_cbor(&record)?, &state)
            .map(|l| json!({ "account_id": hex(l.account_id.as_bytes()), "rver": l.rver.get() })),
    }
}

pub(super) fn replay_lifecycle(case: &Value) {
    check_outcome(
        replay_lifecycle_inputs(case),
        field(case, "expect"),
        |ok, expect| assert_eq!(ok, expect),
    );
}

pub(super) fn dissolve_and_leave_cases() -> Vec<Value> {
    let (_, commits) = share_fixture();
    let state = verify_prefix(&commits);
    let mut cases = dissolve_cases(&commits, &state);
    cases.extend(leave_cases(&commits, &state));
    cases
}

fn dissolve_cases(commits: &[Commit], state: &VaultState) -> Vec<Value> {
    let (owner, member) = (Person::new(1), Person::new(2));
    let dissolve = Dissolve {
        vault_id: state.roster.vault_id,
        rver: state.rver,
        epoch: state.epoch,
        seq: state.seq,
        head: state.hash,
    };
    let sign_d = |d: &Dissolve, p: &Person| {
        Signed::sign(SigLabel::Dissolve, d, &p.signing)
            .unwrap()
            .to_cbor()
            .unwrap()
    };
    vec![
        lifecycle_case(
            "dissolve",
            "dissolve_by_owner",
            commits,
            &sign_d(&dissolve, &owner),
        ),
        lifecycle_case(
            "dissolve",
            "dissolve_by_member",
            commits,
            &sign_d(&dissolve, &member),
        ),
        lifecycle_case(
            "dissolve",
            "dissolve_older_seq",
            commits,
            &sign_d(
                &Dissolve {
                    seq: Seq::new(1).unwrap(),
                    ..dissolve.clone()
                },
                &owner,
            ),
        ),
        lifecycle_case(
            "dissolve",
            "dissolve_other_head",
            commits,
            &sign_d(
                &Dissolve {
                    head: Hash32::from_bytes([4; 32]),
                    ..dissolve.clone()
                },
                &owner,
            ),
        ),
        lifecycle_case(
            "dissolve",
            "dissolve_other_vault",
            commits,
            &sign_d(
                &Dissolve {
                    vault_id: VaultId::from_bytes([2; 16]),
                    ..dissolve.clone()
                },
                &owner,
            ),
        ),
    ]
}

fn leave_cases(commits: &[Commit], state: &VaultState) -> Vec<Value> {
    let (owner, member, stranger) = (Person::new(1), Person::new(2), Person::new(3));
    let leave = LeaveRequest {
        vault_id: state.roster.vault_id,
        account_id: member.account,
        rver: state.rver,
        epoch: state.epoch,
    };
    let sign_l = |l: &LeaveRequest, p: &Person| {
        Signed::sign(SigLabel::Leave, l, &p.signing)
            .unwrap()
            .to_cbor()
            .unwrap()
    };
    vec![
        lifecycle_case(
            "leave",
            "leave_by_member",
            commits,
            &sign_l(&leave, &member),
        ),
        lifecycle_case(
            "leave",
            "leave_signed_by_other_key",
            commits,
            &sign_l(&leave, &stranger),
        ),
        lifecycle_case(
            "leave",
            "leave_by_owner",
            commits,
            &sign_l(
                &LeaveRequest {
                    account_id: owner.account,
                    ..leave.clone()
                },
                &owner,
            ),
        ),
        lifecycle_case(
            "leave",
            "leave_stale_roster_version",
            commits,
            &sign_l(
                &LeaveRequest {
                    rver: Rver::new(1).unwrap(),
                    ..leave.clone()
                },
                &member,
            ),
        ),
        lifecycle_case(
            "leave",
            "leave_stale_epoch",
            commits,
            &sign_l(
                &LeaveRequest {
                    epoch: Epoch::new(3).unwrap(),
                    ..leave.clone()
                },
                &member,
            ),
        ),
    ]
}
