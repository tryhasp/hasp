use super::*;

pub(super) fn verify_vectors() -> Value {
    let mut cases = chain_cases();
    cases.extend(repair_cases());
    cases.extend(account_cases());
    cases.extend(share_cases());
    cases.extend(item_cases());
    cases.extend(dissolve_and_leave_cases());
    json!({ "description": "Record verification cases: every case lists its inputs as hex and the expected outcome.", "cases": cases })
}

#[test]
pub(super) fn verification_vectors_are_current_and_replay() {
    let vectors = sync("verify.json", verify_vectors());
    let mut count = 0;
    for case in field(&vectors, "cases").as_array().unwrap() {
        match field(case, "kind").as_str().unwrap() {
            "chain" => replay_chain(case),
            "repair" => replay_repair(case),
            "account" => replay_account(case),
            "share" => replay_share(case),
            "item" => replay_item(case),
            "dissolve" | "leave" => replay_lifecycle(case),
            other => panic!("unknown kind {other}"),
        }
        count += 1;
    }
    assert!(count >= 60, "{count}");
}
