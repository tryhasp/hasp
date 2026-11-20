use super::*;

fn add_chain(
    cases: &mut Vec<Value>,
    name: &str,
    own: &Person,
    pins: &[&Person],
    commits: impl AsRef<[Commit]>,
) {
    cases.push(chain_case(name, own, pins, commits.as_ref()));
}

pub(super) fn chain_cases() -> Vec<Value> {
    let (owner, editor) = (Person::new(1), Person::new(2));
    let mut cases = Vec::new();
    lifecycle_and_fork_cases(&mut cases, &owner, &editor);
    manifest_field_cases(&mut cases, &owner, &editor);
    roster_and_epoch_cases(&mut cases, &owner);
    record_and_genesis_cases(&mut cases, &owner, &editor);
    cases
}

fn lifecycle_and_fork_cases(cases: &mut Vec<Value>, owner: &Person, editor: &Person) {
    let (mut vault, prefix) = base();
    let mut ok = prefix.clone();
    ok.push(vault.put(2, 8, b"by editor"));
    ok.push(vault.change_role(2, Role::Viewer));
    ok.push(vault.delete(1, 7));
    ok.push(vault.remove_member(2));
    ok.push(vault.put(1, 9, b"after removal"));
    add_chain(cases, "ok_lifecycle_owner_view", owner, &[], ok.clone());
    add_chain(cases, "ok_lifecycle_member_view", editor, &[], ok);

    let (_, mut replay) = base();
    replay.push(replay[2].clone());
    add_chain(cases, "rollback_replayed_commit", owner, &[], replay);

    let (mut vault, mut gap) = base();
    let _skipped = vault.put(1, 8, b"dropped");
    gap.push(vault.put(1, 9, b"after the gap"));
    add_chain(cases, "rollback_dropped_commit", owner, &[], gap);

    let (_, mut chain) = base();
    let mut rival = Vault::new(VaultKind::Shared, 1);
    rival.genesis();
    rival.put(1, 7, b"first");
    chain.push(rival.put(1, 5, b"conflicting commit at the same seq"));
    add_chain(cases, "fork_two_commits_at_one_seq", owner, &[], chain);

    let (mut vault, mut prev) = base();
    let mut commit = vault.put(1, 8, b"x");
    resign(&mut commit, owner, |m| {
        m.prev = Some(Hash32::from_bytes([9; 32]));
    });
    prev.push(commit);
    add_chain(cases, "fork_wrong_prev", owner, &[], prev);

    let mutations: [(&str, Mutation); 5] = [
        ("root_mismatch", |m| m.root = Hash32::from_bytes([7; 32])),
        ("roster_hash_mismatch", |m| {
            m.roster_hash = Hash32::from_bytes([7; 32]);
        }),
        ("roster_version_mismatch", |m| {
            m.rver = Rver::new(9).unwrap();
        }),
        ("epoch_mismatch", |m| m.epoch = Epoch::new(5).unwrap()),
        ("vault_mismatch", |m| {
            m.vault_id = VaultId::from_bytes([9; 16]);
        }),
    ];
    for (name, edit) in mutations {
        let (mut vault, mut chain) = base();
        let mut commit = vault.put(1, 8, b"x");
        resign(&mut commit, owner, edit);
        chain.push(commit);
        add_chain(cases, name, owner, &[], chain);
    }
}

fn manifest_field_cases(cases: &mut Vec<Value>, owner: &Person, editor: &Person) {
    let (mut vault, mut forged) = base();
    let mut commit = vault.put(1, 8, b"x");
    let mut sig = *commit.manifest.sig.as_bytes();
    sig[3] ^= 0x40;
    commit.manifest.sig = hasp_crypto::Signature::from_bytes(sig);
    forged.push(commit);
    add_chain(cases, "signature_bit_flipped", owner, &[], forged);

    let (mut vault, mut foreign) = base();
    let mut commit = vault.put(1, 8, b"x");
    resign(&mut commit, &Person::new(9), |_| {});
    foreign.push(commit);
    add_chain(cases, "signature_from_foreign_key", owner, &[], foreign);

    let (mut vault, mut stranger) = base();
    let mut commit = vault.put(1, 8, b"x");
    let outsider = Person::new(9);
    resign(&mut commit, &outsider, |m| m.author = outsider.account);
    stranger.push(commit);
    add_chain(cases, "author_not_in_roster", owner, &[], stranger);

    let mut viewer_vault = Vault::new(VaultKind::Shared, 1);
    let mut viewer = vec![
        viewer_vault.genesis(),
        viewer_vault.add_member(2, Role::Viewer),
    ];
    viewer.push(viewer_vault.put(2, 7, b"viewer write"));
    add_chain(cases, "viewer_cannot_write", owner, &[], viewer);

    let (mut vault, mut repair_flag) = base();
    let mut commit = vault.put(2, 8, b"x");
    resign(&mut commit, editor, |m| m.repair = true);
    repair_flag.push(commit);
    add_chain(cases, "editor_cannot_flag_repair", owner, &[], repair_flag);

    let (mut vault, mut stale) = base();
    stale.push(vault.remove_member(2));
    let old_roster_hash = stale[2].manifest.unverified().unwrap().roster_hash;
    let mut late = vault.put(2, 9, b"stale signer");
    resign(&mut late, editor, |m| {
        m.rver = Rver::new(2).unwrap();
        m.roster_hash = old_roster_hash;
        m.epoch = Epoch::new(0).unwrap();
    });
    stale.push(late);
    add_chain(
        cases,
        "stale_roster_signer_after_removal",
        owner,
        &[],
        stale,
    );
}

fn roster_and_epoch_cases(cases: &mut Vec<Value>, owner: &Person) {
    let (mut vault, mut no_bump) = base();
    vault.rver = bump(vault.rver);
    vault.others.remove(&2);
    let vk = vault.vk().clone_key();
    let roster = vault.roster_body(vault.rver, vault.epoch, &vk);
    let signed = vault.sign_roster(&roster);
    vault.roster = Some((roster, signed.hash()));
    no_bump.push(vault.finish(1, Some(signed), Vec::new(), Vec::new()));
    add_chain(cases, "removal_without_epoch_bump", owner, &[], no_bump);

    let (mut vault, mut no_commit) = base();
    vault.rver = bump(vault.rver);
    let vk = vault.vk().clone_key();
    let mut roster = vault.roster_body(vault.rver, 1, &vk);
    roster.vk_commit = vault.roster.clone().unwrap().0.vk_commit;
    let signed = vault.sign_roster(&roster);
    vault.roster = Some((roster, signed.hash()));
    vault.epoch = 1;
    no_commit.push(vault.finish(1, Some(signed), Vec::new(), Vec::new()));
    add_chain(
        cases,
        "epoch_bump_without_new_vk_commit",
        owner,
        &[],
        no_commit,
    );

    let (mut vault, mut low_epoch) = base();
    let mut removal = vault.remove_member(2);
    removal.ops.clear();
    resign(&mut removal, owner, |_| {});
    low_epoch.push(removal);
    add_chain(
        cases,
        "live_leaf_below_manifest_epoch",
        owner,
        &[],
        low_epoch,
    );

    let (mut vault, mut skip) = base();
    let wire = vault.seal(8, 2, 0, b"skips version one");
    skip.push(vault.finish_unchecked(1, vec![wire]));
    add_chain(cases, "item_version_skips", owner, &[], skip);

    let (mut vault, mut alien) = base();
    let mut wire = vault.seal(8, 1, 0, b"alien");
    wire.vault_id = VaultId::from_bytes([3; 16]);
    alien.push(vault.finish_unchecked(1, vec![wire]));
    add_chain(cases, "item_from_another_vault", owner, &[], alien);

    let (mut vault, mut versioned) = base();
    let mut commit = vault.put(1, 8, b"x");
    let mut body = commit.manifest.body.clone();
    body[2] = 0x02;
    commit.manifest = resigned_bytes(owner, body);
    versioned.push(commit);
    add_chain(cases, "record_version_two", owner, &[], versioned);

    let (mut vault, mut wrong_type) = base();
    let mut commit = vault.put(1, 8, b"x");
    let mut body = commit.manifest.body.clone();
    body[4] = 0x03;
    commit.manifest = resigned_bytes(owner, body);
    wrong_type.push(commit);
    add_chain(cases, "record_type_mismatch", owner, &[], wrong_type);
}

fn record_and_genesis_cases(cases: &mut Vec<Value>, owner: &Person, editor: &Person) {
    let mut genesis_vault = Vault::new(VaultKind::Shared, 1);
    genesis_vault.others.insert(2, (Role::Editor, 1));
    genesis_vault.rver = 1;
    let vk = genesis_vault.vk().clone_key();
    let mut roster = genesis_vault.roster_body(1, 0, &vk);
    let imposter = Person::new(7);
    roster.members[1].ik_pk = imposter.ik_pk;
    roster.members[1].kem_pk = imposter.kem_pk.clone();
    let signed = genesis_vault.sign_roster(&roster);
    genesis_vault.roster = Some((roster, signed.hash()));
    let genesis = genesis_vault.finish(1, Some(signed), Vec::new(), Vec::new());
    add_chain(
        cases,
        "genesis_roster_substitutes_own_keys",
        editor,
        &[],
        vec![genesis],
    );

    let mut two_owners = Vault::new(VaultKind::Shared, 1);
    two_owners.others.insert(2, (Role::Owner, 1));
    two_owners.rver = 1;
    let vk = two_owners.vk().clone_key();
    let roster = two_owners.roster_body(1, 0, &vk);
    let signed = two_owners.sign_roster(&roster);
    two_owners.roster = Some((roster, signed.hash()));
    let genesis = two_owners.finish(1, Some(signed), Vec::new(), Vec::new());
    add_chain(
        cases,
        "genesis_roster_with_two_owners",
        owner,
        &[],
        vec![genesis],
    );

    let (_, mut pinned) = base();
    pinned.truncate(3);
    let wrong_pin = Person::new(8);
    let mut pin_case = chain_case("member_pin_key_changed", owner, &[], &pinned);
    pin_case["pins"] = json!([{
        "account_id": hex(editor.account.as_bytes()),
        "ik_pk": hex(wrong_pin.ik_pk.as_bytes()),
        "kem_pk": hex(wrong_pin.kem_pk.as_bytes()),
    }]);
    pin_case["expect"] =
        expected(run_chain(&pin_case["own"], &pin_case["pins"], &pinned).map(|s| state_json(&s)));
    cases.push(pin_case);
}

pub(super) fn resigned_bytes(author: &Person, body: Vec<u8>) -> Signed<Manifest> {
    let sig = author
        .signing
        .sign(&[SigLabel::Manifest.name().as_bytes(), &[0], &body].concat());
    Signed::from_parts(body, author.ik_pk, sig)
}

pub(super) fn repair_cases() -> Vec<Value> {
    let (owner, editor) = (Person::new(1), Person::new(2));
    let (mut vault, prefix) = base();
    let state = verify_prefix(&prefix);
    let mut bad = vault.put(2, 7, b"bad root");
    resign(&mut bad, &editor, |m| m.root = Hash32::from_bytes([7; 32]));
    let mut repairer = Vault::new(VaultKind::Shared, 1);
    repairer.mirror(&vault, &state);
    let mut repair = repairer.put(1, 8, b"repair content");
    resign(&mut repair, &owner, |m| {
        m.repair = true;
        m.prev = Some(state.hash);
        m.seq = state.seq.checked_next().unwrap();
    });
    let mut by_editor = repair.clone();
    resign(&mut by_editor, &editor, |m| m.author = editor.account);
    let mut unflagged = repair.clone();
    resign(&mut unflagged, &owner, |m| m.repair = false);
    let variants: [(&str, Option<&Commit>, Commit); 4] = [
        ("repair_with_quarantined_commit", Some(&bad), repair.clone()),
        ("repair_without_quarantined_commit", None, repair.clone()),
        ("repair_signed_by_editor", None, by_editor),
        ("repair_not_flagged", None, unflagged),
    ];
    variants
        .into_iter()
        .map(|(name, quarantined, repair)| {
            let outcome = verify_repair(&state, quarantined, &repair).map(|s| state_json(&s));
            json!({
                "kind": "repair",
                "name": name,
                "own": own_json(&owner),
                "pins": [],
                "commits": prefix.iter().map(commit_json).collect::<Vec<_>>(),
                "quarantined": quarantined.map(commit_json),
                "repair": commit_json(&repair),
                "expect": expected(outcome),
            })
        })
        .collect()
}

pub(super) fn replay_repair(case: &Value) {
    let commits: Vec<Commit> = field(case, "commits")
        .as_array()
        .unwrap()
        .iter()
        .map(commit_from)
        .collect();
    let state = run_chain(field(case, "own"), field(case, "pins"), &commits).unwrap();
    let quarantined = field(case, "quarantined")
        .as_object()
        .map(|_| commit_from(field(case, "quarantined")));
    let repair = commit_from(field(case, "repair"));
    check_outcome(
        verify_repair(&state, quarantined.as_ref(), &repair),
        field(case, "expect"),
        check_state,
    );
}
