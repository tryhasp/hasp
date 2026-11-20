use super::*;

#[test]
fn open_item_returns_contents_and_rejects_tampering() {
    let (mut vault, owner, pins, state) = setup();
    let commit = vault.put(1, 7, b"overview text");
    let wire = commit.ops[0].wire().clone();
    let bytes = wire.to_cbor().unwrap();
    let state = verify_batch(&state, &[commit], &owner.own(), &pins).unwrap();
    match open_item(&wire, &bytes, &state, vault.vk()).unwrap() {
        OpenedItem::Live {
            overview, details, ..
        } => {
            assert_eq!(overview.expose(), b"overview text");
            assert_eq!(details.expose(), b"details");
        }
        OpenedItem::Tombstone { .. } => panic!("expected a live item"),
    }
    let wrong_key = hasp_crypto::SecretKey::from_bytes([1; 32]);
    assert!(matches!(
        open_item(&wire, &bytes, &state, &wrong_key),
        Err(ProtoError::Aead)
    ));
    let mut tampered = bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(open_item(&wire, &tampered, &state, vault.vk()).is_err());
}

#[test]
fn open_item_rejects_swapped_payloads_and_stale_versions() {
    let (mut vault, owner, pins, state) = setup();
    let a = vault.put(1, 7, b"item a");
    let b = vault.put(1, 8, b"item b");
    let (wa, wb) = (a.ops[0].wire().clone(), b.ops[0].wire().clone());
    let state = verify_batch(&state, &[a, b], &owner.own(), &pins).unwrap();
    let (ItemBody::Live { ov: ova, .. }, ItemBody::Live { wrap, det, .. }) = (&wa.body, &wb.body)
    else {
        panic!("live items expected");
    };
    let swapped = ItemWire {
        body: ItemBody::Live {
            wrap: wrap.clone(),
            ov: ova.clone(),
            det: det.clone(),
        },
        ..wb
    };
    let swapped_bytes = swapped.to_cbor().unwrap();
    assert!(open_item(&swapped, &swapped_bytes, &state, vault.vk()).is_err());
    let older = ItemWire {
        ver: Version::new(9).unwrap(),
        ..wa.clone()
    };
    let older_bytes = older.to_cbor().unwrap();
    assert!(matches!(
        open_item(&older, &older_bytes, &state, vault.vk()),
        Err(ProtoError::Root)
    ));
    assert!(matches!(
        open_item(&wa, &older_bytes, &state, vault.vk()),
        Err(ProtoError::Format)
    ));
}

#[test]
fn open_item_reports_tombstones_and_unknown_items() {
    let (mut vault, owner, pins, state) = setup();
    let put = vault.put(1, 7, b"a");
    let del = vault.delete(1, 7);
    let tomb = del.ops[0].wire().clone();
    let bytes = tomb.to_cbor().unwrap();
    let state = verify_batch(&state, &[put, del], &owner.own(), &pins).unwrap();
    assert!(matches!(
        open_item(&tomb, &bytes, &state, vault.vk()),
        Ok(OpenedItem::Tombstone { .. })
    ));
    let unknown = ItemWire {
        item_id: Vault::item_id(99),
        ..tomb
    };
    let unknown_bytes = unknown.to_cbor().unwrap();
    assert!(matches!(
        open_item(&unknown, &unknown_bytes, &state, vault.vk()),
        Err(ProtoError::Root)
    ));
}

#[test]
fn leafset_roots_are_order_independent_and_change_with_content() {
    let (mut vault, ..) = setup();
    let a = vault.put(1, 3, b"a");
    let b = vault.put(1, 2, b"b");
    let mut forward = crate::LeafSet::new();
    let mut backward = crate::LeafSet::new();
    for op in [&a.ops[0], &b.ops[0]] {
        forward.apply(op).unwrap();
    }
    for op in [&b.ops[0], &a.ops[0]] {
        backward.apply(op).unwrap();
    }
    assert_eq!(
        leafset_root(&forward).unwrap(),
        leafset_root(&backward).unwrap()
    );
    assert_ne!(
        leafset_root(&forward).unwrap(),
        leafset_root(&crate::LeafSet::new()).unwrap()
    );
    let _: Option<&ItemOp> = None;
    let _: Option<Seq> = None;
    let _: Option<&Roster> = None;
    let _: Option<&SigningKey> = None;
}

#[test]
fn stateless_chain_replay_skips_intermediate_leaf_sets_and_checks_the_head_root() {
    use crate::{HeadRoot, verify_chain};
    let mut vault = Vault::new(VaultKind::Shared, 1);
    let owner = Person::new(1);
    let pins = PinState::new();
    let mut commits = vec![vault.genesis()];
    commits.push(vault.put(1, 7, b"v1"));
    commits.push(vault.put(1, 7, b"v2"));
    commits.push(vault.put(1, 7, b"v3"));
    commits.push(vault.put(1, 8, b"other"));
    let pruned: Vec<_> = commits
        .iter()
        .enumerate()
        .map(|(i, commit)| {
            let mut commit = commit.clone();
            if i == 1 || i == 2 {
                commit.ops.clear();
            }
            commit
        })
        .collect();
    let pruned_result = verify_chain(None, &pruned, &owner.own(), &pins, HeadRoot::Check);
    assert!(pruned_result.is_ok(), "{pruned_result:?}");
    assert!(verify_chain(None, &commits, &owner.own(), &pins, HeadRoot::Check).is_ok());
    let strict = verify_genesis(&pruned[0], &owner.own(), &pins).unwrap();
    assert!(matches!(
        expect(verify_batch(&strict, &pruned[1..], &owner.own(), &pins)),
        ProtoError::Root | ProtoError::Epoch
    ));

    let mut wrong_root = pruned.clone();
    wrong_root.last_mut().unwrap().ops.clear();
    let error = verify_chain(None, &wrong_root, &owner.own(), &pins, HeadRoot::Check).unwrap_err();
    assert_eq!(error.index, wrong_root.len() - 1);
    assert!(matches!(error.error, ProtoError::Root));
    assert!(verify_chain(None, &wrong_root, &owner.own(), &pins, HeadRoot::Skip).is_ok());

    let mut forged = pruned.clone();
    resign(&mut forged[2], &Person::new(9), |_| {});
    let error = verify_chain(None, &forged, &owner.own(), &pins, HeadRoot::Check).unwrap_err();
    assert_eq!(error.index, 2);
    assert!(matches!(error.error, ProtoError::Sig | ProtoError::Authz));

    let mut gap = pruned.clone();
    gap.remove(2);
    let error = verify_chain(None, &gap, &owner.own(), &pins, HeadRoot::Check).unwrap_err();
    assert!(matches!(
        error.error,
        ProtoError::Rollback | ProtoError::Fork
    ));
}

#[test]
fn absorb_keeps_the_highest_version_and_ignores_stale_ones() {
    let mut vault = Vault::new(VaultKind::Shared, 1);
    vault.genesis();
    let older = vault.put(1, 7, b"v1").ops[0].clone();
    let newer = vault.put(1, 7, b"v2").ops[0].clone();
    let mut leaves = crate::LeafSet::new();
    leaves.absorb(&newer);
    leaves.absorb(&older);
    let leaf = leaves.get(&Vault::item_id(7)).unwrap();
    assert_eq!(leaf.ver, newer.wire().ver);
    assert_eq!(leaf.h_item, *newer.h_item());
}

fn stored(wires: &[&ItemWire]) -> Vec<(Version, Epoch, Vec<u8>)> {
    wires
        .iter()
        .map(|wire| (wire.ver, wire.epoch, wire.to_cbor().unwrap()))
        .collect()
}

#[test]
fn history_chains_back_through_prev_h_and_a_forged_version_breaks_the_chain() {
    use crate::{chained_history, item_wire_hash};
    let mut vault = Vault::new(VaultKind::Shared, 1);
    vault.genesis();
    let v1 = vault.put(1, 7, b"v1").ops[0].wire().clone();
    let v2 = vault.put(1, 7, b"v2").ops[0].wire().clone();
    let v3 = vault.put(1, 7, b"v3").ops[0].wire().clone();
    assert_eq!(v1.prev_h, None);
    assert_eq!(v2.prev_h, Some(item_wire_hash(&v1.to_cbor().unwrap())));
    assert_eq!(v3.prev_h, Some(item_wire_hash(&v2.to_cbor().unwrap())));

    let honest = chained_history(&v3, &stored(&[&v1, &v2, &v3]));
    assert_eq!(honest, vec![(v2.ver, v2.epoch), (v1.ver, v1.epoch)]);

    let forged_v2 = vault.seal(7, 2, 0, b"forged by a holder of the vault key");
    assert_eq!(forged_v2.ver, v2.ver);
    assert!(chained_history(&v3, &stored(&[&v1, &forged_v2, &v3])).is_empty());

    let forged_v1 = vault.seal(7, 1, 0, b"forged");
    assert_eq!(
        chained_history(&v3, &stored(&[&forged_v1, &v2, &v3])),
        vec![(v2.ver, v2.epoch)]
    );

    let other_item = vault.seal(8, 2, 0, b"not this item");
    assert!(chained_history(&v3, &stored(&[&other_item, &v3])).is_empty());
}

#[test]
fn an_unverified_pin_is_reported_apart_from_ok() {
    use crate::{Pin, PinCheck, PinLevel, PinState, pin_check};
    let person = Person::new(1);
    let mut pins = PinState::new();
    pins.insert(
        person.account,
        Pin::new(person.ik_pk, &person.kem_pk, PinLevel::Unverified),
    );
    assert_eq!(
        pin_check(&pins, &person.account, &person.ik_pk, &person.kem_pk),
        PinCheck::Unverified
    );
    pins.insert(
        person.account,
        Pin::new(person.ik_pk, &person.kem_pk, PinLevel::Tofu),
    );
    assert_eq!(
        pin_check(&pins, &person.account, &person.ik_pk, &person.kem_pk),
        PinCheck::Ok
    );
}

#[test]
fn chain_replay_checks_the_epoch_of_every_op_against_its_manifest() {
    use crate::{HeadRoot, verify_chain};
    let mut vault = Vault::new(VaultKind::Shared, 1);
    let owner = Person::new(1);
    let mut commits = vec![vault.genesis()];
    commits.push(vault.put(1, 7, b"v1"));
    let mut moved = commits[1].ops[0].wire().clone();
    moved.epoch = Epoch::new(1).unwrap();
    commits[1].ops[0] = ItemOp::from_wire_bytes(&moved.to_cbor().unwrap()).unwrap();
    let error = verify_chain(
        None,
        &commits,
        &owner.own(),
        &PinState::new(),
        HeadRoot::Skip,
    )
    .unwrap_err();
    assert_eq!(error.index, 1);
    assert!(matches!(error.error, ProtoError::Epoch));
}
