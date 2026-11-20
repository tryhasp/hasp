use core::fmt::Debug;

use hasp_crypto::SecretKey;

use crate::testkit::{Entry, Person, Vault, dissolve_entries, map_bytes};
use crate::{
    Aad, AccountId, AccountRecord, AccountStatus, AttId, Dissolve, Epoch, Hash32, InviteCode,
    InviteId, ItemBody, ItemWire, KdfWire, Keyset, KeysetKeys, Leaf, LeafFlag, LeaveRequest,
    Manifest, ProtoError, RecoveryEnrolment, Role, Rtype, Rver, Sealed, SealedRaw, Seq, SigLabel,
    Signed, Uint53, VaultId, VaultKind, Version, Wire, Writer, fingerprint, format_fingerprint,
    head_code, parse_fingerprint, rewrap_item, tombstone,
};

fn assert_strict<T: Wire + PartialEq + Debug>(value: &T) {
    let bytes = value.to_cbor().unwrap();
    assert_eq!(&T::from_cbor(&bytes).unwrap(), value);
    for end in 0..bytes.len() {
        assert!(T::from_cbor(&bytes[..end]).is_err(), "truncated at {end}");
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(T::from_cbor(&longer).is_err());
    for index in 0..bytes.len() {
        let mut mutated = bytes.clone();
        mutated[index] ^= 1 << (index % 8);
        if let Ok(decoded) = T::from_cbor(&mutated) {
            assert_eq!(decoded.to_cbor().unwrap(), mutated);
        }
    }
}

fn drop_last(text: &str) -> String {
    let mut owned = text.to_owned();
    owned.pop();
    owned
}

fn shared_vault() -> (Vault, crate::VaultState) {
    let mut vault = Vault::new(VaultKind::Shared, 1);
    let owner = Person::new(1);
    let genesis = vault.genesis();
    let put = vault.put(1, 7, b"overview");
    let joined = vault.add_member(2, Role::Editor);
    let state = crate::verify_genesis(&genesis, &owner.own(), &crate::PinState::new()).unwrap();
    let state = crate::verify_batch(
        &state,
        &[put, joined],
        &owner.own(),
        &crate::PinState::new(),
    )
    .unwrap();
    (vault, state)
}

#[test]
fn every_record_type_roundtrips_and_rejects_truncation_extension_and_bit_flips() {
    let (vault, state) = shared_vault();
    let p = Person::new(1);
    assert_strict(&state.roster);
    assert_strict(&Manifest {
        vault_id: state.roster.vault_id,
        seq: Seq::new(2).unwrap(),
        prev: Some(Hash32::from_bytes([1; 32])),
        epoch: Epoch::new(0).unwrap(),
        rver: Rver::new(1).unwrap(),
        roster_hash: Hash32::from_bytes([2; 32]),
        root: Hash32::from_bytes([3; 32]),
        author: p.account,
        repair: true,
    });
    assert_strict(vault.items.values().next().unwrap());
    assert_strict(&tombstone(
        vault.id,
        Vault::item_id(9),
        Version::new(3).unwrap(),
        Epoch::new(1).unwrap(),
        None,
    ));
    assert_strict(&AccountRecord {
        account_id: p.account,
        seq: Seq::new(1).unwrap(),
        prev: None,
        ik_pk: p.ik_pk,
        kem_pk: p.kem_pk.clone(),
        kdf: KdfWire {
            m: 65_536,
            t: 3,
            p: 4,
        },
        status: AccountStatus::Deleted,
        rc_gen: Uint53::new(2).unwrap(),
        min_v: Uint53::new(1).unwrap(),
        created: Uint53::new(1_700_000_000).unwrap(),
    });
    assert_strict(&RecoveryEnrolment {
        account_id: p.account,
        rgen: Uint53::new(4).unwrap(),
        h_wrap: Hash32::from_bytes([6; 32]),
    });
    assert_strict(&Dissolve {
        vault_id: vault.id,
        rver: Rver::new(2).unwrap(),
        epoch: Epoch::new(0).unwrap(),
        seq: Seq::new(3).unwrap(),
        head: Hash32::from_bytes([7; 32]),
    });
    assert_strict(&LeaveRequest {
        vault_id: vault.id,
        account_id: AccountId::from_bytes([2; 16]),
        rver: Rver::new(2).unwrap(),
        epoch: Epoch::new(0).unwrap(),
    });
    assert_strict(&Leaf {
        item_id: Vault::item_id(7),
        ver: Version::new(1).unwrap(),
        epoch: Epoch::new(0).unwrap(),
        h_item: Hash32::from_bytes([8; 32]),
        flag: LeafFlag::Tombstone,
    });
    assert_strict(&InviteCode {
        invite_id: InviteId::from_bytes([1; 16]),
        fp_owner: [2; 15],
        origin: "https://hasp.example".to_owned(),
    });
}

#[test]
fn share_and_signed_wrappers_roundtrip_strictly() {
    let (_, state) = shared_vault();
    let mut vault = Vault::new(VaultKind::Shared, 1);
    vault.genesis();
    let commit = vault.add_member(2, Role::Editor);
    let share = commit.shares[0].clone();
    assert_strict(&share.unverified().unwrap());
    assert_strict(&share);
    assert_strict(&commit.manifest);
    assert_eq!(state.roster.members.len(), 2);
}

#[test]
fn sealed_types_roundtrip_and_keys_payload_opens_with_its_aad() {
    let account = AccountId::from_bytes([1; 16]);
    let key = SecretKey::from_bytes([5; 32]);
    let keys = KeysetKeys {
        ik_seed: SecretKey::from_bytes([1; 32]),
        kem_seed: SecretKey::from_bytes([2; 32]),
        sk_ascii: hasp_crypto::SecretBytes::from_vec(b"ABCDEFGHJKLMNPQRSTVWXYZ234".to_vec()),
        retired: Vec::new(),
    };
    let aad = Aad::keyset_keys(account, Uint53::new(1).unwrap());
    let sealed = Sealed::seal(&key, &keys, &aad).unwrap();
    assert_eq!(sealed.ct().len(), 256 + 16);
    let opened = sealed.open(&key, &aad).unwrap();
    assert_eq!(opened.ik_seed.expose(), keys.ik_seed.expose());
    assert_eq!(opened.sk_ascii.expose(), keys.sk_ascii.expose());
    assert!(opened.retired.is_empty());
    assert_eq!(format!("{keys:?}"), "KeysetKeys(..)");
    let wrong_gen = Aad::keyset_keys(account, Uint53::new(2).unwrap());
    assert!(matches!(
        sealed.open(&key, &wrong_gen),
        Err(ProtoError::Aead)
    ));
    let keyset = Keyset {
        account_id: account,
        generation: Uint53::new(1).unwrap(),
        ak_wrap: SealedRaw::seal(
            &key,
            &[1; 32],
            &Aad::ak_wrap(
                account,
                &KdfWire {
                    m: 65_536,
                    t: 3,
                    p: 4,
                },
                Uint53::new(1).unwrap(),
            ),
        )
        .unwrap(),
        keys: sealed,
    };
    assert_strict(&keyset);
}

#[test]
fn keys_payload_with_retired_entries_is_refused() {
    let mut w = Writer::new();
    w.map(4).unwrap();
    w.key(0).unwrap();
    w.bytes(&[1; 32]).unwrap();
    w.key(1).unwrap();
    w.bytes(&[2; 32]).unwrap();
    w.key(2).unwrap();
    w.bytes(b"ABCDEFGHJKLMNPQRSTVWXYZ234").unwrap();
    w.key(3).unwrap();
    w.array(1).unwrap();
    w.uint(0).unwrap();
    assert!(KeysetKeys::from_cbor(&w.into_bytes()).is_err());
}

#[test]
fn reference_dissolve_bytes_decode() {
    assert!(Dissolve::from_cbor(&map_bytes(&dissolve_entries(1, 15))).is_ok());
}

#[test]
fn versions_other_than_one_are_version_errors_and_wrong_rtype_is_format() {
    for version in [0, 2, 3, 255] {
        assert!(matches!(
            Dissolve::from_cbor(&map_bytes(&dissolve_entries(version, 15))),
            Err(ProtoError::Version)
        ));
    }
    assert!(matches!(
        Dissolve::from_cbor(&map_bytes(&dissolve_entries(1, 16))),
        Err(ProtoError::Format)
    ));
    assert!(matches!(
        LeaveRequest::from_cbor(&map_bytes(&dissolve_entries(1, 15))),
        Err(ProtoError::Format)
    ));
}

#[test]
fn unsorted_duplicate_unknown_and_missing_keys_are_refused() {
    let mut unsorted = dissolve_entries(1, 15);
    unsorted.swap(2, 3);
    let mut duplicate = dissolve_entries(1, 15);
    duplicate[3].0 = 2;
    let mut unknown = dissolve_entries(1, 15);
    unknown.push((7, Entry::Uint(0)));
    let mut missing = dissolve_entries(1, 15);
    missing.pop();
    let mut shifted = dissolve_entries(1, 15);
    shifted[6].0 = 9;
    let mut high_key = dissolve_entries(1, 15);
    high_key[6].0 = 256;
    for entries in [unsorted, duplicate, unknown, missing, shifted, high_key] {
        assert!(matches!(
            Dissolve::from_cbor(&map_bytes(&entries)),
            Err(ProtoError::Format)
        ));
    }
}

#[test]
fn wrong_types_nulls_and_unsupported_encodings_are_refused() {
    let mut text_id = dissolve_entries(1, 15);
    text_id[2].1 = Entry::Text("0123456789abcdef");
    let mut null_rver = dissolve_entries(1, 15);
    null_rver[3].1 = Entry::Null;
    let mut short_id = dissolve_entries(1, 15);
    short_id[2].1 = Entry::Bytes(vec![1; 15]);
    let mut huge = dissolve_entries(1, 15);
    huge[3].1 = Entry::Uint(1 << 53);
    for entries in [text_id, null_rver, short_id, huge] {
        assert!(matches!(
            Dissolve::from_cbor(&map_bytes(&entries)),
            Err(ProtoError::Format)
        ));
    }
    let good = map_bytes(&dissolve_entries(1, 15));
    let mut indefinite = vec![0xbf];
    indefinite.extend_from_slice(&good[1..]);
    indefinite.push(0xff);
    assert!(matches!(
        Dissolve::from_cbor(&indefinite),
        Err(ProtoError::Format)
    ));
    let mut long_key = good.clone();
    long_key.splice(1..2, [0x18, 0x00]);
    assert!(matches!(
        Dissolve::from_cbor(&long_key),
        Err(ProtoError::Format)
    ));
    let mut tagged = vec![0xd9, 0xd9, 0xf7];
    tagged.extend_from_slice(&good);
    assert!(matches!(
        Dissolve::from_cbor(&tagged),
        Err(ProtoError::Format)
    ));
    let mut float_value = good;
    let last = float_value.len() - 34;
    float_value.splice(last..=last, [0xf9, 0x3c, 0x00]);
    assert!(matches!(
        Dissolve::from_cbor(&float_value),
        Err(ProtoError::Format)
    ));
}

#[test]
fn oversized_input_is_refused_before_parsing() {
    let huge = vec![0_u8; crate::MAX_RECORD + 1];
    assert!(matches!(
        Dissolve::from_cbor(&huge),
        Err(ProtoError::Format)
    ));
}

#[test]
fn array_counts_beyond_the_remaining_input_are_refused() {
    let mut w = Writer::new();
    w.array(crate::MAX_ARRAY).unwrap();
    assert!(Vec::<Hash32>::from_cbor(&w.into_bytes()).is_err());
    let mut w = Writer::new();
    w.array(crate::MAX_ARRAY + 1).unwrap();
    w.bytes(&[0; 32]).unwrap();
    assert!(Vec::<Hash32>::from_cbor(&w.into_bytes()).is_err());
}

#[test]
fn enum_codes_outside_the_defined_set_are_refused() {
    assert!(Role::from_cbor(&[0x04]).is_err());
    assert!(Role::from_cbor(&[0x00]).is_err());
    assert!(VaultKind::from_cbor(&[0x03]).is_err());
    assert!(AccountStatus::from_cbor(&[0x03]).is_err());
    assert!(Role::from_cbor(&[0x02]).is_ok());
}

#[test]
fn item_wire_shape_is_tied_to_its_body_kind() {
    let (vault, _) = shared_vault();
    let live = vault.items.values().next().unwrap().clone();
    let tomb_with_attachments = ItemWire {
        body: ItemBody::Tombstone,
        att_ids: vec![AttId::from_bytes([1; 16])],
        ..live.clone()
    };
    assert!(matches!(
        ItemWire::from_cbor(&tomb_with_attachments.to_cbor().unwrap()),
        Err(ProtoError::Format)
    ));
    let mut with_att = live;
    with_att.att_ids = vec![AttId::from_bytes([1; 16]), AttId::from_bytes([2; 16])];
    assert_strict(&with_att);
}

#[test]
fn rewrap_requires_a_live_item_and_the_old_key() {
    let (vault, _) = shared_vault();
    let live = vault.items.values().next().unwrap();
    let mut entropy = crate::SeededEntropy::new([1; 32]);
    let new_vk = SecretKey::from_bytes([9; 32]);
    assert!(
        rewrap_item(
            &mut entropy,
            vault.vk(),
            &new_vk,
            live,
            Epoch::new(1).unwrap()
        )
        .is_ok()
    );
    assert!(rewrap_item(&mut entropy, &new_vk, &new_vk, live, Epoch::new(1).unwrap()).is_err());
    let tomb = tombstone(
        vault.id,
        Vault::item_id(7),
        Version::new(2).unwrap(),
        Epoch::new(0).unwrap(),
        None,
    );
    assert!(
        rewrap_item(
            &mut entropy,
            vault.vk(),
            &new_vk,
            &tomb,
            Epoch::new(1).unwrap()
        )
        .is_err()
    );
}

#[test]
fn signed_wrapper_rejects_malformed_structure() {
    let p = Person::new(1);
    let record = Dissolve {
        vault_id: VaultId::from_bytes([1; 16]),
        rver: Rver::new(1).unwrap(),
        epoch: Epoch::new(0).unwrap(),
        seq: Seq::new(1).unwrap(),
        head: Hash32::from_bytes([1; 32]),
    };
    let signed = Signed::sign(SigLabel::Dissolve, &record, &p.signing).unwrap();
    let bytes = signed.to_cbor().unwrap();
    assert_eq!(&bytes[..2], [0x83, 0x58]);
    assert!(Signed::<Dissolve>::from_cbor(&bytes).is_ok());
    let mut two = Writer::new();
    two.array(2).unwrap();
    two.bytes(&signed.body).unwrap();
    two.bytes(signed.signer.as_bytes()).unwrap();
    assert!(Signed::<Dissolve>::from_cbor(&two.into_bytes()).is_err());
    assert!(signed.verify(SigLabel::Leave, &p.ik_pk).is_err());
    assert_eq!(signed.verify(SigLabel::Dissolve, &p.ik_pk).unwrap(), record);
    let _ = Rtype::Account;
}

#[test]
fn invite_text_roundtrips_and_rejects_corruption() {
    let code = InviteCode {
        invite_id: InviteId::from_bytes([0xab; 16]),
        fp_owner: [0xcd; 15],
        origin: "https://hasp.example".to_owned(),
    };
    let text = code.to_text().unwrap();
    assert!(text.starts_with("INV1-"));
    assert_eq!(InviteCode::parse(&text).unwrap(), code);
    assert_eq!(InviteCode::parse(&text.to_lowercase()).unwrap(), code);
    assert!(InviteCode::parse(&text.replacen("INV1-", "INV2-", 1)).is_err());
    assert!(InviteCode::parse(text.strip_prefix("INV1-").unwrap()).is_err());
    assert!(InviteCode::parse(&format!("{text}A")).is_err());
    assert!(InviteCode::parse(&drop_last(&text)).is_err());
    assert!(InviteCode::parse("INV1-U!").is_err());
}

#[test]
fn invite_version_and_origin_limits_are_enforced() {
    let mut version_two = Writer::new();
    version_two.map(4).unwrap();
    version_two.key(0).unwrap();
    version_two.uint(2).unwrap();
    version_two.key(1).unwrap();
    version_two.bytes(&[0; 16]).unwrap();
    version_two.key(2).unwrap();
    version_two.bytes(&[0; 15]).unwrap();
    version_two.key(3).unwrap();
    version_two.text("x").unwrap();
    assert!(matches!(
        InviteCode::from_cbor(&version_two.into_bytes()),
        Err(ProtoError::Version)
    ));
    let long = InviteCode {
        invite_id: InviteId::from_bytes([0; 16]),
        fp_owner: [0; 15],
        origin: "a".repeat(crate::MAX_TEXT + 1),
    };
    assert!(long.to_cbor().is_err());
}

#[test]
fn fingerprints_are_stable_distinct_and_formatted_in_groups_of_four() {
    let (p, q) = (Person::new(1), Person::new(2));
    let fp = fingerprint(&p.ik_pk, &p.kem_pk);
    assert_eq!(fp, fingerprint(&p.ik_pk, &p.kem_pk));
    assert_ne!(fp, fingerprint(&q.ik_pk, &p.kem_pk));
    assert_ne!(fp, fingerprint(&p.ik_pk, &q.kem_pk));
    let shown = format_fingerprint(&fp);
    assert_eq!(shown.len(), 24 + 5);
    assert_eq!(shown.split('-').count(), 6);
    assert!(shown.split('-').all(|group| group.len() == 4));
    assert_eq!(parse_fingerprint(&shown).unwrap(), fp);
    assert_eq!(
        parse_fingerprint(&shown.to_lowercase().replace('-', " ")).unwrap(),
        fp
    );
    assert!(parse_fingerprint(&drop_last(&shown)).is_err());
    assert!(parse_fingerprint("").is_err());
}

#[test]
fn head_codes_bind_every_input_and_use_the_xxxx_xxxx_form() {
    let vault = VaultId::from_bytes([1; 16]);
    let hash = Hash32::from_bytes([2; 32]);
    let code = |r, e, s, h: &Hash32, v: &VaultId| {
        head_code(
            v,
            Rver::new(r).unwrap(),
            Epoch::new(e).unwrap(),
            Seq::new(s).unwrap(),
            h,
        )
        .unwrap()
    };
    let base = code(1, 0, 3, &hash, &vault);
    assert_eq!(base.len(), 9);
    assert_eq!(base.as_bytes()[4], b'-');
    for other in [
        code(2, 0, 3, &hash, &vault),
        code(1, 1, 3, &hash, &vault),
        code(1, 0, 4, &hash, &vault),
        code(1, 0, 3, &Hash32::from_bytes([3; 32]), &vault),
        code(1, 0, 3, &hash, &VaultId::from_bytes([9; 16])),
    ] {
        assert_ne!(base, other);
    }
}
