use super::*;
use crate::ItemWire;

pub(super) fn sealed_vectors() -> Vec<Value> {
    let key = SecretKey::from_bytes([0x33; 32]);
    let account = AccountId::from_bytes([0xa1; 16]);
    let mut entropy = SeededEntropy::new([0x55; 32]);
    let kdf = KdfWire {
        m: 65_536,
        t: 3,
        p: 4,
    };
    let ak_aad = Aad::ak_wrap(account, &kdf, Uint53::new(1).unwrap());
    let ak_wrap = SealedRaw::seal_with(&mut entropy, &key, &[0x99; 32], &ak_aad).unwrap();
    let keys_aad = Aad::keyset_keys(account, Uint53::new(1).unwrap());
    let keys = KeysetKeys {
        ik_seed: SecretKey::from_bytes([1; 32]),
        kem_seed: SecretKey::from_bytes([2; 32]),
        sk_ascii: SecretBytes::from_vec(b"ABCDEFGHJKLMNPQRSTVWXYZ234".to_vec()),
        retired: Vec::new(),
    };
    let sealed_keys = Sealed::seal_with(&mut entropy, &key, &keys, &keys_aad).unwrap();
    let padded = SealedPadded::seal_with(
        &mut entropy,
        &key,
        b"overview",
        &Aad::item_overview(
            VaultId::from_bytes([1; 16]),
            ItemId::from_bytes([2; 16]),
            Version::new(1).unwrap(),
        ),
    )
    .unwrap();
    vec![
        json!({ "type": "SealedRaw", "key": hex(key.expose()), "aad": hex(&ak_aad.to_bytes().unwrap()), "plaintext": hex(&[0x99; 32]), "hex": hex(&ak_wrap.to_cbor().unwrap()) }),
        json!({ "type": "SealedKeysetKeys", "key": hex(key.expose()), "aad": hex(&keys_aad.to_bytes().unwrap()), "plaintext": hex(&keys.to_cbor().unwrap()), "hex": hex(&sealed_keys.to_cbor().unwrap()) }),
        json!({ "type": "SealedPadded", "key": hex(key.expose()), "aad": hex(&Aad::item_overview(VaultId::from_bytes([1; 16]), ItemId::from_bytes([2; 16]), Version::new(1).unwrap()).to_bytes().unwrap()), "plaintext": hex(b"overview"), "hex": hex(&padded.to_cbor().unwrap()) }),
    ]
}

fn item_wires() -> (ItemWire, ItemWire, ItemWire) {
    let mut item_vault = Vault::new(VaultKind::Shared, 1);
    item_vault.genesis();
    let live = item_vault.put(1, 7, b"overview").ops[0].wire().clone();
    let mut entropy = SeededEntropy::new([0x66; 32]);
    let with_attachment = seal_item_with(
        &mut entropy,
        item_vault.vk(),
        &ItemParams {
            vault_id: item_vault.id,
            item_id: Vault::item_id(9),
            ver: Version::new(1).unwrap(),
            epoch: Epoch::new(0).unwrap(),
            overview: b"o",
            details: b"d",
            att_ids: vec![AttId::from_bytes([1; 16]), AttId::from_bytes([2; 16])],
            prev_h: None,
        },
    )
    .unwrap();
    let tomb = tombstone(
        item_vault.id,
        Vault::item_id(7),
        Version::new(2).unwrap(),
        Epoch::new(0).unwrap(),
        Some(Hash32::from_bytes([0x42; 32])),
    );
    (live, with_attachment, tomb)
}

fn keyset_fixture(owner: &Person) -> Keyset {
    let key = SecretKey::from_bytes([0x33; 32]);
    let mut entropy = SeededEntropy::new([0x77; 32]);
    let kdf = KdfWire {
        m: 65_536,
        t: 3,
        p: 4,
    };
    let keys = KeysetKeys {
        ik_seed: SecretKey::from_bytes([1; 32]),
        kem_seed: SecretKey::from_bytes([2; 32]),
        sk_ascii: SecretBytes::from_vec(b"ABCDEFGHJKLMNPQRSTVWXYZ234".to_vec()),
        retired: Vec::new(),
    };
    Keyset {
        account_id: owner.account,
        generation: Uint53::new(1).unwrap(),
        ak_wrap: SealedRaw::seal_with(
            &mut entropy,
            &key,
            &[7; 32],
            &Aad::ak_wrap(owner.account, &kdf, Uint53::new(1).unwrap()),
        )
        .unwrap(),
        keys: Sealed::seal_with(
            &mut entropy,
            &key,
            &keys,
            &Aad::keyset_keys(owner.account, Uint53::new(1).unwrap()),
        )
        .unwrap(),
    }
}

pub(super) fn record_vectors() -> Value {
    let (vault, commits) = share_fixture();
    let state = verify_prefix(&commits);
    let (owner, member) = (Person::new(1), Person::new(2));
    let manifest = commits[1].manifest.unverified().unwrap();
    let (live, with_attachment, tomb) = item_wires();
    let account = AccountWorld::record_of(
        &owner,
        1,
        None,
        KdfWire {
            m: 65_536,
            t: 3,
            p: 4,
        },
    );
    let keyset = keyset_fixture(&owner);
    let recovery = RecoveryEnrolment {
        account_id: owner.account,
        rgen: Uint53::new(1).unwrap(),
        h_wrap: Hash32::from_bytes([0x44; 32]),
    };
    let leaf = Leaf {
        item_id: Vault::item_id(7),
        ver: Version::new(1).unwrap(),
        epoch: Epoch::new(0).unwrap(),
        h_item: Hash32::from_bytes([0x11; 32]),
        flag: LeafFlag::Live,
    };
    let invite = invite_for(&owner, None);
    let share = commits[1].shares[0].unverified().unwrap();
    let plain = |kind: &str, bytes: Vec<u8>| json!({ "type": kind, "hex": hex(&bytes) });
    let signed = |label: SigLabel, kind: &str, record: &Signed<Manifest>, signer: &Person| json!({ "type": kind, "label": label.name(), "hex": hex(&record.to_cbor().unwrap()), "signer": hex(signer.ik_pk.as_bytes()) });
    let mut records = vec![
        plain(
            "Dissolve",
            Dissolve {
                vault_id: vault.id,
                rver: state.rver,
                epoch: state.epoch,
                seq: state.seq,
                head: state.hash,
            }
            .to_cbor()
            .unwrap(),
        ),
        plain(
            "LeaveRequest",
            LeaveRequest {
                vault_id: vault.id,
                account_id: member.account,
                rver: state.rver,
                epoch: state.epoch,
            }
            .to_cbor()
            .unwrap(),
        ),
        plain("Manifest", manifest.to_cbor().unwrap()),
        plain("Roster", state.roster.to_cbor().unwrap()),
        plain("ItemWire", live.to_cbor().unwrap()),
        plain("ItemWire", with_attachment.to_cbor().unwrap()),
        plain("ItemWire", tomb.to_cbor().unwrap()),
        plain("Share", share.to_cbor().unwrap()),
        plain("AccountRecord", account.to_cbor().unwrap()),
        plain("RecoveryEnrolment", recovery.to_cbor().unwrap()),
        plain("Leaf", leaf.to_cbor().unwrap()),
        plain("InviteCode", invite.to_cbor().unwrap()),
        plain("Keyset", keyset.to_cbor().unwrap()),
        signed(SigLabel::Manifest, "Signed", &commits[1].manifest, &owner),
    ];
    records.extend(sealed_vectors());
    json!({ "records": records })
}

#[test]
pub(super) fn record_vectors_are_current_and_replay() {
    let vectors = sync("records.json", record_vectors());
    for case in field(&vectors, "records").as_array().unwrap() {
        let kind = field(case, "type").as_str().unwrap();
        match kind {
            "SealedRaw" | "SealedKeysetKeys" | "SealedPadded" => {
                let key = SecretKey::from_bytes(array32(case, "key"));
                let aad_bytes = bytes_of(case, "aad");
                let wire = bytes_of(case, "hex");
                let plaintext = bytes_of(case, "plaintext");
                let (nonce, ct) = match kind {
                    "SealedRaw" => {
                        let s = SealedRaw::from_cbor(&wire).unwrap();
                        (*s.nonce(), s.ct().to_vec())
                    }
                    "SealedPadded" => {
                        let s = SealedPadded::from_cbor(&wire).unwrap();
                        (*s.nonce(), s.ct().to_vec())
                    }
                    _ => {
                        let s = Sealed::<KeysetKeys>::from_cbor(&wire).unwrap();
                        (*s.nonce(), s.ct().to_vec())
                    }
                };
                let opened = hasp_crypto::open(&key, &nonce, &ct, &aad_bytes).unwrap();
                let opened = if kind == "SealedRaw" {
                    opened
                } else {
                    unpad(opened).unwrap()
                };
                assert_eq!(opened.expose(), &plaintext[..]);
            }
            "Signed" => {
                let signed = Signed::<Manifest>::from_cbor(&bytes_of(case, "hex")).unwrap();
                let expected_key = VerifyingKey::from_bytes(array32(case, "signer")).unwrap();
                assert!(signed.verify(SigLabel::Manifest, &expected_key).is_ok());
                assert!(signed.verify(SigLabel::Roster, &expected_key).is_err());
            }
            _ => {
                let bytes = bytes_of(case, "hex");
                assert_eq!(decode_named(kind, &bytes).unwrap(), bytes);
            }
        }
    }
}
