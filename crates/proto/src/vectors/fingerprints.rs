use super::*;

#[test]
pub(super) fn fingerprint_vectors_are_current_and_replay() {
    let people: Vec<Value> = [1_u8, 2, 3]
        .iter()
        .map(|n| {
            let p = Person::new(*n);
            let fp = fingerprint(&p.ik_pk, &p.kem_pk);
            json!({ "n": n, "ik_pk": hex(p.ik_pk.as_bytes()), "kem_pk": hex(p.kem_pk.as_bytes()), "fp": hex(&fp), "display": format_fingerprint(&fp) })
        })
        .collect();
    let owner = Person::new(1);
    let code = invite_for(&owner, None);
    let text = code.to_text().unwrap();
    let heads: Vec<Value> = [(1_u64, 0_u64, 1_u64), (3, 2, 9), (1_000_000, 7, 123_456)]
        .iter()
        .map(|(rver, epoch, seq)| {
            let vault = VaultId::from_bytes([0xee; 16]);
            let hash = Hash32::from_bytes([0x5a; 32]);
            json!({
                "vault_id": hex(vault.as_bytes()),
                "rver": rver, "epoch": epoch, "seq": seq,
                "manifest_hash": hex(hash.as_bytes()),
                "code": head_code(&vault, Rver::new(*rver).unwrap(), Epoch::new(*epoch).unwrap(), Seq::new(*seq).unwrap(), &hash).unwrap(),
            })
        })
        .collect();
    let vectors = sync(
        "fingerprint.json",
        json!({
            "people": people,
            "head_codes": heads,
            "invite": { "text": text, "invite_id": hex(code.invite_id.as_bytes()), "fp_owner": hex(&code.fp_owner), "origin": code.origin },
            "invite_reject": [
                text.replacen("INV1-", "INV2-", 1),
                text.strip_prefix("INV1-").unwrap().to_owned(),
                format!("{text}A"),
                drop_last(&text),
                "INV1-U!".to_owned(),
            ],
        }),
    );
    for person in field(&vectors, "people").as_array().unwrap() {
        let ik = VerifyingKey::from_bytes(array32(person, "ik_pk")).unwrap();
        let kem = KemPublicKey::from_bytes(bytes_of(person, "kem_pk").try_into().unwrap()).unwrap();
        let fp = fingerprint(&ik, &kem);
        assert_eq!(hex(&fp), field(person, "fp").as_str().unwrap());
        assert_eq!(
            format_fingerprint(&fp),
            field(person, "display").as_str().unwrap()
        );
    }
    for case in field(&vectors, "head_codes").as_array().unwrap() {
        let code = head_code(
            &VaultId::from_bytes(array16(case, "vault_id")),
            Rver::new(field(case, "rver").as_u64().unwrap()).unwrap(),
            Epoch::new(field(case, "epoch").as_u64().unwrap()).unwrap(),
            Seq::new(field(case, "seq").as_u64().unwrap()).unwrap(),
            &Hash32::from_bytes(array32(case, "manifest_hash")),
        )
        .unwrap();
        assert_eq!(code, field(case, "code").as_str().unwrap());
    }
    let invite = field(&vectors, "invite");
    let parsed = InviteCode::parse(field(invite, "text").as_str().unwrap()).unwrap();
    assert_eq!(parsed.origin, field(invite, "origin").as_str().unwrap());
    assert_eq!(
        hex(&parsed.fp_owner),
        field(invite, "fp_owner").as_str().unwrap()
    );
    for bad in field(&vectors, "invite_reject").as_array().unwrap() {
        assert!(InviteCode::parse(bad.as_str().unwrap()).is_err());
    }
}
