use super::*;

pub(super) fn account_json(
    name: &str,
    signed: &Signed<AccountRecord>,
    seen: Option<&AccountSeen>,
    pins: &[&Person],
    pin_override: Option<Value>,
) -> Value {
    let pins_value = pin_override.unwrap_or_else(|| pins_json(pins));
    let outcome = replay_account_inputs(signed, seen, &pins_value)
        .map(|r| json!({ "account_id": hex(r.account_id.as_bytes()), "seq": r.seq.get() }));
    json!({
        "kind": "account",
        "name": name,
        "record": hex(&signed.to_cbor().unwrap()),
        "seen": seen.map(|s| json!({ "seq": s.seq.get(), "hash": hex(s.hash.as_bytes()) })),
        "pins": pins_value,
        "expect": expected(outcome),
    })
}

pub(super) fn replay_account_inputs(
    signed: &Signed<AccountRecord>,
    seen: Option<&AccountSeen>,
    pins: &Value,
) -> Result<AccountRecord, ProtoError> {
    verify_account_record(signed, seen, &pins_from(pins))
}

pub(super) fn replay_account(case: &Value) {
    let signed = Signed::<AccountRecord>::from_cbor(&bytes_of(case, "record")).unwrap();
    let seen = field(case, "seen").as_object().map(|_| AccountSeen {
        seq: Seq::new(field(field(case, "seen"), "seq").as_u64().unwrap()).unwrap(),
        hash: Hash32::from_bytes(array32(field(case, "seen"), "hash")),
    });
    let result = replay_account_inputs(&signed, seen.as_ref(), field(case, "pins"));
    check_outcome(result, field(case, "expect"), |record, ok| {
        assert_eq!(
            hex(record.account_id.as_bytes()),
            field(ok, "account_id").as_str().unwrap()
        );
        assert_eq!(record.seq.get(), field(ok, "seq").as_u64().unwrap());
    });
}

pub(super) struct AccountWorld {
    p: Person,
    q: Person,
    floor: KdfWire,
    first: Signed<AccountRecord>,
    seen: AccountSeen,
}

impl AccountWorld {
    fn new() -> Self {
        let (p, q) = (Person::new(1), Person::new(2));
        let floor = KdfWire {
            m: 65_536,
            t: 3,
            p: 4,
        };
        let mut world = Self {
            first: Signed::sign(
                SigLabel::Account,
                &Self::record_of(&p, 1, None, floor),
                &p.signing,
            )
            .unwrap(),
            p,
            q,
            floor,
            seen: AccountSeen {
                seq: Seq::new(1).unwrap(),
                hash: Hash32::from_bytes([0; 32]),
            },
        };
        world.seen.hash = world.first.hash();
        world
    }

    pub(super) fn record_of(
        p: &Person,
        seq: u64,
        prev: Option<Hash32>,
        kdf: KdfWire,
    ) -> AccountRecord {
        AccountRecord {
            account_id: p.account,
            seq: Seq::new(seq).unwrap(),
            prev,
            ik_pk: p.ik_pk,
            kem_pk: p.kem_pk.clone(),
            kdf,
            status: AccountStatus::Active,
            rc_gen: Uint53::ZERO,
            min_v: Uint53::new(1).unwrap(),
            created: Uint53::new(1_700_000_000).unwrap(),
        }
    }

    fn record(&self, seq: u64, prev: Option<Hash32>, kdf: KdfWire) -> AccountRecord {
        Self::record_of(&self.p, seq, prev, kdf)
    }

    fn sign(record: &AccountRecord, who: &Person) -> Signed<AccountRecord> {
        Signed::sign(SigLabel::Account, record, &who.signing).unwrap()
    }

    fn by_owner(&self, record: &AccountRecord) -> Signed<AccountRecord> {
        Self::sign(record, &self.p)
    }
}

pub(super) fn account_cases() -> Vec<Value> {
    let world = AccountWorld::new();
    let mut cases = kdf_bound_cases(&world);
    cases.extend(account_chain_cases(&world));
    cases
}

fn kdf_bound_cases(world: &AccountWorld) -> Vec<Value> {
    let kdf_case = |name: &str, m: u32, t: u32, p: u32| {
        let kdf = KdfWire { m, t, p };
        let record = world.by_owner(&world.record(1, None, kdf));
        account_json(name, &record, None, &[], None)
    };
    vec![
        account_json("first_record", &world.first, None, &[], None),
        kdf_case("kdf_memory_below_floor", 8_192, 1, 4),
        kdf_case("kdf_iterations_above_ceiling", 65_536, 13, 4),
        kdf_case("kdf_parallelism_not_four", 65_536, 3, 1),
        kdf_case("kdf_ceiling_accepted", 524_288, 12, 4),
    ]
}

fn account_chain_cases(world: &AccountWorld) -> Vec<Value> {
    let AccountWorld {
        p,
        q,
        floor,
        first,
        seen,
    } = world;
    let signed = |seq: u64, prev: Option<Hash32>| world.by_owner(&world.record(seq, prev, *floor));
    let plain = |name: &str, record: &Signed<AccountRecord>, seen: Option<&AccountSeen>| {
        account_json(name, record, seen, &[], None)
    };
    let changed = json!([{
        "account_id": hex(p.account.as_bytes()),
        "ik_pk": hex(q.ik_pk.as_bytes()),
        "kem_pk": hex(q.kem_pk.as_bytes()),
    }]);
    let same_seq_other_hash = world.by_owner(&AccountRecord {
        rc_gen: Uint53::new(1).unwrap(),
        ..world.record(1, None, *floor)
    });
    vec![
        plain(
            "signed_by_another_key",
            &AccountWorld::sign(&world.record(1, None, *floor), q),
            None,
        ),
        plain(
            "seq_one_with_prev",
            &signed(1, Some(Hash32::from_bytes([1; 32]))),
            None,
        ),
        plain("seq_two_without_prev", &signed(2, None), None),
        plain(
            "next_record_extends_chain",
            &signed(2, Some(first.hash())),
            Some(seen),
        ),
        plain(
            "next_record_wrong_prev",
            &signed(2, Some(Hash32::from_bytes([3; 32]))),
            Some(seen),
        ),
        plain(
            "older_than_seen",
            first,
            Some(&AccountSeen {
                seq: Seq::new(2).unwrap(),
                hash: Hash32::from_bytes([4; 32]),
            }),
        ),
        plain("same_seq_other_hash", &same_seq_other_hash, Some(seen)),
        account_json("pin_matches", first, None, &[p], None),
        account_json("pin_key_changed", first, None, &[], Some(changed)),
    ]
}
