use super::*;

#[expect(
    clippy::panic_in_result_fn,
    reason = "unknown type names are a vector bug"
)]
pub(super) fn decode_named(kind: &str, bytes: &[u8]) -> Result<Vec<u8>, ProtoError> {
    match kind {
        "Dissolve" => Dissolve::from_cbor(bytes)?.to_cbor(),
        "LeaveRequest" => LeaveRequest::from_cbor(bytes)?.to_cbor(),
        "Manifest" => Manifest::from_cbor(bytes)?.to_cbor(),
        "Roster" => Roster::from_cbor(bytes)?.to_cbor(),
        "ItemWire" => crate::ItemWire::from_cbor(bytes)?.to_cbor(),
        "Share" => Share::from_cbor(bytes)?.to_cbor(),
        "AccountRecord" => AccountRecord::from_cbor(bytes)?.to_cbor(),
        "RecoveryEnrolment" => RecoveryEnrolment::from_cbor(bytes)?.to_cbor(),
        "Leaf" => Leaf::from_cbor(bytes)?.to_cbor(),
        "InviteCode" => InviteCode::from_cbor(bytes)?.to_cbor(),
        "Keyset" => Keyset::from_cbor(bytes)?.to_cbor(),
        "Signed" => Signed::<Manifest>::from_cbor(bytes)?.to_cbor(),
        "Uint53" => Uint53::from_cbor(bytes)?.to_cbor(),
        other => panic!("unknown type {other}"),
    }
}

pub(super) fn error_of(kind: &str, bytes: &[u8]) -> &'static str {
    decode_named(kind, bytes).map_or_else(|e| e.name(), |_| "Ok")
}

fn uint_vectors() -> Vec<Value> {
    [
        0_u64,
        1,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        4_294_967_295,
        4_294_967_296,
        Uint53::MAX,
    ]
    .iter()
    .map(|v| {
        let mut w = Writer::new();
        w.uint(*v).unwrap();
        json!({ "value": v, "hex": hex(&w.into_bytes()) })
    })
    .collect()
}

const UINT_REJECTS: [(&str, &str); 18] = [
    ("non_shortest_one_byte", "1800"),
    ("non_shortest_two_byte", "190017"),
    ("non_shortest_four_byte", "1a0000ffff"),
    ("non_shortest_eight_byte", "1b00000000ffffffff"),
    ("above_2_pow_53_minus_1", "1b0020000000000000"),
    ("maximum_u64", "1bffffffffffffffff"),
    ("negative", "20"),
    ("float16", "f93c00"),
    ("float64", "fb3ff0000000000000"),
    ("tag", "c000"),
    ("self_describe_tag", "d9d9f700"),
    ("undefined", "f7"),
    ("simple_16", "f0"),
    ("indefinite_bytes", "5fff"),
    ("indefinite_array", "9fff"),
    ("indefinite_map", "bfff"),
    ("trailing_byte", "0000"),
    ("empty", ""),
];

fn dissolve_rejects(good: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let dissolve = |mutate: &dyn Fn(&mut Entries)| {
        let mut entries = dissolve_entries(1, 15);
        mutate(&mut entries);
        map_bytes(&entries)
    };
    let mut record_rejects = vec![
        ("unsorted_keys", dissolve(&|e| e.swap(2, 3))),
        ("duplicate_key", dissolve(&|e| e[3].0 = 2)),
        ("unknown_key", dissolve(&|e| e.push((7, Entry::Uint(0))))),
        (
            "missing_key",
            dissolve(&|e| {
                e.pop();
            }),
        ),
        ("key_out_of_range", dissolve(&|e| e[6].0 = 256)),
        ("null_for_integer", dissolve(&|e| e[3].1 = Entry::Null)),
        (
            "text_for_bytes",
            dissolve(&|e| e[2].1 = Entry::Text("0123456789abcdef")),
        ),
        (
            "short_id",
            dissolve(&|e| e[2].1 = Entry::Bytes(vec![1; 15])),
        ),
        (
            "integer_above_2_pow_53",
            dissolve(&|e| e[3].1 = Entry::Uint(1 << 53)),
        ),
        ("version_zero", map_bytes(&dissolve_entries(0, 15))),
        ("version_two", map_bytes(&dissolve_entries(2, 15))),
        ("wrong_rtype", map_bytes(&dissolve_entries(1, 16))),
    ];
    let mut indefinite = vec![0xbf];
    indefinite.extend_from_slice(&good[1..]);
    indefinite.push(0xff);
    record_rejects.push(("indefinite_map", indefinite));
    let mut long_key = good.to_vec();
    long_key.splice(1..2, [0x18, 0x00]);
    record_rejects.push(("non_shortest_key", long_key));
    let mut tagged = vec![0xd9, 0xd9, 0xf7];
    tagged.extend_from_slice(good);
    record_rejects.push(("tagged_map", tagged));
    let mut trailing = good.to_vec();
    trailing.push(0);
    record_rejects.push(("trailing_byte", trailing));
    record_rejects.push((
        "truncated",
        good.get(..good.len().saturating_sub(1)).unwrap().to_vec(),
    ));
    record_rejects
}

pub(super) fn cbor_vectors() -> Value {
    let good = map_bytes(&dissolve_entries(1, 15));
    let record_rejects = dissolve_rejects(&good);
    json!({
        "uint": uint_vectors(),
        "uint_reject": UINT_REJECTS.iter().map(|(n, h)| json!({ "name": n, "hex": h })).collect::<Vec<_>>(),
        "dissolve_ok": hex(&good),
        "dissolve_reject": record_rejects
            .iter()
            .map(|(name, bytes)| json!({ "name": name, "hex": hex(bytes), "error": error_of("Dissolve", bytes) }))
            .collect::<Vec<_>>(),
        "limits": { "nesting": crate::MAX_NESTING, "array": crate::MAX_ARRAY, "text": crate::MAX_TEXT, "record": crate::MAX_RECORD },
    })
}

#[test]
pub(super) fn cbor_vectors_are_current_and_replay() {
    let vectors = sync("cbor.json", cbor_vectors());
    for case in field(&vectors, "uint").as_array().unwrap() {
        let bytes = bytes_of(case, "hex");
        let value = Uint53::from_cbor(&bytes).unwrap();
        assert_eq!(value.get(), field(case, "value").as_u64().unwrap());
        assert_eq!(value.to_cbor().unwrap(), bytes);
    }
    for case in field(&vectors, "uint_reject").as_array().unwrap() {
        assert!(
            Uint53::from_cbor(&bytes_of(case, "hex")).is_err(),
            "{}",
            field(case, "name")
        );
    }
    assert!(Dissolve::from_cbor(&bytes_of(&vectors, "dissolve_ok")).is_ok());
    for case in field(&vectors, "dissolve_reject").as_array().unwrap() {
        let got = error_of("Dissolve", &bytes_of(case, "hex"));
        assert_eq!(
            got,
            field(case, "error").as_str().unwrap(),
            "{}",
            field(case, "name")
        );
        assert_ne!(got, "Ok");
    }
}
