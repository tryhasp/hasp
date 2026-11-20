use super::*;

pub(super) fn ctx_json(ctx: &[CtxValue]) -> Value {
    Value::Array(
        ctx.iter()
            .map(|value| match value {
                CtxValue::Uint(v) => json!({ "uint": v.get() }),
                CtxValue::Bytes(b) => json!({ "bytes": hex(b) }),
                CtxValue::Id16(id) => json!({ "id": hex(id) }),
            })
            .collect(),
    )
}

pub(super) fn ctx_from(value: &Value) -> Vec<CtxValue> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            if let Some(v) = item.get("uint") {
                CtxValue::Uint(Uint53::new(v.as_u64().unwrap()).unwrap())
            } else if let Some(v) = item.get("bytes") {
                CtxValue::Bytes(unhex(v.as_str().unwrap()))
            } else {
                CtxValue::Id16(array16(item, "id"))
            }
        })
        .collect()
}

pub(super) fn label_vectors() -> Value {
    let key = SecretKey::from_bytes([0x42; 32]);
    let contexts: [Vec<CtxValue>; 4] = [
        Vec::new(),
        vec![CtxValue::Id16([1; 16])],
        vec![
            CtxValue::Id16([2; 16]),
            CtxValue::Uint(Uint53::new(7).unwrap()),
        ],
        vec![
            CtxValue::Id16([3; 16]),
            CtxValue::Id16([4; 16]),
            CtxValue::Uint(Uint53::new(2).unwrap()),
            CtxValue::Bytes(vec![9; 5]),
        ],
    ];
    let mut derived = Vec::new();
    for kdf in Kdf::ALL {
        for ctx in &contexts {
            let out = crate::derive(&key, kdf, ctx).unwrap();
            derived.push(json!({
                "label": kdf.name(),
                "ctx": ctx_json(ctx),
                "info": hex(&crate::label::info(kdf.name(), ctx).unwrap()),
                "out": hex(out.expose()),
            }));
        }
    }
    json!({
        "kdf": Kdf::ALL.iter().map(|k| k.name()).collect::<Vec<_>>(),
        "sig": SigLabel::ALL.iter().map(|l| l.name()).collect::<Vec<_>>(),
        "hpke": { "info": HPKE_SHARE_INFO, "aad": HPKE_SHARE_AAD },
        "key": hex(key.expose()),
        "derive": derived,
    })
}

#[test]
pub(super) fn label_vectors_are_current_and_replay() {
    let vectors = sync("labels.json", label_vectors());
    let kdf: Vec<_> = field(&vectors, "kdf")
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(kdf, Kdf::ALL.iter().map(|k| k.name()).collect::<Vec<_>>());
    let key = SecretKey::from_bytes(array32(&vectors, "key"));
    for case in field(&vectors, "derive").as_array().unwrap() {
        let label = Kdf::ALL
            .iter()
            .find(|k| k.name() == field(case, "label").as_str().unwrap())
            .unwrap();
        let ctx = ctx_from(field(case, "ctx"));
        assert_eq!(
            hex(&crate::label::info(label.name(), &ctx).unwrap()),
            field(case, "info").as_str().unwrap()
        );
        assert_eq!(
            hex(crate::derive(&key, *label, &ctx).unwrap().expose()),
            field(case, "out").as_str().unwrap()
        );
    }
}
