use super::*;

struct AadIds {
    account: AccountId,
    vault: VaultId,
    item: ItemId,
    att: AttId,
    device: DeviceId,
}

impl AadIds {
    fn new() -> Self {
        Self {
            account: AccountId::from_bytes([0xa1; 16]),
            vault: VaultId::from_bytes([0xb2; 16]),
            item: ItemId::from_bytes([0xc3; 16]),
            att: AttId::from_bytes([0xd4; 16]),
            device: DeviceId::from_bytes([0xe5; 16]),
        }
    }
}

type AadCase = (&'static str, Value, Aad);

fn uint_of(value: u64) -> Uint53 {
    Uint53::new(value).unwrap()
}

pub(super) fn aad_cases() -> Vec<AadCase> {
    let ids = AadIds::new();
    let mut cases = record_aad_cases(&ids);
    cases.extend(local_aad_cases(&ids));
    cases
}

fn record_aad_cases(ids: &AadIds) -> Vec<AadCase> {
    let AadIds {
        account,
        vault,
        item,
        att,
        ..
    } = *ids;
    let kdf = KdfWire {
        m: 65_536,
        t: 3,
        p: 4,
    };
    let n = uint_of;
    let (ver, epoch) = (Version::new(3).unwrap(), Epoch::new(2).unwrap());
    let account_hex = hex(account.as_bytes());
    let vault_hex = hex(vault.as_bytes());
    let item_hex = hex(item.as_bytes());
    vec![
        (
            "ak_wrap",
            json!({"account": account_hex, "gen": 1, "m": 65_536, "t": 3, "p": 4}),
            Aad::ak_wrap(account, &kdf, n(1)),
        ),
        (
            "keyset_keys",
            json!({"account": account_hex, "gen": 1}),
            Aad::keyset_keys(account, n(1)),
        ),
        (
            "item_overview",
            json!({"vault": vault_hex, "item": item_hex, "ver": 3}),
            Aad::item_overview(vault, item, ver),
        ),
        (
            "item_details",
            json!({"vault": vault_hex, "item": item_hex, "ver": 3}),
            Aad::item_details(vault, item, ver),
        ),
        (
            "item_key_wrap",
            json!({"vault": vault_hex, "item": item_hex, "epoch": 2, "ver": 3}),
            Aad::item_key_wrap(vault, item, epoch, ver),
        ),
        (
            "attachment_chunk",
            json!({"vault": vault_hex, "item": item_hex, "att": hex(att.as_bytes()), "chunk_size": 1_048_576}),
            Aad::attachment_chunk(vault, item, att, n(1_048_576)),
        ),
        (
            "self_wrap",
            json!({"account": account_hex, "vault": vault_hex, "epoch": 2}),
            Aad::self_wrap(account, vault, epoch),
        ),
        (
            "recovery_wrap",
            json!({"account": account_hex, "rgen": 4}),
            Aad::recovery_wrap(account, n(4)),
        ),
    ]
}

fn local_aad_cases(ids: &AadIds) -> Vec<AadCase> {
    let AadIds {
        account,
        att,
        device,
        ..
    } = *ids;
    let n = uint_of;
    let account_hex = hex(account.as_bytes());
    vec![
        (
            "device_local_ak_bio",
            json!({"account": account_hex, "field": 1, "device": hex(device.as_bytes()), "local_gen": 5}),
            Aad::device_local(account, LocalField::AkBio, device, n(5)),
        ),
        (
            "device_local_ext_key",
            json!({"account": account_hex, "field": 8, "device": hex(device.as_bytes()), "local_gen": 5}),
            Aad::device_local(account, LocalField::ExtKey, device, n(5)),
        ),
        (
            "account_meta",
            json!({"account": account_hex, "device": hex(device.as_bytes())}),
            Aad::account_meta(account, device),
        ),
        (
            "enrolment",
            json!({"transcript": hex(&[0x77; 32])}),
            Aad::enrolment(Hash32::from_bytes([0x77; 32])),
        ),
        (
            "export_stream",
            json!({"header_hash": hex(&[0x88; 32]), "chunk_size": 1_048_576}),
            Aad::export_stream(Hash32::from_bytes([0x88; 32]), n(1_048_576)),
        ),
        (
            "custom_extra_list",
            json!({"rtype": 11, "extra": [{"uint": 1}, {"id": hex(att.as_bytes())}, {"hash": hex(&[1; 32])}]}),
            Aad::new(crate::Rtype::DeviceLocal).extra(Extra::List(vec![
                ExtraValue::Uint(n(1)),
                ExtraValue::Id(*att.as_bytes()),
                ExtraValue::Hash(Hash32::from_bytes([1; 32])),
            ])),
        ),
    ]
}

pub(super) fn aad_from(name: &str, args: &Value) -> Aad {
    let account_of = |key| AccountId::from_bytes(array16(args, key));
    let vault_of = |key| VaultId::from_bytes(array16(args, key));
    let item_of = |key| ItemId::from_bytes(array16(args, key));
    let device_of = |key| DeviceId::from_bytes(array16(args, key));
    let num = |key: &str| uint(args, key);
    let ver = |key: &str| Version::new(num(key).get()).unwrap();
    let epoch = |key: &str| Epoch::new(num(key).get()).unwrap();
    match name {
        "ak_wrap" => Aad::ak_wrap(
            account_of("account"),
            &KdfWire {
                m: u32::try_from(num("m").get()).unwrap(),
                t: u32::try_from(num("t").get()).unwrap(),
                p: u32::try_from(num("p").get()).unwrap(),
            },
            num("gen"),
        ),
        "keyset_keys" => Aad::keyset_keys(account_of("account"), num("gen")),
        "item_overview" => Aad::item_overview(vault_of("vault"), item_of("item"), ver("ver")),
        "item_details" => Aad::item_details(vault_of("vault"), item_of("item"), ver("ver")),
        "item_key_wrap" => Aad::item_key_wrap(
            vault_of("vault"),
            item_of("item"),
            epoch("epoch"),
            ver("ver"),
        ),
        "attachment_chunk" => Aad::attachment_chunk(
            vault_of("vault"),
            item_of("item"),
            AttId::from_bytes(array16(args, "att")),
            num("chunk_size"),
        ),
        "self_wrap" => Aad::self_wrap(account_of("account"), vault_of("vault"), epoch("epoch")),
        "recovery_wrap" => Aad::recovery_wrap(account_of("account"), num("rgen")),
        "device_local_ak_bio" => Aad::device_local(
            account_of("account"),
            LocalField::AkBio,
            device_of("device"),
            num("local_gen"),
        ),
        "device_local_ext_key" => Aad::device_local(
            account_of("account"),
            LocalField::ExtKey,
            device_of("device"),
            num("local_gen"),
        ),
        "account_meta" => Aad::account_meta(account_of("account"), device_of("device")),
        "enrolment" => Aad::enrolment(Hash32::from_bytes(array32(args, "transcript"))),
        "export_stream" => Aad::export_stream(
            Hash32::from_bytes(array32(args, "header_hash")),
            num("chunk_size"),
        ),
        "custom_extra_list" => Aad::new(crate::Rtype::DeviceLocal).extra(Extra::List(
            field(args, "extra")
                .as_array()
                .unwrap()
                .iter()
                .map(|e| {
                    if e.get("uint").is_some() {
                        ExtraValue::Uint(uint(e, "uint"))
                    } else if e.get("id").is_some() {
                        ExtraValue::Id(array16(e, "id"))
                    } else {
                        ExtraValue::Hash(Hash32::from_bytes(array32(e, "hash")))
                    }
                })
                .collect(),
        )),
        other => panic!("unknown aad constructor {other}"),
    }
}

#[test]
pub(super) fn aad_vectors_are_current_and_replay() {
    let cases: Vec<Value> = aad_cases()
        .into_iter()
        .map(|(name, args, aad)| json!({ "ctor": name, "args": args, "hex": hex(&aad.to_bytes().unwrap()) }))
        .collect();
    let vectors = sync("aad.json", json!({ "cases": cases }));
    for case in field(&vectors, "cases").as_array().unwrap() {
        let aad = aad_from(field(case, "ctor").as_str().unwrap(), field(case, "args"));
        assert_eq!(
            hex(&aad.to_bytes().unwrap()),
            field(case, "hex").as_str().unwrap()
        );
    }
}
