use hasp_crypto::{KemPublicKey, SecretBytes, SecretKey, VerifyingKey};
use hasp_proto::{
    Aad, AccountId, AccountRecord, AttId, CtxValue, DeviceId, Dissolve, Epoch, Extra, ExtraValue,
    HPKE_SHARE_AAD, HPKE_SHARE_INFO, Hash32, InviteCode, ItemId, ItemWire, Kdf, KdfWire, Keyset,
    KeysetKeys, Leaf, LeaveRequest, LocalField, Manifest, RecoveryEnrolment, Roster, Rtype, Rver,
    Sealed, SealedPadded, SealedRaw, SecretAscii, SecretKind, Seq, Share, SigLabel, Signed, Uint53,
    VaultId, Version, Wire, derive, encode_secret_key, fingerprint, format_fingerprint, head_code,
    pad, parse_secret_key, unpad,
};
use serde_json::{Value, json};

use crate::Outcome;
use crate::ReplayError;
use crate::json::{Replay, bytes, field, fixed, hex, list, named, num, outcome, text, unhex};

fn uint(value: &Value, key: &str) -> Replay<Uint53> {
    Ok(Uint53::new(num(value, key)?)?)
}

fn narrow(value: &Value, key: &str) -> Replay<u32> {
    u32::try_from(num(value, key)?).map_err(|_| ReplayError::Vector("number"))
}

fn accepted(accepted: bool) -> Value {
    json!({ "accepted": accepted })
}

fn strings<'a>(value: &'a Value, key: &str) -> Replay<Vec<&'a str>> {
    list(value, key)?
        .iter()
        .map(|item| item.as_str().ok_or(ReplayError::Vector("not text")))
        .collect()
}

fn decode_named(kind: &str, input: &[u8]) -> Result<Vec<u8>, ReplayError> {
    Ok(match kind {
        "Dissolve" => Dissolve::from_cbor(input)?.to_cbor()?,
        "LeaveRequest" => LeaveRequest::from_cbor(input)?.to_cbor()?,
        "Manifest" => Manifest::from_cbor(input)?.to_cbor()?,
        "Roster" => Roster::from_cbor(input)?.to_cbor()?,
        "ItemWire" => ItemWire::from_cbor(input)?.to_cbor()?,
        "Share" => Share::from_cbor(input)?.to_cbor()?,
        "AccountRecord" => AccountRecord::from_cbor(input)?.to_cbor()?,
        "RecoveryEnrolment" => RecoveryEnrolment::from_cbor(input)?.to_cbor()?,
        "Leaf" => Leaf::from_cbor(input)?.to_cbor()?,
        "InviteCode" => InviteCode::from_cbor(input)?.to_cbor()?,
        "Keyset" => Keyset::from_cbor(input)?.to_cbor()?,
        "Signed" => Signed::<Manifest>::from_cbor(input)?.to_cbor()?,
        "Uint53" => Uint53::from_cbor(input)?.to_cbor()?,
        _ => return Err(ReplayError::Vector("unknown type")),
    })
}

fn error_name(kind: &str, input: &[u8]) -> Replay<String> {
    match decode_named(kind, input) {
        Ok(_) => Ok("Ok".to_owned()),
        Err(ReplayError::Proto(error)) => Ok(error.name().to_owned()),
        Err(other) => Err(other),
    }
}

pub(crate) fn cbor(value: &Value) -> Replay<Vec<Outcome>> {
    let mut outcomes = Vec::new();
    for (index, case) in list(value, "uint")?.iter().enumerate() {
        let parsed = Uint53::from_cbor(&bytes(case, "hex")?)?;
        outcomes.push(outcome(
            named(case, "uint", index),
            &json!({ "value": num(case, "value")?, "hex": text(case, "hex")? }),
            &json!({ "value": parsed.get(), "hex": hex(&parsed.to_cbor()?) }),
        ));
    }
    for (index, case) in list(value, "uint_reject")?.iter().enumerate() {
        outcomes.push(outcome(
            named(case, "uint_reject", index),
            &accepted(false),
            &accepted(Uint53::from_cbor(&bytes(case, "hex")?).is_ok()),
        ));
    }
    outcomes.push(outcome(
        "dissolve_ok".to_owned(),
        &json!({ "error": "Ok" }),
        &json!({ "error": error_name("Dissolve", &bytes(value, "dissolve_ok")?)? }),
    ));
    for (index, case) in list(value, "dissolve_reject")?.iter().enumerate() {
        outcomes.push(outcome(
            named(case, "dissolve_reject", index),
            &json!({ "error": text(case, "error")? }),
            &json!({ "error": error_name("Dissolve", &bytes(case, "hex")?)? }),
        ));
    }
    Ok(outcomes)
}

fn ctx_from(value: &Value) -> Replay<Vec<CtxValue>> {
    value
        .as_array()
        .ok_or(ReplayError::Vector("ctx"))?
        .iter()
        .map(|item| {
            if item.get("uint").is_some() {
                Ok(CtxValue::Uint(uint(item, "uint")?))
            } else if item.get("bytes").is_some() {
                Ok(CtxValue::Bytes(bytes(item, "bytes")?))
            } else {
                Ok(CtxValue::Id16(fixed(item, "id")?))
            }
        })
        .collect()
}

pub(crate) fn labels(value: &Value) -> Replay<Vec<Outcome>> {
    let hpke = field(value, "hpke")?;
    let mut outcomes = vec![
        outcome(
            "kdf-names".to_owned(),
            &json!(strings(value, "kdf")?),
            &json!(Kdf::ALL.iter().map(|kdf| kdf.name()).collect::<Vec<_>>()),
        ),
        outcome(
            "sig-names".to_owned(),
            &json!(strings(value, "sig")?),
            &json!(
                SigLabel::ALL
                    .iter()
                    .map(|label| label.name())
                    .collect::<Vec<_>>()
            ),
        ),
        outcome(
            "hpke".to_owned(),
            &json!({ "aad": text(hpke, "aad")?, "info": text(hpke, "info")? }),
            &json!({ "aad": HPKE_SHARE_AAD, "info": HPKE_SHARE_INFO }),
        ),
    ];
    let key = SecretKey::from_bytes(fixed(value, "key")?);
    for (index, case) in list(value, "derive")?.iter().enumerate() {
        let name = text(case, "label")?;
        let label = Kdf::ALL
            .iter()
            .find(|kdf| kdf.name() == name)
            .ok_or(ReplayError::Vector("unknown label"))?;
        let derived = derive(&key, *label, &ctx_from(field(case, "ctx")?)?)?;
        outcomes.push(outcome(
            named(case, "derive", index),
            &json!({ "out": text(case, "out")? }),
            &json!({ "out": hex(derived.expose()) }),
        ));
    }
    Ok(outcomes)
}

fn aad_for(name: &str, args: &Value) -> Replay<Aad> {
    let account = |key| Ok::<_, ReplayError>(AccountId::from_bytes(fixed(args, key)?));
    let vault = |key| Ok::<_, ReplayError>(VaultId::from_bytes(fixed(args, key)?));
    let item = |key| Ok::<_, ReplayError>(ItemId::from_bytes(fixed(args, key)?));
    let device = |key| Ok::<_, ReplayError>(DeviceId::from_bytes(fixed(args, key)?));
    let ver = |key| Ok::<_, ReplayError>(Version::new(num(args, key)?)?);
    let epoch = |key| Ok::<_, ReplayError>(Epoch::new(num(args, key)?)?);
    Ok(match name {
        "ak_wrap" => Aad::ak_wrap(
            account("account")?,
            &KdfWire {
                m: narrow(args, "m")?,
                t: narrow(args, "t")?,
                p: narrow(args, "p")?,
            },
            uint(args, "gen")?,
        ),
        "keyset_keys" => Aad::keyset_keys(account("account")?, uint(args, "gen")?),
        "item_overview" => Aad::item_overview(vault("vault")?, item("item")?, ver("ver")?),
        "item_details" => Aad::item_details(vault("vault")?, item("item")?, ver("ver")?),
        "item_key_wrap" => {
            Aad::item_key_wrap(vault("vault")?, item("item")?, epoch("epoch")?, ver("ver")?)
        }
        "attachment_chunk" => Aad::attachment_chunk(
            vault("vault")?,
            item("item")?,
            AttId::from_bytes(fixed(args, "att")?),
            uint(args, "chunk_size")?,
        ),
        "self_wrap" => Aad::self_wrap(account("account")?, vault("vault")?, epoch("epoch")?),
        "recovery_wrap" => Aad::recovery_wrap(account("account")?, uint(args, "rgen")?),
        "device_local_ak_bio" => Aad::device_local(
            account("account")?,
            LocalField::AkBio,
            device("device")?,
            uint(args, "local_gen")?,
        ),
        "device_local_ext_key" => Aad::device_local(
            account("account")?,
            LocalField::ExtKey,
            device("device")?,
            uint(args, "local_gen")?,
        ),
        "account_meta" => Aad::account_meta(account("account")?, device("device")?),
        "enrolment" => Aad::enrolment(Hash32::from_bytes(fixed(args, "transcript")?)),
        "export_stream" => Aad::export_stream(
            Hash32::from_bytes(fixed(args, "header_hash")?),
            uint(args, "chunk_size")?,
        ),
        "custom_extra_list" => {
            let extras = list(args, "extra")?
                .iter()
                .map(|extra| {
                    if extra.get("uint").is_some() {
                        Ok(ExtraValue::Uint(uint(extra, "uint")?))
                    } else if extra.get("id").is_some() {
                        Ok(ExtraValue::Id(fixed(extra, "id")?))
                    } else {
                        Ok(ExtraValue::Hash(Hash32::from_bytes(fixed(extra, "hash")?)))
                    }
                })
                .collect::<Replay<Vec<_>>>()?;
            Aad::new(Rtype::DeviceLocal).extra(Extra::List(extras))
        }
        _ => return Err(ReplayError::Vector("unknown aad constructor")),
    })
}

pub(crate) fn aad(value: &Value) -> Replay<Vec<Outcome>> {
    list(value, "cases")?
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let name = text(case, "ctor")?;
            let built = aad_for(name, field(case, "args")?)?;
            Ok(outcome(
                format!("aad:{name}[{index}]"),
                &json!({ "hex": text(case, "hex")? }),
                &json!({ "hex": hex(&built.to_bytes()?) }),
            ))
        })
        .collect()
}

pub(crate) fn padding(value: &Value) -> Replay<Vec<Outcome>> {
    let mut outcomes = Vec::new();
    for (index, case) in list(value, "lengths")?.iter().enumerate() {
        let len = usize::try_from(num(case, "len")?).map_err(|_| ReplayError::Vector("len"))?;
        outcomes.push(outcome(
            named(case, "length", index),
            &json!({ "padded_len": num(case, "padded_len")? }),
            &json!({ "padded_len": pad(&vec![1; len])?.len() }),
        ));
    }
    for (index, case) in list(value, "samples")?.iter().enumerate() {
        let padded = pad(&bytes(case, "plaintext")?)?;
        let padded_hex = hex(padded.expose());
        let opened = unpad(padded)?;
        outcomes.push(outcome(
            named(case, "sample", index),
            &json!({ "padded": text(case, "padded")?, "plaintext": text(case, "plaintext")? }),
            &json!({ "padded": padded_hex, "plaintext": hex(opened.expose()) }),
        ));
    }
    for (group, expected) in [("unpad_ok", true), ("unpad_reject", false)] {
        for (index, item) in strings(value, group)?.into_iter().enumerate() {
            let opened = unpad(SecretBytes::from_vec(unhex(item)?)).is_ok();
            outcomes.push(outcome(
                format!("{group}[{index}]"),
                &accepted(expected),
                &accepted(opened),
            ));
        }
    }
    Ok(outcomes)
}

fn secret_kind(tag: &str) -> Replay<SecretKind> {
    match tag {
        "V1" => Ok(SecretKind::SecretKey),
        "R1" => Ok(SecretKind::RecoveryCode),
        _ => Err(ReplayError::Vector("secret kind")),
    }
}

pub(crate) fn secret_key(value: &Value) -> Replay<Vec<Outcome>> {
    let mut outcomes = Vec::new();
    for (index, case) in list(value, "encode")?.iter().enumerate() {
        let kind = secret_kind(text(case, "kind")?)?;
        let secret = SecretAscii::from_ascii(text(case, "ascii")?.as_bytes())?;
        let encoded = encode_secret_key(kind, &secret)?;
        let (parsed_kind, parsed) = parse_secret_key(text(case, "text")?)?;
        let expected = json!({
            "text": text(case, "text")?,
            "ascii": text(case, "ascii")?,
            "kind": text(case, "kind")?,
        });
        let actual = json!({
            "text": encoded.expose(),
            "ascii": String::from_utf8_lossy(parsed.expose()),
            "kind": if parsed_kind == SecretKind::SecretKey { "V1" } else { "R1" },
        });
        outcomes.push(outcome(named(case, "encode", index), &expected, &actual));
    }
    for (index, item) in strings(value, "reject")?.into_iter().enumerate() {
        outcomes.push(outcome(
            format!("reject[{index}]"),
            &accepted(false),
            &accepted(parse_secret_key(item).is_ok()),
        ));
    }
    Ok(outcomes)
}

pub(crate) fn fingerprints(value: &Value) -> Replay<Vec<Outcome>> {
    let mut outcomes = Vec::new();
    for (index, person) in list(value, "people")?.iter().enumerate() {
        let ik = VerifyingKey::from_bytes(fixed(person, "ik_pk")?)?;
        let kem = KemPublicKey::from_bytes(fixed(person, "kem_pk")?)?;
        let fp = fingerprint(&ik, &kem);
        outcomes.push(outcome(
            named(person, "person", index),
            &json!({ "fp": text(person, "fp")?, "display": text(person, "display")? }),
            &json!({ "fp": hex(&fp), "display": format_fingerprint(&fp) }),
        ));
    }
    for (index, case) in list(value, "head_codes")?.iter().enumerate() {
        let code = head_code(
            &VaultId::from_bytes(fixed(case, "vault_id")?),
            Rver::new(num(case, "rver")?)?,
            Epoch::new(num(case, "epoch")?)?,
            Seq::new(num(case, "seq")?)?,
            &Hash32::from_bytes(fixed(case, "manifest_hash")?),
        )?;
        outcomes.push(outcome(
            named(case, "head_code", index),
            &json!({ "code": text(case, "code")? }),
            &json!({ "code": code }),
        ));
    }
    let invite = field(value, "invite")?;
    let parsed = InviteCode::parse(text(invite, "text")?)?;
    outcomes.push(outcome(
        "invite".to_owned(),
        &json!({ "fp_owner": text(invite, "fp_owner")?, "origin": text(invite, "origin")? }),
        &json!({ "fp_owner": hex(&parsed.fp_owner), "origin": parsed.origin }),
    ));
    for (index, item) in strings(value, "invite_reject")?.into_iter().enumerate() {
        outcomes.push(outcome(
            format!("invite_reject[{index}]"),
            &accepted(false),
            &accepted(InviteCode::parse(item).is_ok()),
        ));
    }
    Ok(outcomes)
}

pub(crate) fn records(value: &Value) -> Replay<Vec<Outcome>> {
    list(value, "records")?
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let kind = text(case, "type")?;
            let wire = bytes(case, "hex")?;
            let name = format!("record:{kind}[{index}]");
            match kind {
                "SealedRaw" | "SealedKeysetKeys" | "SealedPadded" => {
                    let key = SecretKey::from_bytes(fixed(case, "key")?);
                    let (nonce, ct) = match kind {
                        "SealedRaw" => {
                            let sealed = SealedRaw::from_cbor(&wire)?;
                            (*sealed.nonce(), sealed.ct().to_vec())
                        }
                        "SealedPadded" => {
                            let sealed = SealedPadded::from_cbor(&wire)?;
                            (*sealed.nonce(), sealed.ct().to_vec())
                        }
                        _ => {
                            let sealed = Sealed::<KeysetKeys>::from_cbor(&wire)?;
                            (*sealed.nonce(), sealed.ct().to_vec())
                        }
                    };
                    let opened = hasp_crypto::open(&key, &nonce, &ct, &bytes(case, "aad")?)?;
                    let plain = if kind == "SealedRaw" {
                        opened
                    } else {
                        unpad(opened)?
                    };
                    Ok(outcome(
                        name,
                        &json!({ "plaintext": text(case, "plaintext")? }),
                        &json!({ "plaintext": hex(plain.expose()) }),
                    ))
                }
                "Signed" => {
                    let record = Signed::<Manifest>::from_cbor(&wire)?;
                    let author = VerifyingKey::from_bytes(fixed(case, "signer")?)?;
                    let actual = json!({
                        "manifest": record.verify(SigLabel::Manifest, &author).is_ok(),
                        "roster": record.verify(SigLabel::Roster, &author).is_ok(),
                    });
                    Ok(outcome(
                        name,
                        &json!({ "manifest": true, "roster": false }),
                        &actual,
                    ))
                }
                _ => Ok(outcome(
                    name,
                    &json!({ "hex": text(case, "hex")? }),
                    &json!({ "hex": hex(&decode_named(kind, &wire)?) }),
                )),
            }
        })
        .collect()
}
