use hasp_crypto::{
    Argon2idParams, HmacAlg, KemPublicKey, KemSecretKey, SecretBytes, SecretKey, Signature,
    SigningKey, VerifyingKey, argon2id, hkdf_expand, hkdf_extract, hpke_open, open,
    seal_with_nonce, verify_strict,
};
use serde_json::{Value, json};

use crate::Outcome;
use crate::ReplayError;
use crate::json::{Replay, bytes, field, fixed, hex, hex_items, list, named, num, outcome, text};

pub(crate) fn sha256_cases(value: &Value) -> Replay<Vec<Outcome>> {
    list(value, "cases")?
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let repeat = field(case, "repeat")?;
            let digest = if repeat.is_null() {
                let parts = hex_items(case, "parts")?;
                let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
                hasp_crypto::sha256(&refs)
            } else {
                let count = usize::try_from(num(repeat, "count")?)
                    .map_err(|_| ReplayError::Vector("count"))?;
                hasp_crypto::sha256(&[&bytes(repeat, "byte")?.repeat(count)])
            };
            Ok(outcome(
                named(case, "sha256", index),
                &json!({ "digest": text(case, "digest")? }),
                &json!({ "digest": hex(&digest) }),
            ))
        })
        .collect()
}

pub(crate) fn hkdf_cases(value: &Value) -> Replay<Vec<Outcome>> {
    list(value, "cases")?
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let prk = hkdf_extract(&bytes(case, "salt")?, &bytes(case, "ikm")?);
            let info = bytes(case, "info")?;
            let len = usize::try_from(num(case, "len")?).map_err(|_| ReplayError::Vector("len"))?;
            let okm = if info.is_empty() {
                None
            } else {
                Some(hex(hkdf_expand(&prk, &info, len)?.expose()))
            };
            let expected_okm = okm.as_ref().map(|_| text(case, "okm")).transpose()?;
            let expected = json!({ "prk": text(case, "prk")?, "okm": expected_okm });
            let actual = json!({ "prk": hex(prk.into_secret().expose()), "okm": okm });
            Ok(outcome(named(case, "hkdf", index), &expected, &actual))
        })
        .collect()
}

pub(crate) fn hmac_cases(value: &Value) -> Replay<Vec<Outcome>> {
    let mut outcomes = Vec::new();
    for group in ["rfc4231", "project"] {
        for (index, case) in list(value, group)?.iter().enumerate() {
            let mac: SecretBytes =
                hasp_crypto::hmac(HmacAlg::Sha256, &bytes(case, "key")?, &bytes(case, "data")?)?;
            outcomes.push(outcome(
                named(case, group, index),
                &json!({ "mac": text(case, "mac")? }),
                &json!({ "mac": hex(mac.expose()) }),
            ));
        }
    }
    Ok(outcomes)
}

pub(crate) fn ed25519_cases(value: &Value) -> Replay<Vec<Outcome>> {
    let mut outcomes = Vec::new();
    for (index, case) in list(value, "positive")?.iter().enumerate() {
        let signing = SigningKey::from_seed(&SecretKey::from_bytes(fixed(case, "seed")?));
        let message = bytes(case, "message")?;
        let signature = signing.sign(&message);
        let verifies = verify_strict(&signing.verifying_key(), &message, &signature).is_ok();
        let expected = json!({
            "public": text(case, "public")?,
            "signature": text(case, "signature")?,
            "verifies": true,
        });
        let actual = json!({
            "public": hex(signing.verifying_key().as_bytes()),
            "signature": hex(signature.as_bytes()),
            "verifies": verifies,
        });
        outcomes.push(outcome(named(case, "positive", index), &expected, &actual));
    }
    for (index, case) in list(value, "negative")?.iter().enumerate() {
        let signature = Signature::from_bytes(fixed(case, "signature")?);
        let message = bytes(case, "message")?;
        let accepted = VerifyingKey::from_bytes(fixed(case, "public")?)
            .and_then(|key| verify_strict(&key, &message, &signature))
            .is_ok();
        outcomes.push(outcome(
            named(case, "negative", index),
            &json!({ "accepted": false }),
            &json!({ "accepted": accepted }),
        ));
    }
    Ok(outcomes)
}

pub(crate) fn argon2id_cases(value: &Value) -> Replay<Vec<Outcome>> {
    list(value, "project")?
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let narrow =
                |key| u32::try_from(num(case, key)?).map_err(|_| ReplayError::Vector("kdf"));
            let params = Argon2idParams::local(narrow("m_kib")?, narrow("t")?, narrow("p")?)?;
            let tag = argon2id(&bytes(case, "password")?, &fixed(case, "salt")?, &params)?;
            Ok(outcome(
                named(case, "argon2id", index),
                &json!({ "tag": text(case, "tag")? }),
                &json!({ "tag": hex(tag.expose()) }),
            ))
        })
        .collect()
}

pub(crate) fn xchacha_cases(value: &Value) -> Replay<Vec<Outcome>> {
    list(value, "cases")?
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let key = SecretKey::from_bytes(fixed(case, "key")?);
            let (nonce, aad) = (fixed(case, "nonce")?, bytes(case, "aad")?);
            let plaintext = bytes(case, "plaintext")?;
            let sealed = seal_with_nonce(&key, &nonce, &plaintext, &aad)?;
            let opened = open(&key, &nonce, &sealed, &aad)?;
            let expected = json!({
                "ciphertext": text(case, "ciphertext")?,
                "plaintext": text(case, "plaintext")?,
            });
            let actual = json!({ "ciphertext": hex(&sealed), "plaintext": hex(opened.expose()) });
            Ok(outcome(named(case, "xchacha", index), &expected, &actual))
        })
        .collect()
}

pub(crate) fn xwing_cases(value: &Value) -> Replay<Vec<Outcome>> {
    list(value, "vectors")?
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let secret = KemSecretKey::from_seed(&SecretKey::from_bytes(fixed(case, "sk")?))?;
            Ok(outcome(
                named(case, "xwing", index),
                &json!({ "pk": text(case, "pk")? }),
                &json!({ "pk": hex(secret.public_key().as_bytes()) }),
            ))
        })
        .collect()
}

pub(crate) fn xwing_invalid_cases(value: &Value) -> Replay<Vec<Outcome>> {
    list(value, "cases")?
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let accepted = KemPublicKey::from_bytes(fixed(case, "public_key")?).is_ok();
            Ok(outcome(
                named(case, "xwing-invalid-ek", index),
                &json!({ "accepted": false }),
                &json!({ "accepted": accepted }),
            ))
        })
        .collect()
}

pub(crate) fn hpke_cases(value: &Value) -> Replay<Vec<Outcome>> {
    list(value, "cases")?
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let secret = KemSecretKey::from_seed(&SecretKey::from_bytes(fixed(case, "seed")?))?;
            let opened = hpke_open(
                &secret,
                &fixed(case, "enc")?,
                &bytes(case, "info")?,
                &bytes(case, "aad")?,
                &bytes(case, "ciphertext")?,
            )?;
            let expected = json!({
                "public_key": text(case, "public_key")?,
                "plaintext": text(case, "plaintext")?,
            });
            let actual = json!({
                "public_key": hex(secret.public_key().as_bytes()),
                "plaintext": hex(opened.expose()),
            });
            Ok(outcome(named(case, "hpke", index), &expected, &actual))
        })
        .collect()
}
