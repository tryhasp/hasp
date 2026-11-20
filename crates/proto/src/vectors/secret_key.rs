use super::*;

#[test]
pub(super) fn secret_key_vectors_are_current_and_replay() {
    let samples: [&[u8; 26]; 3] = [
        b"ABCDEFGHJKLMNPQRSTVWXYZ234",
        b"22222222222222222222222222",
        b"ZZZZZZZZZZZZZZZZZZZZZZZZZZ",
    ];
    let mut encode = Vec::new();
    for ascii in samples {
        for kind in [SecretKind::SecretKey, SecretKind::RecoveryCode] {
            let secret = SecretAscii::from_ascii(ascii).unwrap();
            let text = encode_secret_key(kind, &secret).unwrap();
            encode.push(json!({
                "kind": if kind == SecretKind::SecretKey { "V1" } else { "R1" },
                "ascii": String::from_utf8(ascii.to_vec()).unwrap(),
                "text": text.expose(),
            }));
        }
    }
    let good = encode_secret_key(
        SecretKind::SecretKey,
        &SecretAscii::from_ascii(samples[0]).unwrap(),
    )
    .unwrap();
    let good = good.expose().to_owned();
    let last = good.chars().last().unwrap();
    let flipped_last = if last == '2' { '3' } else { '2' };
    let rejects = [
        good.replacen("V1", "V2", 1),
        drop_last(&good),
        format!("{good}2"),
        good.replacen('A', "0", 1),
        format!("{}{flipped_last}", drop_last(&good)),
        String::new(),
        "V1".to_owned(),
    ];
    let vectors = sync(
        "secret-key.json",
        json!({ "encode": encode, "reject": rejects }),
    );
    for case in field(&vectors, "encode").as_array().unwrap() {
        let kind = if field(case, "kind").as_str().unwrap() == "V1" {
            SecretKind::SecretKey
        } else {
            SecretKind::RecoveryCode
        };
        let secret =
            SecretAscii::from_ascii(field(case, "ascii").as_str().unwrap().as_bytes()).unwrap();
        let text = encode_secret_key(kind, &secret).unwrap();
        assert_eq!(text.expose(), field(case, "text").as_str().unwrap());
        let (parsed_kind, parsed) =
            parse_secret_key(field(case, "text").as_str().unwrap()).unwrap();
        assert_eq!(parsed_kind, kind);
        assert_eq!(parsed.expose(), secret.expose());
    }
    for bad in field(&vectors, "reject").as_array().unwrap() {
        assert!(parse_secret_key(bad.as_str().unwrap()).is_err());
    }
}
