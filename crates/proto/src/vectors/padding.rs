use super::*;

#[test]
pub(super) fn padding_vectors_are_current_and_replay() {
    let lengths = [
        0_usize, 1, 254, 255, 256, 511, 512, 1023, 1024, 65_535, 65_536, 131_071, 131_072,
    ];
    let lengths_json: Vec<Value> = lengths
        .iter()
        .map(|len| json!({ "len": len, "padded_len": pad(&vec![1; *len]).unwrap().len() }))
        .collect();
    let samples: Vec<Value> = [&b""[..], b"a", b"overview"]
        .iter()
        .map(|p| json!({ "plaintext": hex(p), "padded": hex(pad(p).unwrap().expose()) }))
        .collect();
    let mut short = vec![0_u8; 256];
    short[0] = 1;
    short[1] = 0x80;
    let mut short_wrong = short.clone();
    short_wrong.pop();
    let mut oversize = vec![0_u8; 512];
    oversize[1] = 0x80;
    let rejects = [
        vec![0; 256],
        vec![1; 256],
        short_wrong,
        oversize,
        Vec::new(),
    ];
    let vectors = sync(
        "padding.json",
        json!({
            "lengths": lengths_json,
            "samples": samples,
            "unpad_ok": [hex(&short)],
            "unpad_reject": rejects.iter().map(|r| hex(r)).collect::<Vec<_>>(),
        }),
    );
    for case in field(&vectors, "lengths").as_array().unwrap() {
        let len = usize::try_from(field(case, "len").as_u64().unwrap()).unwrap();
        assert_eq!(
            u64::try_from(pad(&vec![1; len]).unwrap().len()).unwrap(),
            field(case, "padded_len").as_u64().unwrap()
        );
    }
    for case in field(&vectors, "samples").as_array().unwrap() {
        let plaintext = bytes_of(case, "plaintext");
        let padded = pad(&plaintext).unwrap();
        assert_eq!(
            hex(padded.expose()),
            field(case, "padded").as_str().unwrap()
        );
        assert_eq!(unpad(padded).unwrap().expose(), &plaintext[..]);
    }
    for ok in field(&vectors, "unpad_ok").as_array().unwrap() {
        assert!(unpad(SecretBytes::from_vec(unhex(ok.as_str().unwrap()))).is_ok());
    }
    for bad in field(&vectors, "unpad_reject").as_array().unwrap() {
        assert!(unpad(SecretBytes::from_vec(unhex(bad.as_str().unwrap()))).is_err());
    }
}
