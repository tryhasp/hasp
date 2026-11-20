use hasp_proto::SecretAscii;

use super::*;

fn kit(login: &str) -> EmergencyKit {
    let sk = SecretAscii::generate().unwrap();
    EmergencyKit::new("https://hasp.example.com", login, &sk, [7; 15]).unwrap()
}

#[test]
fn the_date_is_civil_utc() {
    assert_eq!(date(0), "1970-01-01");
    assert_eq!(date(1_763_424_000), "2025-11-18");
    assert_eq!(date(951_782_400), "2000-02-29");
}

#[test]
fn the_text_lists_every_field_of_protocol_4_4() {
    let kit = kit("alice@example.com");
    let text = kit.text(1_763_424_000);
    for needle in [
        "Hasp Emergency Kit",
        "Created 2025-11-18, kit version 1",
        "Server: https://hasp.example.com",
        "Login id: alice@example.com",
        &format!("Secret Key: {}", kit.secret_key()),
        &format!("Server key fingerprint: {}", kit.server_fingerprint),
        "Account password: \n",
    ] {
        assert!(text.contains(needle), "missing {needle}");
    }
}

#[test]
fn the_pdf_is_a_well_formed_one_page_file_with_the_kit_text() {
    let kit = kit("alice@example.com");
    let doc = kit.document(1_763_424_000).unwrap();
    let pdf: &[u8] = &doc.pdf;
    assert!(pdf.starts_with(b"%PDF-1.4\n"));
    assert!(pdf.ends_with(b"%%EOF\n"));
    let find = |needle: &[u8]| pdf.windows(needle.len()).position(|w| w == needle);
    assert!(find(kit.secret_key().as_bytes()).is_some());
    assert!(find(b"/Count 1").is_some());
    let xref = find(b"xref\n").unwrap();
    let table = std::str::from_utf8(&pdf[xref..]).unwrap();
    let mut lines = table.lines().skip(2);
    assert!(lines.next().unwrap().ends_with(" f "));
    let mut seen = 0;
    for line in lines.take_while(|line| line.ends_with(" n ")) {
        seen += 1;
        let offset: usize = line[..10].parse().unwrap();
        assert!(pdf[offset..].starts_with(format!("{seen} 0 obj\n").as_bytes()));
    }
    assert_eq!(seen, 7);
    let start = table.split("startxref\n").nth(1).unwrap();
    assert_eq!(
        start.lines().next().unwrap().parse::<usize>().unwrap(),
        xref
    );
}

#[test]
fn awkward_characters_are_escaped_or_replaced_in_the_pdf() {
    let kit = kit("a(b)c\\d\u{d55c}@example.com");
    let doc = kit.document(0).unwrap();
    let pdf: &[u8] = &doc.pdf;
    let expected = b"a\\(b\\)c\\\\d?@example.com";
    assert!(pdf.windows(expected.len()).any(|w| w == expected));
    assert!(doc.text.contains("a(b)c\\d\u{d55c}@example.com"));
}

#[test]
fn the_qr_carries_the_kit_blob_as_base32() {
    let kit = kit("alice@example.com");
    let text = kit.qr_text().unwrap();
    let blob = hasp_proto::crockford_decode(&text).unwrap();
    let parsed = EmergencyKit::parse_qr(&blob).unwrap();
    assert_eq!(parsed.login, "alice@example.com");
    assert_eq!(parsed.server_fp, [7; 15]);
}
