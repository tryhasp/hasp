use hasp_wasm::{normalise_login, normalise_password, vector_groups};

#[test]
fn lists_every_vector_group() {
    let groups = vector_groups();
    assert!(groups.contains(&"proto/verify".to_owned()));
    assert!(groups.contains(&"text/login".to_owned()));
}

#[test]
fn normalises_text_in_rust() {
    assert_eq!(normalise_password("  \u{3142}  "), "\u{1107}");
    assert_eq!(
        normalise_login(" \u{ff21}b ").map_err(|_| ()).unwrap(),
        "ab"
    );
}
