#![expect(
    clippy::unwrap_used,
    reason = "helper functions of an integration test crate"
)]

use hasp_core::import::{ImportBatch, ImportError, Source, delimited};
use hasp_core::testing::{field, find, fixture, templates, value};

fn csv_batch(name: &str) -> ImportBatch {
    delimited::parse(&fixture(name), &templates()).unwrap()
}

#[test]
fn csv_chrome_handles_quoted_newlines_and_empty_notes() {
    let batch = csv_batch("csv-chrome.csv");
    assert_eq!(batch.source, Source::Csv);
    assert_eq!(batch.item_count(), 2);
    let example = find(&batch, "Example");
    assert_eq!(
        example.item.details().notes.as_deref(),
        Some("line1\nline2")
    );
    assert_eq!(value(&example.item, "password"), "pw1");
    assert_eq!(
        example.item.details().urls[0].url(),
        "https://example.com/login"
    );
    assert!(find(&batch, "NoNote").item.details().notes.is_none());
}

#[test]
fn csv_safari_with_bom_reads_otp_auth() {
    let batch = csv_batch("csv-safari.csv");
    let item = find(&batch, "Apple Site");
    assert!(item.item.overview().flags.has_totp);
    assert_eq!(value(&item.item, "username"), "carol");
}

#[test]
fn csv_firefox_ignores_metadata_columns_and_titles_from_host() {
    let batch = csv_batch("csv-firefox.csv");
    let item = find(&batch, "fox.example.com");
    assert_eq!(value(&item.item, "password"), "pw4");
    assert!(field(&item.item, "guid").is_none());
}

#[test]
fn csv_lastpass_maps_favourites_folders_secure_notes_and_bare_totp() {
    let batch = csv_batch("csv-lastpass.csv");
    let site = find(&batch, "LastPass Site");
    assert_eq!(site.item.overview().favourite, Some(1));
    assert_eq!(site.item.overview().tags[0].as_str(), "Shopping");
    assert_eq!(site.item.details().notes.as_deref(), Some("lp note"));
    assert!(site.item.overview().flags.has_totp);
    let note = find(&batch, "A secure note");
    assert_eq!(note.item.overview().kind, "secure-note");
    assert_eq!(note.item.details().notes.as_deref(), Some("secret body"));
    assert!(note.item.details().urls.is_empty());
}

#[test]
fn csv_bitwarden_reads_types_custom_fields_and_folders() {
    let batch = csv_batch("csv-bitwarden.csv");
    let site = find(&batch, "BW Site");
    assert_eq!(value(&site.item, "pin"), "9999");
    assert_eq!(value(&site.item, "tier"), "gold");
    assert_eq!(site.item.overview().tags[0].as_str(), "Work");
    assert_eq!(site.item.overview().favourite, Some(1));
    assert_eq!(find(&batch, "BW Note").item.overview().kind, "secure-note");
}

#[test]
fn csv_one_password_and_keepass_variants_share_one_parser() {
    let op = csv_batch("csv-1password.csv");
    let item = find(&op, "OP Site");
    let tags: Vec<&str> = item
        .item
        .overview()
        .tags
        .iter()
        .map(hasp_core::model::tag::Tag::as_str)
        .collect();
    assert_eq!(tags, ["a", "b"]);
    let keepass = csv_batch("csv-keepass.csv");
    let item = find(&keepass, "KP Site");
    assert_eq!(value(&item.item, "username"), "heidi");
    assert_eq!(item.item.details().notes.as_deref(), Some("kp note"));
    assert_eq!(
        delimited::detect(&fixture("csv-keepass.csv"))
            .unwrap()
            .delimiter,
        b';'
    );
}

#[test]
fn csv_unknown_columns_become_fields_and_secret_looking_ones_are_concealed() {
    let batch = csv_batch("csv-unknown-columns.csv");
    let item = find(&batch, "Cols");
    assert_eq!(value(&item.item, "security question"), "blue");
    assert!(
        !field(&item.item, "security question")
            .unwrap()
            .is_concealed()
    );
    assert_eq!(value(&item.item, "secret code"), "s3cr3t");
    assert!(field(&item.item, "secret code").unwrap().is_concealed());
}

#[test]
fn csv_decodes_utf16_and_rejects_bad_input() {
    let batch = csv_batch("csv-utf16.csv");
    assert_eq!(value(&find(&batch, "Utf16 Site").item, "password"), "pw10");
    let templates = templates();
    assert!(matches!(
        delimited::parse(b"", &templates),
        Err(ImportError::Csv("empty file"))
    ));
    assert!(matches!(
        delimited::parse(b"alpha,beta\n1,2\n", &templates),
        Err(ImportError::Csv("no recognised columns"))
    ));
    assert!(matches!(
        delimited::parse(
            &[b'n', b'a', b'm', b'e', b'\n', 0xff, 0xfe, 0xfd],
            &templates
        ),
        Err(ImportError::Csv("not utf-8"))
    ));
}

#[test]
fn csv_duplicate_roles_keep_the_first_and_blank_rows_are_skipped() {
    let batch = delimited::parse(
        b"name,url,username,email,password\nSite,https://a.example.com,u1,e1@example.com,p\n,,,,\n",
        &templates(),
    )
    .unwrap();
    assert_eq!(batch.item_count(), 1);
    let item = find(&batch, "Site");
    assert_eq!(value(&item.item, "username"), "u1");
    assert_eq!(value(&item.item, "email"), "e1@example.com");
}

#[test]
fn csv_user_can_override_the_detected_mapping() {
    let bytes = b"label,secret,host\nSite,pw,https://a.example.com\n";
    assert!(matches!(
        delimited::detect(bytes),
        Err(ImportError::Csv("no recognised columns"))
    ));
    let plan = delimited::CsvPlan {
        delimiter: b',',
        headers: vec!["label".into(), "secret".into(), "host".into()],
        columns: vec![
            delimited::Column::Title,
            delimited::Column::Password,
            delimited::Column::Url,
        ],
    };
    let batch = delimited::parse_with_plan(bytes, &plan, &templates()).unwrap();
    assert_eq!(value(&find(&batch, "Site").item, "password"), "pw");
}

#[test]
fn csv_source_ids_follow_the_login_not_the_row_number() {
    let ids = |name: &str| -> Vec<String> {
        csv_batch(name).vaults[0]
            .items
            .iter()
            .map(|entry| entry.source_id.clone())
            .collect()
    };
    let chrome = ids("csv-chrome.csv");
    let bitwarden = ids("csv-bitwarden.csv");
    assert!(
        chrome.iter().all(|id| !bitwarden.contains(id)),
        "two different CSV files must not share source ids: {chrome:?} {bitwarden:?}"
    );
    assert_eq!(chrome, ids("csv-chrome.csv"), "a re-read keeps the ids");
    let unique: std::collections::BTreeSet<_> = chrome.iter().collect();
    assert_eq!(unique.len(), chrome.len());
}
