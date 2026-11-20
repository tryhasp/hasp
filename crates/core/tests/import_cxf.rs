#![expect(
    clippy::unwrap_used,
    reason = "helper functions of an integration test crate"
)]

use hasp_core::import::report::{Note, Subject};
use hasp_core::import::{ImportBatch, ImportError, Source, cxf};
use hasp_core::model::field::{FieldValue, Purpose};
use hasp_core::model::item::Item;
use hasp_core::model::url::MatchMode;
use hasp_core::testing::{export_cxf, field, find, fixture, lost, templates, value};

fn spec_batch() -> ImportBatch {
    cxf::parse(&fixture("cxf-spec-appendix-a.json"), &templates()).unwrap()
}

fn items(batch: &ImportBatch) -> Vec<&Item> {
    batch
        .vaults
        .iter()
        .flat_map(|v| v.items.iter().map(|i| &i.item))
        .collect()
}

#[test]
fn spec_appendix_a_maps_logins_passkeys_cards_and_notes() {
    let batch = spec_batch();
    assert_eq!(batch.source, Source::Cxf);
    assert_eq!(batch.report.items.len(), 14);
    assert!(batch.report.notes.contains(&Note::HistoryStartsAtImport));

    let login = find(&batch, "GitHub Login");
    let overview = login.item.overview();
    assert_eq!(overview.kind, "login");
    assert_eq!(overview.subtitle, "johndoe");
    assert!(overview.flags.has_totp);
    let tags: Vec<&str> = overview
        .tags
        .iter()
        .map(hasp_core::model::tag::Tag::as_str)
        .collect();
    assert!(tags.contains(&"collection/Work Accounts") && tags.contains(&"development"));
    assert_eq!(value(&login.item, "password"), "securepassword123");
    let urls = &login.item.details().urls;
    assert_eq!(urls[0].url(), "https://github.com");
    assert_eq!(urls[0].mode(), MatchMode::Domain);

    let passkey = find(&batch, "WebAuthn.io");
    let details = passkey.item.details();
    assert_eq!(details.passkeys.len(), 1);
    assert_eq!(details.passkeys[0].rp_id, "webauthn.io");
    assert_eq!(details.passkeys[0].user_name, "johndoe");
    assert_eq!(details.passkeys[0].credential_id, b"credentialIdExample");
    assert_eq!(details.urls[0].url(), "https://webauthn.io");
    assert!(lost(&batch, "WebAuthn.io").iter().any(
        |(subject, fate)| matches!(subject, Subject::Passkey(rp) if rp == "webauthn.io")
            && fate.is_loss()
    ));

    let card = find(&batch, "Visa Credit Card");
    assert_eq!(card.item.overview().kind, "credit-card");
    assert_eq!(value(&card.item, "number"), "4111111111111111");
    assert!(field(&card.item, "number").unwrap().is_concealed());
    assert_eq!(value(&card.item, "expiry date"), "2027-8");
    assert_eq!(value(&card.item, "verification number"), "123");

    let note = find(&batch, "Home alarm");
    assert_eq!(note.item.overview().kind, "secure-note");
    assert_eq!(
        note.item.details().notes.as_deref(),
        Some("some instructionts to enable/disable the alarm")
    );
}

#[test]
fn spec_appendix_a_keeps_unmapped_types_as_custom_items_and_reports_them() {
    let batch = spec_batch();
    let wifi = find(&batch, "Wifi");
    assert_eq!(wifi.item.overview().kind, "custom");
    assert!(
        lost(&batch, "Wifi")
            .iter()
            .any(|(subject, _)| *subject == Subject::Category("wifi".to_owned()))
    );
    let ssh = find(&batch, "SSH Key");
    assert!(
        field(&ssh.item, "ssh-key/privateKey")
            .unwrap()
            .is_concealed()
    );
    let generated = find(&batch, "Generated Password");
    assert_eq!(generated.item.overview().kind, "login");
    assert_eq!(value(&generated.item, "password"), "KozyS!cf#Nc9C799");
    assert!(
        lost(&batch, "ID card")
            .iter()
            .any(|(subject, _)| matches!(subject, Subject::Attachment(_)))
    );
}

#[test]
fn totp_algorithm_and_secret_are_kept() {
    let batch = spec_batch();
    let login = find(&batch, "GitHub Login");
    let otp = login
        .item
        .details()
        .sections
        .iter()
        .flat_map(hasp_core::model::field::Section::fields)
        .find_map(|f| match f.value() {
            FieldValue::Otp(params) => Some(params),
            _ => None,
        })
        .unwrap();
    assert_eq!(otp.algorithm().name(), "SHA256");
    assert_eq!(otp.issuer(), Some("Google"));
    assert_eq!(otp.account(), Some("jane.smith@example.com"));
    assert_eq!(otp.digits(), 6);
}

#[test]
fn unknown_totp_algorithms_and_bad_passkey_keys_are_reported_not_imported() {
    let document = br#"{"version":{"major":1,"minor":0},"exporterRpId":"x","exporterDisplayName":"x","timestamp":1,
      "accounts":[{"id":"a","username":"u","email":"e","collections":[],"items":[
        {"id":"i","title":"Odd","credentials":[
          {"type":"totp","secret":"JBSWY3DPEHPK3PXP","period":30,"digits":6,"algorithm":"md5"},
          {"type":"passkey","credentialId":"AQID","rpId":"example.com","username":"u","userDisplayName":"u","userHandle":"AQ","key":"AAAA"}
        ]}]}]}"#;
    let batch = cxf::parse(document, &templates()).unwrap();
    let odd = find(&batch, "Odd");
    assert!(!odd.item.overview().flags.has_totp);
    assert!(odd.item.details().passkeys.is_empty());
    assert_eq!(lost(&batch, "Odd").len(), 2);
}

#[test]
fn rejects_other_major_versions_and_malformed_documents() {
    let templates = templates();
    assert!(matches!(
        cxf::parse(
            br#"{"version":{"major":2,"minor":0},"accounts":[]}"#,
            &templates
        ),
        Err(ImportError::Unsupported(_))
    ));
    assert!(matches!(
        cxf::parse(b"{\"accounts\": [", &templates),
        Err(ImportError::Json { .. })
    ));
    assert!(matches!(
        cxf::parse(b"[]", &templates),
        Err(ImportError::Format(_))
    ));
    assert!(matches!(
        cxf::parse(b"{}", &templates),
        Err(ImportError::Format(_))
    ));
}

#[test]
fn accepts_padded_base64_float_timestamps_and_unknown_members() {
    let document = br#"{"version":{"major":1,"minor":3},"futureMember":1,"exporterRpId":"x","exporterDisplayName":"x","timestamp":1,
      "accounts":[{"id":"a","username":"u","email":"e","collections":[],"items":[
        {"id":"i","title":"Padded","creationAt":1705228800.0,"modifiedAt":1705315200.0,"credentials":[
          {"type":"basic-auth","username":{"fieldType":"string","value":"bob"},"password":{"fieldType":"concealed-string","value":"pw"},"someFuture":true},
          {"type":"hologram","payload":"x"}
        ]}]}]}"#;
    let batch = cxf::parse(document, &templates()).unwrap();
    let item = find(&batch, "Padded");
    assert_eq!(item.item.overview().created, 1_705_228_800);
    assert_eq!(item.item.overview().client_modified, 1_705_315_200);
    assert_eq!(value(&item.item, "username"), "bob");
}

#[test]
fn export_then_import_round_trips_the_mapped_types() {
    let first = spec_batch();
    let mapped: Vec<(String, &Item)> = items(&first)
        .into_iter()
        .filter(|item| {
            matches!(
                item.overview().kind.as_str(),
                "login" | "credit-card" | "secure-note"
            )
        })
        .enumerate()
        .map(|(n, item)| (format!("item-{n}"), item))
        .collect();
    let exported = export_cxf(&mapped);
    let second = cxf::parse(exported.as_bytes(), &templates()).unwrap();
    assert_eq!(items(&second).len(), mapped.len());
    for (_, original) in &mapped {
        let title = &original.overview().title;
        let again = &find(&second, title).item;
        assert_eq!(again.overview().kind, original.overview().kind, "{title}");
        assert_eq!(again.overview().subtitle, original.overview().subtitle);
        assert_eq!(again.overview().favourite, original.overview().favourite);
        assert_eq!(again.overview().created, original.overview().created);
        assert_eq!(again.overview().flags, original.overview().flags);
        assert_eq!(again.details().notes, original.details().notes);
        assert_eq!(
            again
                .details()
                .urls
                .iter()
                .map(hasp_core::model::url::UrlEntry::url)
                .collect::<Vec<_>>(),
            original
                .details()
                .urls
                .iter()
                .map(hasp_core::model::url::UrlEntry::url)
                .collect::<Vec<_>>()
        );
        for purpose in [
            Purpose::Username,
            Purpose::Password,
            Purpose::CardNumber,
            Purpose::CardCvc,
        ] {
            let pick = |item: &Item| {
                item.details()
                    .sections
                    .iter()
                    .flat_map(hasp_core::model::field::Section::fields)
                    .find(|f| f.purpose() == Some(purpose))
                    .map(hasp_core::testing::text_of)
            };
            assert_eq!(pick(again), pick(original), "{title} {purpose:?}");
        }
        let keys = |item: &Item| {
            item.details()
                .passkeys
                .iter()
                .map(|p| {
                    (
                        p.credential_id.clone(),
                        p.rp_id.clone(),
                        p.user_handle.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(keys(again), keys(original));
    }
}

#[test]
fn the_shape_apple_encodes_for_an_import_is_accepted_with_unix_second_dates() {
    let batch = cxf::parse(&fixture("cxf-apple-encoder.json"), &templates()).unwrap();
    let example = find(&batch, "Example");
    let overview = example.item.overview();
    assert_eq!(overview.kind, "login");
    assert!(overview.flags.has_totp);
    assert_eq!(value(&example.item, "password"), "pw123");
    let details = example.item.details();
    assert_eq!(details.passkeys.len(), 1);
    assert_eq!(details.passkeys[0].rp_id, "example.com");
    assert_eq!(details.passkeys[0].credential_id, [1, 2, 3, 4]);
    assert_eq!(details.urls[0].url(), "https://example.com");
    let tags: Vec<&str> = overview
        .tags
        .iter()
        .map(hasp_core::model::tag::Tag::as_str)
        .collect();
    assert!(tags.contains(&"collection/Work") && tags.contains(&"a"));
    assert!(
        lost(&batch, "Example")
            .iter()
            .all(|(_, fate)| !fate.is_loss())
    );
}

fn spec_json() -> serde_json::Value {
    serde_json::from_slice(&fixture("cxf-spec-appendix-a.json")).unwrap()
}

fn passkey_of(document: &mut serde_json::Value) -> &mut serde_json::Value {
    document["accounts"][0]["items"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .flat_map(|item| item["credentials"].as_array_mut().unwrap().iter_mut())
        .find(|credential| credential["type"] == "passkey")
        .unwrap()
}

fn parse_value(document: &serde_json::Value) -> ImportBatch {
    cxf::parse(&serde_json::to_vec(document).unwrap(), &templates()).unwrap()
}

fn minimal(accounts: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "version": {"major": 1, "minor": 0},
        "exporterRpId": "x",
        "exporterDisplayName": "x",
        "timestamp": 1,
        "accounts": accounts,
    }))
    .unwrap()
}

#[test]
fn a_document_over_the_size_cap_is_refused_before_parsing() {
    let mut huge = b"{\"accounts\":[],\"pad\":\"".to_vec();
    huge.resize((32 << 20) + 1, b'x');
    assert!(matches!(
        cxf::parse(&huge, &templates()),
        Err(ImportError::Limit(_))
    ));
}

#[test]
fn item_account_collection_and_credential_counts_are_capped() {
    let many_items: Vec<_> = (0..50_001)
        .map(|n| serde_json::json!({"id": n.to_string(), "title": "t", "credentials": []}))
        .collect();
    let accounts = serde_json::json!([{"id": "a", "items": many_items, "collections": []}]);
    assert!(matches!(
        cxf::parse(&minimal(&accounts), &templates()),
        Err(ImportError::Limit("items"))
    ));

    let many_accounts: Vec<_> = (0..65)
        .map(|n| serde_json::json!({"id": n.to_string(), "items": [], "collections": []}))
        .collect();
    assert!(matches!(
        cxf::parse(&minimal(&serde_json::json!(many_accounts)), &templates()),
        Err(ImportError::Limit("accounts"))
    ));

    let many_collections: Vec<_> = (0..10_001)
        .map(|n| serde_json::json!({"id": n.to_string(), "title": "c", "items": []}))
        .collect();
    let accounts = serde_json::json!([{"id": "a", "items": [], "collections": many_collections}]);
    assert!(matches!(
        cxf::parse(&minimal(&accounts), &templates()),
        Err(ImportError::Limit("collections"))
    ));

    let credentials: Vec<_> = (0..65)
        .map(|_| serde_json::json!({"type": "note", "content": {"value": "x", "fieldType": "string"}}))
        .collect();
    let accounts = serde_json::json!([{"id": "a", "collections": [],
        "items": [{"id": "1", "title": "t", "credentials": credentials}]}]);
    assert!(matches!(
        cxf::parse(&minimal(&accounts), &templates()),
        Err(ImportError::Limit("credentials per item"))
    ));
}

#[test]
fn collection_membership_comes_from_one_pass_over_nested_collections() {
    let items: Vec<_> = (0..300)
        .map(|n| {
            serde_json::json!({"id": format!("i{n}"), "title": format!("T{n}"),
            "credentials": [{"type": "note", "content": {"value": "x", "fieldType": "string"}}]})
        })
        .collect();
    let accounts = serde_json::json!([{"id": "a", "items": items, "collections": [
        {"id": "c1", "title": "Work", "items": [{"item": "i7", "account": "a"}, {"item": "i8", "account": "other"}],
         "subCollections": [{"id": "c2", "title": "Deep", "items": [{"item": "i7"}]}]}
    ]}]);
    let batch = cxf::parse(&minimal(&accounts), &templates()).unwrap();
    let tags = |title: &str| -> Vec<String> {
        find(&batch, title)
            .item
            .overview()
            .tags
            .iter()
            .map(|t| t.as_str().to_owned())
            .collect()
    };
    let seven = tags("T7");
    assert!(seven.contains(&"collection/Work".to_owned()));
    assert!(seven.contains(&"collection/Work/Deep".to_owned()));
    assert!(tags("T8").iter().all(|t| !t.starts_with("collection/")));
}

#[test]
fn a_repeated_source_id_is_reported_not_silently_hidden() {
    let accounts = serde_json::json!([{"id": "a", "collections": [], "items": [
        {"id": "1", "title": "First", "credentials": [{"type": "note", "content": {"value": "x", "fieldType": "string"}}]},
        {"id": "1", "title": "Second", "credentials": [{"type": "note", "content": {"value": "y", "fieldType": "string"}}]}
    ]}]);
    let batch = cxf::parse(&minimal(&accounts), &templates()).unwrap();
    assert_eq!(batch.vaults[0].items.len(), 1);
    assert_eq!(batch.report.items.len(), 2);
    let skipped = &batch.report.items[1];
    assert_eq!(skipped.title, "Second");
    assert!(skipped.entries.iter().any(|e| e.fate.is_loss()));
}

#[test]
fn passkeys_with_invalid_rp_ids_or_oversize_ids_are_reported_as_lost() {
    let cases: [(&str, serde_json::Value); 4] = [
        ("rpId", serde_json::json!("not a host")),
        ("rpId", serde_json::json!("com")),
        ("credentialId", serde_json::json!("QUJD".repeat(400))),
        ("userHandle", serde_json::json!("QUJD".repeat(30))),
    ];
    for (member, value) in cases {
        let mut document = spec_json();
        passkey_of(&mut document)[member] = value;
        let batch = parse_value(&document);
        assert!(
            lost(&batch, "WebAuthn.io")
                .iter()
                .any(|(subject, fate)| matches!(subject, Subject::Passkey(_)) && fate.is_loss()),
            "{member} is reported"
        );
        assert!(
            find(&batch, "WebAuthn.io")
                .item
                .details()
                .passkeys
                .is_empty()
        );
    }
}

#[test]
fn an_rp_id_is_lowercased_on_import() {
    let mut document = spec_json();
    passkey_of(&mut document)["rpId"] = serde_json::json!("WebAuthn.IO");
    let batch = parse_value(&document);
    assert_eq!(
        find(&batch, "WebAuthn.io").item.details().passkeys[0].rp_id,
        "webauthn.io"
    );
}

#[test]
fn bare_string_members_of_unmapped_types_are_concealed() {
    let accounts = serde_json::json!([{"id": "a", "collections": [], "items": [
        {"id": "1", "title": "Router", "credentials": [{"type": "router-admin", "passphrase": "hunter2", "pin": "1234"}]}
    ]}]);
    let batch = cxf::parse(&minimal(&accounts), &templates()).unwrap();
    let router = find(&batch, "Router");
    for label in ["router-admin/passphrase", "router-admin/pin"] {
        assert!(
            field(&router.item, label).unwrap().is_concealed(),
            "{label}"
        );
    }
}
