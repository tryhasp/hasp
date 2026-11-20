use super::*;
use crate::model::item::{Item, ItemParts, ItemState};

const MINIMAL: &str = r#"{
    "id": "thing", "version": 1, "name": {"en": "Thing", "ko": "물건"}, "icon": "box",
    "sections": [{"key": "main", "fields": [
        {"key": "name", "label": {"en": "name", "ko": "이름"}, "kind": "text", "purpose": "username"}
    ]}],
    "capabilities": {"autofill": "none"}
}"#;

fn templates() -> Templates {
    Templates::bundled().unwrap()
}

fn counter() -> impl FnMut() -> Result<Id, ModelError> {
    let mut next = 0u8;
    move || {
        next += 1;
        Ok(Id::from_bytes([next; 16]))
    }
}

fn with(replace: (&str, &str)) -> String {
    assert!(MINIMAL.contains(replace.0), "{}", replace.0);
    MINIMAL.replace(replace.0, replace.1)
}

#[test]
fn bundled_set_covers_every_one_password_category_and_custom() {
    let templates = templates();
    let expected = [
        "login",
        "password",
        "secure-note",
        "credit-card",
        "identity",
        "document",
        "ssh-key",
        "api-credential",
        "wireless-router",
        "bank-account",
        "passport",
        "driver-license",
        "social-security-number",
        "software-license",
        "server",
        "database",
        "email-account",
        "crypto-wallet",
        "membership",
        "reward-program",
        "medical-record",
        "outdoor-license",
        "custom",
    ];
    assert_eq!(templates.len(), expected.len());
    for id in expected {
        assert!(templates.get(id).is_some(), "{id}");
    }
}

#[test]
fn every_template_file_is_bundled() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
    let mut files: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    files.sort();
    let mut ids: Vec<String> = templates()
        .iter()
        .map(|t| format!("{}.json", t.id))
        .collect();
    ids.sort();
    assert_eq!(files, ids);
}

#[test]
fn one_password_import_codes_map_to_distinct_templates() {
    let templates = templates();
    let mut seen = BTreeSet::new();
    let codes = (1..=6).chain(100..=115).map(|n| format!("{n:03}"));
    for code in codes {
        let template = templates.by_import_code("1pux", &code);
        assert_ne!(template.id, CUSTOM_ID, "{code}");
        assert!(seen.insert(template.id.clone()), "{code}");
    }
    assert_eq!(templates.by_import_code("1pux", "999").id, CUSTOM_ID);
    assert_eq!(templates.by_import_code("bitwarden", "3").id, "credit-card");
    assert_eq!(templates.by_import_code("bitwarden", "2").id, "secure-note");
}

#[test]
fn every_template_has_both_languages_and_a_valid_shape() {
    for template in templates().iter() {
        assert!(
            !template.name.ko.is_empty() && !template.name.en.is_empty(),
            "{}",
            template.id
        );
        for field in template.fields() {
            assert!(!field.label.ko.is_empty(), "{} {}", template.id, field.key);
        }
    }
}

#[test]
fn login_template_drives_autofill_and_watchtower() {
    let templates = templates();
    let login = templates.resolve("login").unwrap();
    assert_eq!(login.capabilities.autofill, AutofillClass::Login);
    assert!(login.field_with_purpose(Purpose::Password).is_some());
    assert!(login.field_with_purpose(Purpose::Totp).is_some());
    assert!(
        login
            .capabilities
            .watchtower
            .contains(&WatchtowerCheck::InsecureUrl)
    );
    assert_eq!(
        templates
            .get("credit-card")
            .unwrap()
            .capabilities
            .expiry_window_days,
        Some(60)
    );
    assert_eq!(
        templates
            .get("api-credential")
            .unwrap()
            .capabilities
            .expiry_window_days,
        Some(90)
    );
    assert_eq!(
        templates
            .get("passport")
            .unwrap()
            .capabilities
            .expiry_window_days,
        Some(300)
    );
}

#[test]
fn rejects_invalid_templates() {
    let cases = [
        with(("\"id\": \"thing\"", "\"id\": \"Thing\"")),
        with(("\"version\": 1", "\"version\": 0")),
        with(("\"ko\": \"물건\"", "\"ko\": \"\"")),
        with(("\"key\": \"main\"", "\"key\": \"Main!\"")),
        with(("\"kind\": \"text\"", "\"kind\": \"otp\"")),
        with(("\"kind\": \"text\"", "\"kind\": \"menu\"")),
        with((
            "\"kind\": \"text\"",
            "\"kind\": \"text\", \"options\": [\"a\"]",
        )),
        with(("\"kind\": \"text\"", "\"kind\": \"nonsense\"")),
        with(("\"purpose\": \"username\"", "\"purpose\": \"totp\"")),
        with(("{\"autofill\": \"none\"}", "{\"autofill\": \"card\"}")),
        with((
            "{\"autofill\": \"none\"}",
            "{\"autofill\": \"none\", \"watchtower\": [\"weak\"]}",
        )),
        with((
            "{\"autofill\": \"none\"}",
            "{\"autofill\": \"none\", \"watchtower\": [\"expiring\"]}",
        )),
        with((
            "{\"autofill\": \"none\"}",
            "{\"autofill\": \"none\", \"expiry_window_days\": 0}",
        )),
        with((
            "{\"autofill\": \"none\"}",
            "{\"autofill\": \"none\", \"requires_attachment\": true}",
        )),
        with((
            "{\"autofill\": \"none\"}",
            "{\"autofill\": \"none\", \"surprise\": 1}",
        )),
        "not json".to_owned(),
    ];
    for json in cases {
        assert!(CategoryTemplate::parse(&json).is_err(), "{json}");
    }
    assert!(CategoryTemplate::parse(MINIMAL).is_ok());
}

#[test]
fn rejects_duplicate_field_keys_and_purposes() {
    let two_keys = MINIMAL.replace(
        "]}],",
        ", {\"key\": \"name\", \"label\": {\"en\": \"x\", \"ko\": \"x\"}, \"kind\": \"text\"}]}],",
    );
    assert!(CategoryTemplate::parse(&two_keys).is_err());
    let two_purposes = MINIMAL.replace(
        "]}],",
        ", {\"key\": \"other\", \"label\": {\"en\": \"x\", \"ko\": \"x\"}, \"kind\": \"text\", \"purpose\": \"username\"}]}],",
    );
    assert!(CategoryTemplate::parse(&two_purposes).is_err());
}

#[test]
fn a_set_needs_custom_unique_ids_and_valid_promotions() {
    let custom = include_str!("../../../templates/custom.json");
    assert!(Templates::from_json([MINIMAL]).is_err());
    assert!(Templates::from_json([MINIMAL, MINIMAL, custom]).is_err());
    assert!(Templates::from_json([MINIMAL, custom]).is_ok());
    let promoting = MINIMAL.replace(
        "\"capabilities\"",
        "\"promotion\": {\"to\": \"missing\", \"when_filled\": \"username\"}, \"capabilities\"",
    );
    assert!(Templates::from_json([promoting.as_str(), custom]).is_err());
    let to_self = promoting.replace("missing", "thing");
    assert!(Templates::from_json([to_self.as_str(), custom]).is_err());
}

#[test]
fn blank_sections_follow_the_template() {
    let templates = templates();
    let login = templates.get("login").unwrap();
    let sections = login.blank_sections(counter()).unwrap();
    assert_eq!(sections.len(), 1);
    let fields = sections[0].fields();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0].purpose(), Some(Purpose::Username));
    assert_eq!(fields[1].purpose(), Some(Purpose::Password));
    assert!(fields[1].is_concealed());
    let card = templates
        .get("credit-card")
        .unwrap()
        .blank_sections(counter())
        .unwrap();
    assert_eq!(card.len(), 3);
    assert!(
        card[0]
            .fields()
            .iter()
            .any(|f| f.purpose() == Some(Purpose::CardNumber) && f.is_concealed())
    );
}

fn parts(kind: &str, sections: Vec<Section>) -> ItemParts {
    ItemParts {
        kind: kind.to_owned(),
        title: "t".to_owned(),
        subtitle: String::new(),
        tags: Vec::new(),
        favourite: None,
        state: ItemState::Active,
        sections,
        notes: None,
        urls: Vec::new(),
        apps: Vec::new(),
        passkeys: Vec::new(),
        attachments: Vec::new(),
        password_history: Vec::new(),
        client_modified: 1,
        created: 1,
        expires_at: None,
    }
}

#[test]
fn password_becomes_login_once_a_username_is_filled() {
    let templates = templates();
    let mut ids = counter();
    let password = templates
        .get("password")
        .unwrap()
        .blank_sections(&mut ids)
        .unwrap();
    let item = Item::new(parts("password", password)).unwrap();
    assert_eq!(
        templates.kind_after_edit("password", item.details()),
        "password"
    );
    let user = Field::new(
        ids().unwrap(),
        "username",
        FieldValue::Text("alice".to_owned()),
    )
    .unwrap()
    .with_purpose(Purpose::Username)
    .unwrap();
    let blank_user = Field::new(ids().unwrap(), "username", FieldValue::Text(String::new()))
        .unwrap()
        .with_purpose(Purpose::Username)
        .unwrap();
    let empty = Item::new(parts(
        "password",
        vec![Section::new(ids().unwrap(), "", vec![blank_user]).unwrap()],
    ))
    .unwrap();
    assert_eq!(
        templates.kind_after_edit("password", empty.details()),
        "password"
    );
    let filled = Item::new(parts(
        "password",
        vec![Section::new(ids().unwrap(), "", vec![user]).unwrap()],
    ))
    .unwrap();
    assert_eq!(
        templates.kind_after_edit("password", filled.details()),
        "login"
    );
    assert_eq!(
        templates.kind_after_edit("login", filled.details()),
        "login"
    );
    assert_eq!(
        templates.kind_after_edit("unknown-kind", filled.details()),
        "unknown-kind"
    );
}

#[test]
fn document_requires_an_attachment_and_unknown_kinds_pass() {
    let templates = templates();
    let item = Item::new(parts("document", Vec::new())).unwrap();
    assert!(templates.check_details("document", item.details()).is_err());
    assert!(templates.check_details("login", item.details()).is_ok());
    assert!(
        templates
            .check_details("from-the-future", item.details())
            .is_ok()
    );
}
