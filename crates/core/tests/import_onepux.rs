#![expect(
    clippy::unwrap_used,
    reason = "helper functions of an integration test crate"
)]

use std::io::Write;

use hasp_core::import::onepux::{self, Limits};
use hasp_core::import::report::{Fate, Note, Outcome, Reason, Subject};
use hasp_core::import::{ImportBatch, ImportError, Source};
use hasp_core::model::field::{FieldKind, Purpose};
use hasp_core::model::item::ItemState;
use hasp_core::model::url::MatchMode;
use hasp_core::testing::{field, find, fixture, lost, templates, value};
use hasp_proto::VaultKind;
use secrecy::ExposeSecret;

fn onepux_batch() -> ImportBatch {
    onepux::parse(&fixture("onepux-basic.1pux"), &templates()).unwrap()
}

fn zip_of(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut buffer = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(&mut buffer);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, data) in entries {
        writer.start_file(*name, options).unwrap();
        writer.write_all(data).unwrap();
    }
    writer.finish().unwrap();
    buffer.into_inner()
}

#[test]
fn onepux_imports_every_item_and_both_vaults() {
    let batch = onepux_batch();
    assert_eq!(batch.source, Source::OnePassword);
    assert_eq!(batch.vaults.len(), 2);
    assert_eq!(batch.vaults[0].kind, VaultKind::Private);
    assert_eq!(batch.vaults[0].name, "Personal");
    assert_eq!(batch.vaults[1].kind, VaultKind::Shared);
    assert_eq!(batch.item_count(), 13);
    let counts = batch.counts_by_kind();
    assert_eq!(counts["login"], 4);
    assert_eq!(counts["document"], 1);
    assert_eq!(counts["custom"], 2);
    for kind in [
        "credit-card",
        "identity",
        "secure-note",
        "password",
        "ssh-key",
        "api-credential",
    ] {
        assert_eq!(counts[kind], 1, "{kind}");
    }
    assert!(batch.report.notes.contains(&Note::HistoryStartsAtImport));
    assert!(
        batch
            .report
            .notes
            .contains(&Note::SharedVaultMembersMustBeReinvited {
                vault: "Family".to_owned()
            })
    );
    assert_eq!(batch.report.counts().skipped, 0);
}

#[test]
fn onepux_login_keeps_fields_tags_and_state() {
    let batch = onepux_batch();
    let login = find(&batch, "Example Bank");
    let overview = login.item.overview();
    assert_eq!(overview.favourite, Some(2));
    assert_eq!(overview.created, 1_700_000_000);
    assert_eq!(overview.client_modified, 1_701_000_000);
    assert_eq!(overview.subtitle, "alice@example.com");
    let tags: Vec<&str> = overview
        .tags
        .iter()
        .map(hasp_core::model::tag::Tag::as_str)
        .collect();
    assert_eq!(tags, ["Finance", "Work/Clients"]);
    assert!(overview.flags.has_totp);
    let details = login.item.details();
    assert_eq!(details.notes.as_deref(), Some("first line\nsecond line"));
    assert_eq!(value(&login.item, "username"), "alice@example.com");
    assert_eq!(
        value(&login.item, "password"),
        "correct-horse-battery-staple"
    );
    assert_eq!(
        field(&login.item, "password").unwrap().purpose(),
        Some(Purpose::Password)
    );
    assert_eq!(
        field(&login.item, "username").unwrap().purpose(),
        Some(Purpose::Username)
    );
    assert_eq!(
        field(&login.item, "one-time password").unwrap().purpose(),
        Some(Purpose::Totp)
    );
    assert_eq!(
        field(&login.item, "one-time password").unwrap().kind(),
        FieldKind::Otp
    );
    assert_eq!(value(&login.item, "pin"), "123456");
    assert!(field(&login.item, "pin").unwrap().is_concealed());
    assert_eq!(value(&login.item, "backup email"), "bob@example.com");
    assert_eq!(value(&login.item, "member since"), "2020-1-1");
    assert_eq!(
        field(&login.item, "backup email").unwrap().kind(),
        FieldKind::Email
    );
}

#[test]
fn onepux_login_keeps_history_and_url_modes_and_reports_what_was_lost() {
    let batch = onepux_batch();
    let login = find(&batch, "Example Bank");
    let details = login.item.details();
    let history: Vec<(&str, u64)> = details
        .password_history
        .iter()
        .map(|h| (h.value.expose_secret(), h.replaced_at))
        .collect();
    assert_eq!(
        history,
        [
            ("old-password-1", 1_690_000_000),
            ("old-password-2", 1_680_000_000)
        ]
    );
    assert_eq!(
        details.password_history[0].field,
        field(&login.item, "password").unwrap().id()
    );
    let modes: Vec<(&str, MatchMode)> = details.urls.iter().map(|u| (u.url(), u.mode())).collect();
    assert_eq!(
        modes,
        [
            ("https://bank.example.com/login", MatchMode::Domain),
            ("https://app.example.com", MatchMode::Host),
            ("https://skip.example.com", MatchMode::Never),
            ("https://exact.example.com/a", MatchMode::Host),
            ("https://bare.example.org", MatchMode::Domain),
        ]
    );
    let entries = lost(&batch, "Example Bank");
    assert!(entries.contains(&(
        Subject::Reference("linked item".to_owned()),
        Fate::Lost {
            reason: Reason::NoEquivalent
        }
    )));
    assert!(entries.contains(&(
        Subject::Url("https://exact.example.com/a".to_owned()),
        Fate::Approximated {
            reason: Reason::NoEquivalent
        }
    )));
}

#[test]
fn onepux_maps_cards_identities_notes_and_states() {
    let batch = onepux_batch();
    let card = find(&batch, "Visa Travel");
    assert_eq!(card.item.overview().kind, "credit-card");
    assert_eq!(value(&card.item, "number"), "4111111111111111");
    assert!(field(&card.item, "number").unwrap().is_concealed());
    assert_eq!(
        field(&card.item, "number").unwrap().purpose(),
        Some(Purpose::CardNumber)
    );
    assert_eq!(value(&card.item, "expiry date"), "2028-12");
    assert_eq!(value(&card.item, "verification number"), "123");
    let identity = find(&batch, "Alice Example");
    assert_eq!(
        value(&identity.item, "address"),
        "1 Main St|Springfield|IL|12345|us"
    );
    assert_eq!(
        field(&identity.item, "address").unwrap().purpose(),
        Some(Purpose::StreetAddress)
    );
    assert_eq!(value(&identity.item, "date of birth"), "1990-1-1");
    let note = find(&batch, "Wifi notes");
    assert_eq!(note.item.overview().kind, "secure-note");
    assert_eq!(
        note.item.overview().state,
        ItemState::Archived { at: 1_701_000_000 }
    );
    assert_eq!(
        note.item.details().notes.as_deref(),
        Some("router in closet")
    );
    let password = find(&batch, "Standalone");
    assert_eq!(
        password.item.overview().state,
        ItemState::Trashed { at: 1_701_000_000 }
    );
    assert_eq!(value(&password.item, "password"), "s3cret-value");
    let ssh = find(&batch, "Deploy key");
    assert_eq!(
        field(&ssh.item, "private key").unwrap().purpose(),
        Some(Purpose::SshPrivateKey)
    );
    assert_eq!(
        value(&ssh.item, "public key"),
        "ssh-ed25519 AAAAC3Nza deploy"
    );
    assert_eq!(value(&ssh.item, "key type"), "Ed25519");
    let api = find(&batch, "Cloud API");
    assert_eq!(api.item.overview().kind, "api-credential");
    assert_eq!(
        field(&api.item, "credential").unwrap().purpose(),
        Some(Purpose::ApiKey)
    );
}

#[test]
fn onepux_documents_and_attachments_resolve_from_the_files_folder() {
    let batch = onepux_batch();
    let doc = find(&batch, "Passport scan");
    assert_eq!(doc.item.overview().kind, "document");
    assert_eq!(doc.files.len(), 1);
    assert_eq!(doc.files[0].name, "passport.pdf");
    assert_eq!(doc.files[0].mime, "application/pdf");
    assert_eq!(doc.files[0].data.expose_secret(), b"%PDF-1.4 fake");
    let attached = find(&batch, "Login with attachment");
    assert_eq!(attached.files.len(), 1);
    assert_eq!(attached.files[0].name, "codes.txt");
    let missing = find(&batch, "Lost scan");
    assert_eq!(missing.item.overview().kind, "custom");
    let entries = lost(&batch, "Lost scan");
    assert!(entries.contains(&(
        Subject::Attachment("gone.png".to_owned()),
        Fate::Lost {
            reason: Reason::NotExportedBySource
        }
    )));
}

#[test]
fn onepux_unknown_category_falls_to_custom_and_keeps_known_fields() {
    let batch = onepux_batch();
    let future = find(&batch, "Future thing");
    assert_eq!(future.item.overview().kind, "custom");
    assert_eq!(value(&future.item, "mystery"), "value");
    let entries = lost(&batch, "Future thing");
    assert!(entries.contains(&(
        Subject::Category("999".to_owned()),
        Fate::Approximated {
            reason: Reason::NoEquivalent
        }
    )));
    assert!(entries.contains(&(
        Subject::Field("odd".to_owned()),
        Fate::Lost {
            reason: Reason::NoEquivalent
        }
    )));
    let report = batch
        .report
        .items
        .iter()
        .find(|i| i.title == "Future thing")
        .unwrap();
    assert_eq!(report.outcome, Outcome::ImportedWithLoss);
}

#[test]
fn onepux_passkeys_import_only_with_key_material() {
    let batch = onepux_batch();
    let item = find(&batch, "Passkey site");
    let passkeys = &item.item.details().passkeys;
    assert_eq!(passkeys.len(), 1);
    assert_eq!(passkeys[0].rp_id, "passkey.example.com");
    assert_eq!(passkeys[0].credential_id, [1, 2, 3, 4]);
    assert!(item.item.overview().flags.has_passkey);
    assert!(lost(&batch, "Passkey site").contains(&(
        Subject::Passkey("nokey.example.com".to_owned()),
        Fate::Lost {
            reason: Reason::NotExportedBySource
        }
    )));
}

#[test]
fn onepux_debug_output_hides_secrets() {
    let batch = onepux_batch();
    let rendered = format!("{batch:?}");
    for secret in [
        "correct-horse-battery-staple",
        "4111111111111111",
        "s3cret-value",
        "old-password-1",
    ] {
        assert!(!rendered.contains(secret), "{secret}");
    }
    let json = batch.report.to_json().unwrap();
    assert!(!json.contains("correct-horse"));
    assert!(json.contains("Example Bank"));
}

#[test]
fn onepux_rejects_malformed_containers() {
    let templates = templates();
    let good = fixture("onepux-basic.1pux");
    let parse = |bytes: &[u8]| onepux::parse(bytes, &templates).unwrap_err();
    assert!(matches!(parse(b"not a zip at all"), ImportError::Format(_)));
    assert!(matches!(parse(&[]), ImportError::Format(_)));
    assert!(matches!(
        parse(&good[..good.len() / 2]),
        ImportError::Format(_)
    ));
    let without_data = zip_of(&[("export.attributes", b"{}".to_vec())]);
    assert!(matches!(parse(&without_data), ImportError::Format(_)));
    let bad_json = zip_of(&[("export.data", b"{\"accounts\": [".to_vec())]);
    assert!(matches!(parse(&bad_json), ImportError::Json { .. }));
    let no_accounts = zip_of(&[("export.data", b"{}".to_vec())]);
    assert!(matches!(parse(&no_accounts), ImportError::Format(_)));
    let not_object = zip_of(&[("export.data", b"[1,2]".to_vec())]);
    assert!(matches!(parse(&not_object), ImportError::Format(_)));
}

#[test]
fn onepux_skips_unusable_items_but_keeps_the_rest() {
    let data = br#"{"accounts":[{"vaults":[{"attrs":{"name":"V","type":"P"},"items":[
        {"uuid":"a","categoryUuid":"001","details":{},"overview":{"title":"ok"}},
        {"uuid":"b","categoryUuid":"006","details":{},"overview":{"title":"doc without file"}},
        7]}]}]}"#;
    let bytes = zip_of(&[("export.data", data.to_vec())]);
    let batch = onepux::parse(&bytes, &templates()).unwrap();
    assert_eq!(batch.item_count(), 3);
    assert_eq!(
        find(&batch, "doc without file").item.overview().kind,
        "custom"
    );
}

#[test]
fn onepux_enforces_size_ratio_and_entry_limits() {
    let templates = templates();
    let good = fixture("onepux-basic.1pux");
    let small_data = Limits {
        max_data_bytes: 1000,
        ..Limits::STANDARD
    };
    assert!(matches!(
        onepux::parse_with(&good, &templates, &small_data),
        Err(ImportError::Limit("entry size"))
    ));
    let few_entries = Limits {
        max_entries: 2,
        ..Limits::STANDARD
    };
    assert!(matches!(
        onepux::parse_with(&good, &templates, &few_entries),
        Err(ImportError::Limit("zip entries"))
    ));
    let tiny_total = Limits {
        max_total_bytes: 100,
        ..Limits::STANDARD
    };
    assert!(onepux::parse_with(&good, &templates, &tiny_total).is_err());
    let mut padded = br#"{"accounts":[]}"#.to_vec();
    padded.extend(std::iter::repeat_n(b' ', 8 << 20));
    let bomb = zip_of(&[("export.data", padded)]);
    let strict = Limits {
        max_ratio: 100,
        ..Limits::STANDARD
    };
    assert!(matches!(
        onepux::parse_with(&bomb, &templates, &strict),
        Err(ImportError::Limit("compression ratio"))
    ));
    let one_file = Limits {
        max_file_bytes: 4,
        ..Limits::STANDARD
    };
    let batch = onepux::parse_with(&good, &templates, &one_file).unwrap();
    assert!(find(&batch, "Passport scan").files.is_empty());
    assert!(lost(&batch, "Passport scan").iter().any(|(_, f)| matches!(
        f,
        Fate::Lost {
            reason: Reason::TooLarge
        }
    )));
}
