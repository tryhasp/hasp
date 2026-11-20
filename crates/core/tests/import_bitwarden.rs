#![expect(
    clippy::unwrap_used,
    reason = "helper functions of an integration test crate"
)]

use hasp_core::import::report::{Note, Subject};
use hasp_core::import::{ImportBatch, ImportError, Source, bitwarden};
use hasp_core::model::field::Purpose;
use hasp_core::model::item::ItemState;
use hasp_core::model::url::MatchMode;
use hasp_core::testing::{field, find, fixture, lost, templates, value};
use hasp_proto::VaultKind;

fn bitwarden_batch() -> ImportBatch {
    bitwarden::parse(&fixture("bitwarden-individual.json"), &templates()).unwrap()
}

#[test]
fn bitwarden_imports_all_item_types() {
    let batch = bitwarden_batch();
    assert_eq!(batch.source, Source::Bitwarden);
    assert_eq!(batch.item_count(), 6);
    let counts = batch.counts_by_kind();
    assert_eq!(counts["login"], 2);
    for kind in ["secure-note", "credit-card", "identity", "ssh-key"] {
        assert_eq!(counts[kind], 1, "{kind}");
    }
    assert!(batch.report.notes.contains(&Note::AttachmentsNotInExport));
}

#[test]
fn bitwarden_login_maps_uris_totp_fields_history_and_passkeys() {
    let batch = bitwarden_batch();
    let login = find(&batch, "Example Login");
    let overview = login.item.overview();
    assert_eq!(overview.favourite, Some(1));
    assert_eq!(overview.tags[0].as_str(), "Work/Clients");
    assert_eq!(overview.created, 1_704_067_200);
    assert_eq!(value(&login.item, "username"), "alice");
    assert_eq!(value(&login.item, "password"), "pa55word");
    assert!(overview.flags.has_totp);
    assert_eq!(value(&login.item, "pin"), "4321");
    assert!(field(&login.item, "pin").unwrap().is_concealed());
    assert_eq!(value(&login.item, "tier"), "gold");
    assert!(field(&login.item, "linked").is_none());
    let details = login.item.details();
    let modes: Vec<(&str, MatchMode)> = details.urls.iter().map(|u| (u.url(), u.mode())).collect();
    assert_eq!(
        modes,
        [
            ("https://example.com/login", MatchMode::Domain),
            ("https://host.example.com", MatchMode::Host),
            ("https://exact.example.com/x", MatchMode::Host),
            ("https://never.example.com", MatchMode::Never),
        ]
    );
    assert_eq!(details.apps.len(), 1);
    assert_eq!(details.apps[0].id, "com.example.app");
    assert_eq!(details.password_history.len(), 1);
    assert_eq!(details.password_history[0].replaced_at, 1_704_164_645);
    assert_eq!(details.passkeys.len(), 1);
    assert_eq!(details.passkeys[0].credential_id.len(), 16);
    assert_eq!(details.passkeys[0].user_handle, [5, 6, 7]);
    let entries = lost(&batch, "Example Login");
    assert!(entries.iter().any(|(s, _)| *s == Subject::RepromptSetting));
    assert!(
        entries
            .iter()
            .any(|(s, f)| *s == Subject::Field("linked".to_owned()) && f.is_loss())
    );
}

#[test]
fn bitwarden_cards_identities_ssh_and_trash() {
    let batch = bitwarden_batch();
    let card = find(&batch, "My Card");
    assert_eq!(value(&card.item, "type"), "Visa");
    assert_eq!(value(&card.item, "expiry date"), "2030-12");
    assert_eq!(value(&card.item, "number"), "4111111111111111");
    assert_eq!(card.item.overview().tags[0].as_str(), "Finance");
    let identity = find(&batch, "Me");
    assert_eq!(value(&identity.item, "first name"), "Alice");
    assert_eq!(
        value(&identity.item, "address"),
        "1 Main St|Springfield|IL|12345|US"
    );
    assert_eq!(
        value(&identity.item, "social security number"),
        "000-00-0000"
    );
    let ssh = find(&batch, "SSH");
    assert_eq!(
        field(&ssh.item, "private key").unwrap().purpose(),
        Some(Purpose::SshPrivateKey)
    );
    let trashed = find(&batch, "Trashed");
    assert_eq!(
        trashed.item.overview().state,
        ItemState::Trashed { at: 1_717_286_400 }
    );
}

#[test]
fn bitwarden_organization_items_land_in_a_shared_vault_with_collection_tags() {
    let batch = bitwarden::parse(&fixture("bitwarden-organization.json"), &templates()).unwrap();
    assert_eq!(batch.vaults.len(), 2);
    assert!(batch.vaults[0].items.is_empty());
    assert_eq!(batch.vaults[1].kind, VaultKind::Shared);
    let router = find(&batch, "Shared Router");
    assert_eq!(router.item.overview().tags[0].as_str(), "collection/Infra");
    assert!(
        batch
            .report
            .notes
            .iter()
            .any(|n| matches!(n, Note::OrganizationVault { .. }))
    );
}

#[test]
fn bitwarden_rejects_encrypted_and_malformed_exports() {
    let templates = templates();
    assert!(matches!(
        bitwarden::parse(&fixture("bitwarden-encrypted.json"), &templates),
        Err(ImportError::Encrypted)
    ));
    assert!(matches!(
        bitwarden::parse(b"{\"items\": [", &templates),
        Err(ImportError::Json { .. })
    ));
    assert!(matches!(
        bitwarden::parse(b"[]", &templates),
        Err(ImportError::Format(_))
    ));
    assert!(matches!(
        bitwarden::parse(b"{\"items\": [{\"type\": \"x\"}]}", &templates),
        Err(ImportError::Json { .. })
    ));
    let unknown = bitwarden::parse(
        br#"{"items":[{"id":"z","type":9,"name":"weird"}]}"#,
        &templates,
    )
    .unwrap();
    assert_eq!(find(&unknown, "weird").item.overview().kind, "custom");
}
