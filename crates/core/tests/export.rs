#![expect(
    clippy::unwrap_used,
    reason = "helper functions of an integration test crate"
)]

use hasp_core::export::{
    CHUNK_SIZE, ExportContent, ExportError, ExportItem, ExportVault, KeyMode, Protection, Unlock,
    peek, read, write,
};
use hasp_core::import::{AttachedFile, ImportBatch, bitwarden, delimited, onepux};
use hasp_core::model::id::Id;
use hasp_core::model::item::{AttachmentDesc, Item, ItemParts, ItemState};
use hasp_core::testing::{fixture, signature, templates};
use hasp_crypto::{Argon2idParams, SecretKey};
use secrecy::{ExposeSecret, SecretSlice, SecretString};

fn params() -> Argon2idParams {
    Argon2idParams::local(8, 1, 1).unwrap()
}

fn phrase() -> SecretString {
    SecretString::from("tr0ub4dor & three")
}

fn batches() -> Vec<ImportBatch> {
    let templates = templates();
    vec![
        onepux::parse(&fixture("onepux-basic.1pux"), &templates).unwrap(),
        bitwarden::parse(&fixture("bitwarden-individual.json"), &templates).unwrap(),
        delimited::parse(&fixture("csv-chrome.csv"), &templates).unwrap(),
    ]
}

fn content_of(batch: ImportBatch) -> ExportContent {
    let mut content = ExportContent {
        vaults: Vec::new(),
        items: Vec::new(),
    };
    for vault in batch.vaults {
        let vault_id = Id::random().unwrap();
        content.vaults.push(ExportVault {
            id: vault_id,
            name: vault.name,
            kind: vault.kind,
        });
        for item in vault.items {
            content.items.push(ExportItem {
                vault_id,
                item_id: Id::random().unwrap(),
                item: item.item,
                history: Vec::new(),
                files: item.files,
            });
        }
    }
    content
}

fn export(content: &ExportContent) -> Vec<u8> {
    let phrase = phrase();
    let protection = Protection::Passphrase {
        passphrase: &phrase,
        params: params(),
    };
    let mut out = Vec::new();
    write(&mut out, content, &protection, 1_731_000_000).unwrap();
    out
}

fn restore(bytes: &[u8]) -> Result<ExportContent, ExportError> {
    read(bytes, &Unlock::Passphrase(&phrase()))
}

fn assert_same(before: &ExportContent, after: &ExportContent) {
    assert_eq!(before.vaults, after.vaults);
    assert_eq!(before.items.len(), after.items.len());
    for (a, b) in before.items.iter().zip(&after.items) {
        assert_eq!(a.vault_id, b.vault_id);
        assert_eq!(a.item_id, b.item_id);
        assert_eq!(signature(&a.item), signature(&b.item));
        assert_eq!(a.history.len(), b.history.len());
        assert_eq!(a.files.len(), b.files.len());
        for (x, y) in a.files.iter().zip(&b.files) {
            assert_eq!((x.id, &x.name, &x.mime), (y.id, &y.name, &y.mime));
            assert_eq!(x.data.expose_secret(), y.data.expose_secret());
        }
    }
}

#[test]
fn every_importer_output_round_trips_losslessly() {
    for (original, copy) in batches().into_iter().zip(batches()) {
        let before = content_of(original);
        let bytes = export(&before);
        let after = restore(&bytes).unwrap();
        assert_same(&before, &after);
        assert!(!before.items.is_empty());
        drop(copy);
    }
}

#[test]
fn the_file_has_the_magic_a_readable_header_and_no_plaintext() {
    let content = content_of(onepux::parse(&fixture("onepux-basic.1pux"), &templates()).unwrap());
    let bytes = export(&content);
    assert_eq!(&bytes[..4], b"VLTX");
    let info = peek(&bytes).unwrap();
    assert_eq!(info.created, 1_731_000_000);
    assert_eq!(info.key_mode, KeyMode::Passphrase);
    for secret in [
        "correct-horse-battery-staple",
        "Example Bank",
        "4111111111111111",
        "passport.pdf",
        "%PDF",
    ] {
        assert!(
            !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "{secret}"
        );
    }
    assert_ne!(export(&content), bytes);
}

#[test]
fn a_wrong_passphrase_and_a_damaged_file_are_different_errors() {
    let content =
        content_of(bitwarden::parse(&fixture("bitwarden-individual.json"), &templates()).unwrap());
    let bytes = export(&content);
    let wrong = SecretString::from("not the passphrase");
    assert!(matches!(
        read(&bytes, &Unlock::Passphrase(&wrong)),
        Err(ExportError::WrongPassphrase)
    ));
    assert!(matches!(
        read(&bytes, &Unlock::BackupKey(&SecretKey::from_bytes([1; 32]))),
        Err(ExportError::KeyMode)
    ));
    assert!(matches!(
        read(b"VLTX", &Unlock::Passphrase(&phrase())),
        Err(ExportError::Format(_))
    ));
    assert!(matches!(
        read(b"", &Unlock::Passphrase(&phrase())),
        Err(ExportError::Format(_))
    ));
}

fn large_content() -> ExportContent {
    let templates = templates();
    let batch = delimited::parse(&fixture("csv-chrome.csv"), &templates).unwrap();
    let mut content = content_of(batch);
    let data: Vec<u8> = (0..(2 * CHUNK_SIZE + 12_345))
        .map(|i| u8::try_from(i % 253).unwrap())
        .collect();
    content.items[0].files.push(AttachedFile {
        id: Id::random().unwrap(),
        name: "big.bin".into(),
        mime: "application/octet-stream".into(),
        data: SecretSlice::from(data),
    });
    content
}

#[test]
fn a_multi_chunk_file_round_trips_and_every_tampering_is_caught() {
    let content = large_content();
    let bytes = export(&content);
    assert!(bytes.len() > 2 * CHUNK_SIZE);
    assert_same(&content, &restore(&bytes).unwrap());

    let mut flipped = bytes.clone();
    let middle = bytes.len() / 2;
    flipped[middle] ^= 1;
    assert!(matches!(restore(&flipped), Err(ExportError::Corrupt(_))));

    let mut reordered = bytes.clone();
    let header_len = header_len_of(&bytes);
    let chunk = CHUNK_SIZE + 16;
    let start = header_len;
    let (first, second) = (start..start + chunk, start + chunk..start + 2 * chunk);
    let a = reordered[first.clone()].to_vec();
    let b = reordered[second.clone()].to_vec();
    reordered[first].copy_from_slice(&b);
    reordered[second].copy_from_slice(&a);
    assert!(restore(&reordered).is_err());

    assert!(matches!(
        restore(&bytes[..bytes.len() - 1]),
        Err(ExportError::Corrupt(_))
    ));
    assert!(matches!(
        restore(&bytes[..bytes.len() - chunk]),
        Err(ExportError::Corrupt(_))
    ));
    let mut extended = bytes.clone();
    extended.push(0);
    assert!(matches!(restore(&extended), Err(ExportError::Corrupt(_))));
    let mut header_only = bytes.clone();
    header_only.truncate(header_len_of(&bytes));
    assert!(matches!(
        restore(&header_only),
        Err(ExportError::Corrupt("no chunks"))
    ));
}

fn header_len_of(bytes: &[u8]) -> usize {
    (4..bytes.len())
        .find(|end| peek(&bytes[..*end]).is_ok())
        .unwrap()
}

#[test]
fn attachments_of_every_edge_size_survive() {
    let batch = delimited::parse(&fixture("csv-chrome.csv"), &templates()).unwrap();
    let mut content = content_of(batch);
    for size in [0_usize, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1] {
        content.items[0].files.push(AttachedFile {
            id: Id::random().unwrap(),
            name: format!("f{size}"),
            mime: "x/y".into(),
            data: SecretSlice::from(vec![0xa5; size]),
        });
    }
    assert_same(&content, &restore(&export(&content)).unwrap());
}

#[test]
fn backup_mode_opens_with_the_derived_key_or_the_passphrase() {
    let content = content_of(
        bitwarden::parse(&fixture("bitwarden-organization.json"), &templates()).unwrap(),
    );
    let salt = [7_u8; 16];
    let key = SecretKey::from_bytes({
        let derived = hasp_crypto::argon2id(b"backup phrase", &salt, &params()).unwrap();
        *derived.expose()
    });
    let protection = Protection::BackupKey {
        key: &key,
        params: params(),
        salt,
    };
    let mut bytes = Vec::new();
    write(&mut bytes, &content, &protection, 5).unwrap();
    assert_eq!(peek(&bytes).unwrap().key_mode, KeyMode::BackupKey);
    assert_same(&content, &read(&bytes, &Unlock::BackupKey(&key)).unwrap());
    let phrase = SecretString::from("backup phrase");
    assert_same(
        &content,
        &read(&bytes, &Unlock::Passphrase(&phrase)).unwrap(),
    );
    assert!(matches!(
        read(&bytes, &Unlock::BackupKey(&SecretKey::from_bytes([0; 32]))),
        Err(ExportError::WrongPassphrase)
    ));
    let mut second = Vec::new();
    write(&mut second, &content, &protection, 5).unwrap();
    assert_ne!(bytes, second);
}

#[test]
fn history_and_empty_exports_round_trip() {
    let mut content =
        content_of(delimited::parse(&fixture("csv-chrome.csv"), &templates()).unwrap());
    let older = delimited::parse(&fixture("csv-safari.csv"), &templates()).unwrap();
    let old_item = older
        .vaults
        .into_iter()
        .next()
        .unwrap()
        .items
        .into_iter()
        .next()
        .unwrap()
        .item;
    content.items[0].history.push(old_item);
    assert_same(&content, &restore(&export(&content)).unwrap());
    let empty = ExportContent {
        vaults: Vec::new(),
        items: Vec::new(),
    };
    let restored = restore(&export(&empty)).unwrap();
    assert!(restored.vaults.is_empty() && restored.items.is_empty());
}

#[test]
fn items_that_still_carry_attachment_descriptors_are_refused() {
    let item = Item::new(ItemParts {
        kind: "document".into(),
        title: "doc".into(),
        subtitle: String::new(),
        tags: Vec::new(),
        favourite: None,
        state: ItemState::Active,
        sections: Vec::new(),
        notes: None,
        urls: Vec::new(),
        apps: Vec::new(),
        passkeys: Vec::new(),
        attachments: vec![AttachmentDesc {
            att_id: Id::random().unwrap(),
            file_key: SecretKey::random().unwrap(),
            nonce_prefix: [0; 15],
            size: 1,
            chunk_size: 1 << 20,
            name: "a".into(),
            mime: "a/b".into(),
        }],
        password_history: Vec::new(),
        client_modified: 1,
        created: 1,
        expires_at: None,
    })
    .unwrap();
    let content = ExportContent {
        vaults: Vec::new(),
        items: vec![ExportItem {
            vault_id: Id::random().unwrap(),
            item_id: Id::random().unwrap(),
            item,
            history: Vec::new(),
            files: Vec::new(),
        }],
    };
    let phrase = phrase();
    let protection = Protection::Passphrase {
        passphrase: &phrase,
        params: params(),
    };
    let mut out = Vec::new();
    assert!(matches!(
        write(&mut out, &content, &protection, 1),
        Err(ExportError::Format("attachment descriptors"))
    ));
    assert_eq!(format!("{protection:?}"), "Protection(..)");
}

#[test]
fn a_flipped_key_check_value_is_a_wrong_passphrase_and_later_damage_is_corruption() {
    let content =
        content_of(bitwarden::parse(&fixture("bitwarden-individual.json"), &templates()).unwrap());
    let bytes = export(&content);
    let header_len = header_len_of(&bytes);
    let mut kcv = bytes.clone();
    kcv[header_len - 1] ^= 1;
    assert!(matches!(restore(&kcv), Err(ExportError::WrongPassphrase)));
    let mut body = bytes;
    body[header_len + 3] ^= 1;
    assert!(matches!(restore(&body), Err(ExportError::Corrupt(_))));
}
