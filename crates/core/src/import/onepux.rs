use std::collections::BTreeMap;
use std::io::{Cursor, Read};

use hasp_proto::VaultKind;
use secrecy::SecretSlice;
use serde_json::Value;
use zip::ZipArchive;

use crate::import::build::{Draft, decode_base64, mime_for, random_id};
use crate::import::report::{MigrationReport, Note, Reason, Subject};
use crate::import::time::{date_from_epoch, month_year_from_number};
use crate::import::{AttachedFile, ImportBatch, ImportError, ImportItem, ImportVault, Source};
use crate::model::field::{Address, FieldValue, Purpose};
use crate::model::item::{ItemState, Passkey};
use crate::model::template::Templates;
use crate::model::url::MatchMode;

const DATA_ENTRY: &str = "export.data";
const FILES_PREFIX: &str = "files/";
const DOCUMENT_SEPARATOR: &str = "___";
const MIN_RATIO_CHECK_BYTES: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_entries: usize,
    pub max_data_bytes: u64,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_ratio: u64,
}

impl Limits {
    pub const STANDARD: Self = Self {
        max_entries: 100_000,
        max_data_bytes: 128 << 20,
        max_file_bytes: 100 << 20,
        max_total_bytes: 1 << 30,
        max_ratio: 1000,
    };
}

struct Container<'a> {
    archive: ZipArchive<Cursor<&'a [u8]>>,
    documents: BTreeMap<String, usize>,
    limits: Limits,
    spent: u64,
}

pub fn parse(bytes: &[u8], templates: &Templates) -> Result<ImportBatch, ImportError> {
    parse_with(bytes, templates, &Limits::STANDARD)
}

pub fn parse_with(
    bytes: &[u8],
    templates: &Templates,
    limits: &Limits,
) -> Result<ImportBatch, ImportError> {
    let mut container = Container::open(bytes, *limits)?;
    let data = container.read_named(DATA_ENTRY, limits.max_data_bytes)?;
    let root: Value = serde_json::from_slice(&data).map_err(|e| ImportError::Json {
        line: e.line(),
        column: e.column(),
    })?;
    drop(data);
    let accounts = array(&root, "accounts").ok_or(ImportError::Format("no accounts"))?;
    let mut report = MigrationReport::new(Source::OnePassword);
    let mut vaults = Vec::new();
    for account in accounts {
        for vault in array(account, "vaults").unwrap_or(&[]) {
            vaults.push(read_vault(vault, templates, &mut container, &mut report));
        }
    }
    report.note(Note::HistoryStartsAtImport);
    report.note(Note::PasskeysNotExportedBySource);
    Ok(ImportBatch {
        source: Source::OnePassword,
        vaults,
        report,
    })
}

impl<'a> Container<'a> {
    fn open(bytes: &'a [u8], limits: Limits) -> Result<Self, ImportError> {
        let archive = ZipArchive::new(Cursor::new(bytes))
            .map_err(|_| ImportError::Format("not a zip container"))?;
        if archive.len() > limits.max_entries {
            return Err(ImportError::Limit("zip entries"));
        }
        let mut documents = BTreeMap::new();
        for index in 0..archive.len() {
            let Some(Ok(name)) = archive.name_for_index(index) else {
                continue;
            };
            if let Some(rest) = name.strip_prefix(FILES_PREFIX)
                && let Some((document, _)) = rest.split_once(DOCUMENT_SEPARATOR)
            {
                documents.insert(document.to_owned(), index);
            }
        }
        Ok(Self {
            archive,
            documents,
            limits,
            spent: 0,
        })
    }

    fn read_named(&mut self, name: &str, max: u64) -> Result<Vec<u8>, ImportError> {
        let index = self
            .archive
            .index_for_name(name)
            .ok_or(ImportError::Format("missing export.data"))?;
        self.read_index(index, max)
    }

    fn read_index(&mut self, index: usize, max: u64) -> Result<Vec<u8>, ImportError> {
        let mut entry = self
            .archive
            .by_index(index)
            .map_err(|_| ImportError::Zip("unreadable entry"))?;
        let declared = entry.size();
        let packed = entry.compressed_size().max(1);
        if declared > max {
            return Err(ImportError::Limit("entry size"));
        }
        if declared > MIN_RATIO_CHECK_BYTES && declared / packed > self.limits.max_ratio {
            return Err(ImportError::Limit("compression ratio"));
        }
        let mut buffer = Vec::new();
        entry
            .by_ref()
            .take(max.saturating_add(1))
            .read_to_end(&mut buffer)
            .map_err(|_| ImportError::Zip("corrupt entry"))?;
        let read = u64::try_from(buffer.len()).map_err(|_| ImportError::Limit("entry size"))?;
        self.spent = self.spent.saturating_add(read);
        if read > max || self.spent > self.limits.max_total_bytes {
            return Err(ImportError::Limit("uncompressed size"));
        }
        Ok(buffer)
    }

    fn document(&mut self, id: &str) -> Result<Option<Vec<u8>>, ImportError> {
        let Some(index) = self.documents.get(id).copied() else {
            return Ok(None);
        };
        let max = self.limits.max_file_bytes;
        self.read_index(index, max).map(Some)
    }
}

fn read_vault(
    vault: &Value,
    templates: &Templates,
    container: &mut Container<'_>,
    report: &mut MigrationReport,
) -> ImportVault {
    let attrs = vault.get("attrs").unwrap_or(&Value::Null);
    let name = text(attrs, "name").unwrap_or("1Password").to_owned();
    let kind = if text(attrs, "type") == Some("P") {
        VaultKind::Private
    } else {
        report.note(Note::SharedVaultMembersMustBeReinvited {
            vault: name.clone(),
        });
        VaultKind::Shared
    };
    let mut items = Vec::new();
    for raw in array(vault, "items").unwrap_or(&[]) {
        let (item, item_report) = read_item(raw, templates, container);
        report.items.push(item_report);
        items.extend(item);
    }
    ImportVault {
        source_id: text(attrs, "uuid").unwrap_or_default().to_owned(),
        name,
        kind,
        items,
    }
}

fn read_item(
    raw: &Value,
    templates: &Templates,
    container: &mut Container<'_>,
) -> (Option<ImportItem>, crate::import::report::ItemReport) {
    let empty = Value::Null;
    let overview = raw.get("overview").unwrap_or(&empty);
    let details = raw.get("details").unwrap_or(&empty);
    let code = text(raw, "categoryUuid").unwrap_or_default();
    let template = templates.by_import_code("1pux", code);
    let mut draft = Draft::new(
        text(raw, "uuid").unwrap_or_default(),
        &template.id,
        text(overview, "title").unwrap_or_default(),
    );
    if template.import_codes.get("1pux").map(String::as_str) != Some(code) {
        draft.approximated(Subject::Category(code.to_owned()), Reason::NoEquivalent);
    }
    text(overview, "subtitle")
        .unwrap_or_default()
        .clone_into(&mut draft.subtitle);
    draft.created = unsigned(raw, "createdAt");
    draft.modified = unsigned(raw, "updatedAt");
    draft.favourite = u32::try_from(integer(raw, "favIndex"))
        .ok()
        .filter(|f| *f > 0);
    draft.state = match (
        text(raw, "state"),
        raw.get("trashed").and_then(Value::as_bool),
    ) {
        (Some("trashed" | "deleted"), _) | (_, Some(true)) => {
            ItemState::Trashed { at: draft.modified }
        }
        (Some("archived"), _) => ItemState::Archived { at: draft.modified },
        _ => ItemState::Active,
    };
    draft.notes = text(details, "notesPlain")
        .filter(|n| !n.is_empty())
        .map(str::to_owned);
    for tag in array(overview, "tags").unwrap_or(&[]) {
        if let Some(tag) = tag.as_str() {
            draft.tag(tag);
        }
    }
    read_urls(&mut draft, overview);
    read_login(&mut draft, details);
    read_sections(&mut draft, &template.id, details, container);
    read_document(&mut draft, details, container);
    read_history(&mut draft, details);
    read_passkeys(&mut draft, details);
    draft.finish()
}

fn read_urls(draft: &mut Draft, overview: &Value) {
    let mut seen_primary = false;
    if let Some(url) = text(overview, "url").filter(|u| !u.is_empty()) {
        draft.url(url, MatchMode::Domain);
        seen_primary = true;
    }
    for entry in array(overview, "urls").unwrap_or(&[]) {
        let Some(url) = text(entry, "url") else {
            continue;
        };
        let mode = match text(entry, "mode").unwrap_or("default") {
            "default" | "domain" => MatchMode::Domain,
            "host" => MatchMode::Host,
            "never" => MatchMode::Never,
            _ => {
                draft.approximated(Subject::Url(url.to_owned()), Reason::NoEquivalent);
                MatchMode::Host
            }
        };
        if seen_primary && draft.urls.iter().any(|u| u.url() == url) {
            if let Some(existing) = draft.urls.iter_mut().find(|u| u.url() == url) {
                existing.set_mode(mode);
            }
            continue;
        }
        draft.url(url, mode);
    }
}

fn read_login(draft: &mut Draft, details: &Value) {
    let mut credentials = Vec::new();
    let mut form = Vec::new();
    for field in array(details, "loginFields").unwrap_or(&[]) {
        let value = text(field, "value").unwrap_or_default();
        let name = text(field, "name")
            .filter(|n| !n.is_empty())
            .or_else(|| text(field, "id"))
            .unwrap_or("field");
        match text(field, "designation") {
            Some("username") => {
                credentials.push(draft.text("username", value, Some(Purpose::Username)));
            }
            Some("password") => {
                credentials.push(draft.secret("password", value, Some(Purpose::Password)));
            }
            _ if text(field, "fieldType").or_else(|| text(field, "type")) == Some("P") => {
                form.push(draft.secret(name, value, None));
            }
            _ => form.push(draft.text(name, value, None)),
        }
    }
    if let Some(password) = text(details, "password") {
        credentials.push(draft.secret("password", password, Some(Purpose::Password)));
    }
    draft.section("", credentials);
    draft.section("Form fields", form);
}

fn read_sections(
    draft: &mut Draft,
    template: &str,
    details: &Value,
    container: &mut Container<'_>,
) {
    for section in array(details, "sections").unwrap_or(&[]) {
        let title = text(section, "title").unwrap_or_default();
        let mut fields = Vec::new();
        for field in array(section, "fields").unwrap_or(&[]) {
            let id = text(field, "id").unwrap_or_default();
            let label = text(field, "title")
                .filter(|t| !t.is_empty())
                .unwrap_or(id)
                .to_owned();
            let guarded = field.get("guarded").and_then(Value::as_bool) == Some(true);
            let purpose = purpose_for(template, id);
            if let Some(value) = field.get("value").and_then(Value::as_object) {
                for (variant, inner) in value {
                    let cell = Cell {
                        label: &label,
                        variant,
                        inner,
                        purpose,
                        guarded,
                    };
                    fields.extend(read_value(draft, container, &cell));
                }
            }
        }
        draft.section(title, fields);
    }
}

struct Cell<'a> {
    label: &'a str,
    variant: &'a str,
    inner: &'a Value,
    purpose: Option<Purpose>,
    guarded: bool,
}

fn read_value(
    draft: &mut Draft,
    container: &mut Container<'_>,
    cell: &Cell<'_>,
) -> Vec<Option<crate::model::field::Field>> {
    let Cell {
        label,
        variant,
        inner,
        purpose,
        guarded,
    } = *cell;
    let string = inner.as_str().unwrap_or_default();
    let field = match variant {
        "string" => draft
            .text(label, string, purpose)
            .map(|f| f.with_concealed(guarded)),
        "concealed" => draft.secret(label, string, purpose),
        "email" => {
            let address = inner
                .get("email_address")
                .and_then(Value::as_str)
                .unwrap_or(string);
            non_empty(address)
                .and_then(|a| draft.field(label, FieldValue::Email(a.to_owned()), purpose, false))
        }
        "phone" => non_empty(string)
            .and_then(|v| draft.field(label, FieldValue::Phone(v.to_owned()), purpose, false)),
        "url" => non_empty(string)
            .and_then(|v| draft.field(label, FieldValue::Url(v.to_owned()), purpose, false)),
        "totp" => non_empty(string).and_then(|v| draft.otp(label, v, Some(Purpose::Totp))),
        "date" => inner.as_i64().and_then(|seconds| {
            if let Some(date) = date_from_epoch(seconds) {
                draft.field(label, FieldValue::Date(date), purpose, false)
            } else {
                draft.lost(Subject::Field(label.to_owned()), Reason::InvalidValue);
                None
            }
        }),
        "monthYear" => inner.as_i64().and_then(|number| {
            if let Some(value) = month_year_from_number(number) {
                draft.field(label, FieldValue::MonthYear(value), purpose, false)
            } else {
                draft.lost(Subject::Field(label.to_owned()), Reason::InvalidValue);
                None
            }
        }),
        "address" => {
            let address = Address {
                street: text(inner, "street").unwrap_or_default().to_owned(),
                city: text(inner, "city").unwrap_or_default().to_owned(),
                region: text(inner, "state").unwrap_or_default().to_owned(),
                postal_code: text(inner, "zip").unwrap_or_default().to_owned(),
                country: text(inner, "country").unwrap_or_default().to_owned(),
            };
            (address != Address::default())
                .then(|| draft.field(label, FieldValue::Address(address), purpose, false))
                .flatten()
        }
        "creditCardType" | "menu" | "gender" => non_empty(string)
            .and_then(|v| draft.field(label, FieldValue::Menu(v.to_owned()), purpose, false)),
        "creditCardNumber" => non_empty(string)
            .and_then(|v| draft.field(label, FieldValue::Text(v.to_owned()), purpose, true)),
        "reference" => {
            draft.lost(Subject::Reference(label.to_owned()), Reason::NoEquivalent);
            None
        }
        "file" => {
            attach(draft, container, inner);
            None
        }
        "sshKey" => return read_ssh_key(draft, inner),
        _ => {
            draft.lost(Subject::Field(label.to_owned()), Reason::NoEquivalent);
            None
        }
    };
    vec![field]
}

fn read_ssh_key(draft: &mut Draft, inner: &Value) -> Vec<Option<crate::model::field::Field>> {
    let metadata = inner.get("metadata").unwrap_or(&Value::Null);
    let private = text(inner, "privateKey")
        .or_else(|| text(metadata, "privateKey"))
        .unwrap_or_default();
    vec![
        draft.secret("private key", private, Some(Purpose::SshPrivateKey)),
        draft.text(
            "public key",
            text(metadata, "publicKey").unwrap_or_default(),
            Some(Purpose::SshPublicKey),
        ),
        draft.text(
            "fingerprint",
            text(metadata, "fingerprint").unwrap_or_default(),
            None,
        ),
        draft.text(
            "key type",
            text(metadata, "keyType").unwrap_or_default(),
            None,
        ),
    ]
}

fn read_document(draft: &mut Draft, details: &Value, container: &mut Container<'_>) {
    if let Some(attributes) = details.get("documentAttributes") {
        attach(draft, container, attributes);
    }
}

fn attach(draft: &mut Draft, container: &mut Container<'_>, descriptor: &Value) {
    let name = text(descriptor, "fileName").unwrap_or("file").to_owned();
    let document = text(descriptor, "documentId").unwrap_or_default();
    match container.document(document) {
        Ok(Some(data)) => match random_id() {
            Ok(id) => draft.files.push(AttachedFile {
                id,
                mime: mime_for(&name),
                name,
                data: SecretSlice::from(data),
            }),
            Err(_) => draft.lost(Subject::Attachment(name), Reason::InvalidValue),
        },
        Ok(None) => draft.lost(Subject::Attachment(name), Reason::NotExportedBySource),
        Err(_) => draft.lost(Subject::Attachment(name), Reason::TooLarge),
    }
}

fn read_history(draft: &mut Draft, details: &Value) {
    let entries: Vec<(String, u64)> = array(details, "passwordHistory")
        .unwrap_or(&[])
        .iter()
        .filter_map(|entry| {
            let value = text(entry, "value")?;
            (!value.is_empty()).then(|| (value.to_owned(), unsigned(entry, "time")))
        })
        .collect();
    if !entries.is_empty() {
        draft.history(entries);
    }
}

fn read_passkeys(draft: &mut Draft, details: &Value) {
    let mut candidates: Vec<&Value> = array(details, "passkeys").unwrap_or(&[]).iter().collect();
    candidates.extend(details.get("passkey"));
    for candidate in candidates {
        let rp = text(candidate, "rpId")
            .or_else(|| text(candidate, "rpID"))
            .unwrap_or_default()
            .to_owned();
        let key = text(candidate, "privateKey").and_then(decode_base64);
        let credential = text(candidate, "credentialId").and_then(decode_base64);
        match (key, credential) {
            (Some(key), Some(credential)) if !key.is_empty() && !credential.is_empty() => {
                draft.passkeys.push(Passkey {
                    credential_id: credential,
                    rp_id: rp,
                    user_handle: text(candidate, "userHandle")
                        .and_then(decode_base64)
                        .unwrap_or_default(),
                    user_name: text(candidate, "userName")
                        .or_else(|| text(candidate, "username"))
                        .unwrap_or_default()
                        .to_owned(),
                    display_name: text(candidate, "displayName")
                        .unwrap_or_default()
                        .to_owned(),
                    algorithm: -7,
                    private_key: SecretSlice::from(key),
                    created: unsigned(candidate, "createdAt"),
                    last_used: None,
                    backup_eligible: true,
                    backed_up: false,
                });
            }
            _ => draft.lost(Subject::Passkey(rp), Reason::NotExportedBySource),
        }
    }
}

fn purpose_for(template: &str, id: &str) -> Option<Purpose> {
    match (template, id) {
        ("credit-card", "cardholder") => Some(Purpose::CardHolder),
        ("credit-card", "type") => Some(Purpose::CardType),
        ("credit-card", "ccnum") => Some(Purpose::CardNumber),
        ("credit-card", "cvv") => Some(Purpose::CardCvc),
        ("credit-card", "expiry") => Some(Purpose::CardExpiry),
        ("identity", "firstname") => Some(Purpose::GivenName),
        ("identity", "lastname") => Some(Purpose::FamilyName),
        ("identity", "email") => Some(Purpose::Email),
        ("identity", "defphone") => Some(Purpose::Phone),
        ("identity", "birthdate") => Some(Purpose::Birthday),
        ("identity", "address") => Some(Purpose::StreetAddress),
        ("identity", "company") => Some(Purpose::Organization),
        ("identity", "username") => Some(Purpose::Username),
        ("api-credential", "credential") => Some(Purpose::ApiKey),
        ("api-credential", "hostname") => Some(Purpose::Hostname),
        ("password", "password") => Some(Purpose::Password),
        _ => None,
    }
}

fn non_empty(text: &str) -> Option<&str> {
    let trimmed = text.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn array<'a>(value: &'a Value, key: &str) -> Option<&'a [Value]> {
    value.get(key).and_then(Value::as_array).map(Vec::as_slice)
}

fn integer(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(0)
}

fn unsigned(value: &Value, key: &str) -> u64 {
    u64::try_from(integer(value, key)).unwrap_or(0)
}
