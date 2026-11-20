use std::collections::BTreeMap;

use hasp_proto::VaultKind;
use secrecy::SecretSlice;
use serde::{Deserialize, Deserializer};

use crate::import::build::{Draft, decode_base64};
use crate::import::report::{MigrationReport, Note, Reason, Subject};
use crate::import::time::parse_rfc3339;
use crate::import::{ImportBatch, ImportError, ImportItem, ImportVault, Source};
use crate::model::field::{FieldValue, MonthYear, Purpose};
use crate::model::item::{ItemState, Passkey};
use crate::model::template::Templates;
use crate::model::url::MatchMode;

const MAX_BYTES: usize = 256 << 20;
const PRIVATE_VAULT: &str = "Bitwarden";

fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Option::<T>::deserialize(deserializer).map(Option::unwrap_or_default)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Export {
    #[serde(default, deserialize_with = "null_default")]
    encrypted: bool,
    #[serde(default, deserialize_with = "null_default")]
    folders: Vec<Named>,
    #[serde(default, deserialize_with = "null_default")]
    collections: Vec<Named>,
    #[serde(default, deserialize_with = "null_default")]
    items: Vec<Entry>,
}

#[derive(Deserialize)]
struct Named {
    id: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    id: Option<String>,
    organization_id: Option<String>,
    folder_id: Option<String>,
    #[serde(rename = "type")]
    kind: Option<u8>,
    #[serde(default, deserialize_with = "null_default")]
    reprompt: u8,
    name: Option<String>,
    notes: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    favorite: bool,
    #[serde(default, deserialize_with = "null_default")]
    fields: Vec<CustomField>,
    login: Option<Login>,
    card: Option<Card>,
    identity: Option<Identity>,
    ssh_key: Option<SshKey>,
    #[serde(default, deserialize_with = "null_default")]
    password_history: Vec<HistoryEntry>,
    #[serde(default, deserialize_with = "null_default")]
    collection_ids: Vec<String>,
    revision_date: Option<String>,
    creation_date: Option<String>,
    deleted_date: Option<String>,
}

#[derive(Deserialize)]
struct CustomField {
    name: Option<String>,
    value: Option<String>,
    #[serde(rename = "type", default, deserialize_with = "null_default")]
    kind: u8,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Login {
    #[serde(default, deserialize_with = "null_default")]
    uris: Vec<Uri>,
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    fido2_credentials: Vec<Fido2>,
}

#[derive(Deserialize)]
struct Uri {
    #[serde(rename = "match")]
    matching: Option<u8>,
    uri: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fido2 {
    credential_id: Option<String>,
    key_algorithm: Option<String>,
    key_curve: Option<String>,
    key_value: Option<String>,
    rp_id: Option<String>,
    user_handle: Option<String>,
    user_name: Option<String>,
    user_display_name: Option<String>,
    creation_date: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Card {
    cardholder_name: Option<String>,
    brand: Option<String>,
    number: Option<String>,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Identity {
    title: Option<String>,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    address1: Option<String>,
    address2: Option<String>,
    address3: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    company: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    ssn: Option<String>,
    username: Option<String>,
    passport_number: Option<String>,
    license_number: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshKey {
    private_key: Option<String>,
    public_key: Option<String>,
    key_fingerprint: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HistoryEntry {
    last_used_date: Option<String>,
    password: Option<String>,
}

pub fn parse(bytes: &[u8], templates: &Templates) -> Result<ImportBatch, ImportError> {
    if bytes.len() > MAX_BYTES {
        return Err(ImportError::Limit("file size"));
    }
    if !bytes.trim_ascii_start().starts_with(b"{") {
        return Err(ImportError::Format("not a json object"));
    }
    let export: Export = serde_json::from_slice(bytes).map_err(|e| ImportError::Json {
        line: e.line(),
        column: e.column(),
    })?;
    if export.encrypted {
        return Err(ImportError::Encrypted);
    }
    let folders = names(&export.folders);
    let collections = names(&export.collections);
    let mut report = MigrationReport::new(Source::Bitwarden);
    let mut private = ImportVault {
        source_id: String::new(),
        name: PRIVATE_VAULT.to_owned(),
        kind: VaultKind::Private,
        items: Vec::new(),
    };
    let mut organizations: BTreeMap<String, ImportVault> = BTreeMap::new();
    for entry in &export.items {
        let (item, item_report) = read_entry(entry, templates, &folders, &collections);
        report.items.push(item_report);
        let Some(item) = item else { continue };
        match entry.organization_id.as_deref() {
            None | Some("") => private.items.push(item),
            Some(organization) => organizations
                .entry(organization.to_owned())
                .or_insert_with(|| organization_vault(organization, &mut report))
                .items
                .push(item),
        }
    }
    report.note(Note::AttachmentsNotInExport);
    let mut vaults = vec![private];
    vaults.extend(organizations.into_values());
    Ok(ImportBatch {
        source: Source::Bitwarden,
        vaults,
        report,
    })
}

fn organization_vault(id: &str, report: &mut MigrationReport) -> ImportVault {
    let short: String = id.chars().take(8).collect();
    let name = format!("Bitwarden organization {short}");
    report.note(Note::OrganizationVault {
        vault: name.clone(),
    });
    ImportVault {
        source_id: id.to_owned(),
        name,
        kind: VaultKind::Shared,
        items: Vec::new(),
    }
}

fn names(named: &[Named]) -> BTreeMap<String, String> {
    named
        .iter()
        .filter_map(|n| Some((n.id.clone()?, n.name.clone()?)))
        .collect()
}

fn read_entry(
    entry: &Entry,
    templates: &Templates,
    folders: &BTreeMap<String, String>,
    collections: &BTreeMap<String, String>,
) -> (Option<ImportItem>, crate::import::report::ItemReport) {
    let code = entry.kind.map_or_else(String::new, |k| k.to_string());
    let template = templates.by_import_code("bitwarden", &code).id.as_str();
    let mut draft = Draft::new(
        entry.id.as_deref().unwrap_or_default(),
        template,
        entry.name.as_deref().unwrap_or_default(),
    );
    if template == "custom" {
        draft.approximated(Subject::Category(code), Reason::NoEquivalent);
    }
    draft.created = entry
        .creation_date
        .as_deref()
        .and_then(parse_rfc3339)
        .unwrap_or(0);
    draft.modified = entry
        .revision_date
        .as_deref()
        .and_then(parse_rfc3339)
        .unwrap_or(draft.created);
    draft.favourite = entry.favorite.then_some(1);
    if let Some(deleted) = entry.deleted_date.as_deref() {
        draft.state = ItemState::Trashed {
            at: parse_rfc3339(deleted).unwrap_or(draft.modified),
        };
    }
    draft.notes = entry.notes.clone().filter(|n| !n.is_empty());
    if let Some(folder) = entry.folder_id.as_ref().and_then(|id| folders.get(id)) {
        draft.tag(folder);
    }
    for id in &entry.collection_ids {
        if let Some(name) = collections.get(id) {
            draft.tag(&format!("collection/{name}"));
        }
    }
    if entry.reprompt != 0 {
        draft.approximated(Subject::RepromptSetting, Reason::NoEquivalent);
    }
    match entry.kind {
        Some(1) => read_login(&mut draft, entry),
        Some(3) => read_card(&mut draft, entry),
        Some(4) => read_identity(&mut draft, entry),
        Some(5) => read_ssh(&mut draft, entry),
        _ => {}
    }
    read_custom_fields(&mut draft, &entry.fields);
    let history = entry
        .password_history
        .iter()
        .filter_map(|h| {
            let password = h.password.as_deref().filter(|p| !p.is_empty())?;
            let at = h
                .last_used_date
                .as_deref()
                .and_then(parse_rfc3339)
                .unwrap_or(0);
            Some((password.to_owned(), at))
        })
        .collect::<Vec<_>>();
    if !history.is_empty() {
        draft.history(history);
    }
    draft.finish()
}

fn read_login(draft: &mut Draft, entry: &Entry) {
    let Some(login) = &entry.login else { return };
    let username = draft.text(
        "username",
        login.username.as_deref().unwrap_or(""),
        Some(Purpose::Username),
    );
    let password = draft.secret(
        "password",
        login.password.as_deref().unwrap_or(""),
        Some(Purpose::Password),
    );
    let totp = login
        .totp
        .as_deref()
        .filter(|t| !t.trim().is_empty())
        .and_then(|t| draft.otp("one-time password", t, Some(Purpose::Totp)));
    draft.section("", vec![username, password, totp]);
    draft.subtitle = login.username.clone().unwrap_or_default();
    for uri in &login.uris {
        let Some(text) = uri.uri.as_deref() else {
            continue;
        };
        let mode = match uri.matching {
            None | Some(0) => MatchMode::Domain,
            Some(1) => MatchMode::Host,
            Some(5) => MatchMode::Never,
            Some(_) => {
                draft.approximated(Subject::Url(text.to_owned()), Reason::NoEquivalent);
                MatchMode::Host
            }
        };
        draft.url(text, mode);
    }
    for credential in &login.fido2_credentials {
        read_passkey(draft, credential);
    }
}

fn read_passkey(draft: &mut Draft, credential: &Fido2) {
    let rp = credential.rp_id.clone().unwrap_or_default();
    let p256 = credential
        .key_algorithm
        .as_deref()
        .is_none_or(|a| a.eq_ignore_ascii_case("ECDSA"))
        && credential.key_curve.as_deref().is_none_or(|c| c == "P-256");
    let key = credential.key_value.as_deref().and_then(decode_base64);
    let id = credential
        .credential_id
        .as_deref()
        .and_then(credential_bytes);
    match (key, id) {
        (Some(key), Some(id)) if p256 && !key.is_empty() => draft.passkeys.push(Passkey {
            credential_id: id,
            rp_id: rp,
            user_handle: credential
                .user_handle
                .as_deref()
                .and_then(decode_base64)
                .unwrap_or_default(),
            user_name: credential.user_name.clone().unwrap_or_default(),
            display_name: credential.user_display_name.clone().unwrap_or_default(),
            algorithm: -7,
            private_key: SecretSlice::from(key),
            created: credential
                .creation_date
                .as_deref()
                .and_then(parse_rfc3339)
                .unwrap_or(0),
            last_used: None,
            backup_eligible: true,
            backed_up: false,
        }),
        _ => draft.lost(Subject::Passkey(rp), Reason::NoEquivalent),
    }
}

fn credential_bytes(text: &str) -> Option<Vec<u8>> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    let is_uuid = text.len() == 36 && hex.len() == 32 && hex.chars().all(|c| c.is_ascii_hexdigit());
    if is_uuid {
        return (0..32)
            .step_by(2)
            .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
            .collect();
    }
    decode_base64(text).filter(|b| !b.is_empty())
}

fn read_card(draft: &mut Draft, entry: &Entry) {
    let Some(card) = &entry.card else { return };
    let get = |v: &Option<String>| v.clone().unwrap_or_default();
    let holder = draft.text(
        "cardholder name",
        &get(&card.cardholder_name),
        Some(Purpose::CardHolder),
    );
    let brand = non_empty(card.brand.as_ref()).and_then(|b| {
        draft.field(
            "type",
            FieldValue::Menu(b.to_owned()),
            Some(Purpose::CardType),
            false,
        )
    });
    let number = non_empty(card.number.as_ref()).and_then(|n| {
        draft.field(
            "number",
            FieldValue::Text(n.to_owned()),
            Some(Purpose::CardNumber),
            true,
        )
    });
    let code = draft.secret(
        "verification number",
        &get(&card.code),
        Some(Purpose::CardCvc),
    );
    let month: Option<u8> = card
        .exp_month
        .as_deref()
        .and_then(|m| m.trim().parse().ok());
    let year: Option<u16> = card.exp_year.as_deref().and_then(|y| y.trim().parse().ok());
    let expiry = match (month, year) {
        (Some(month), Some(year)) => MonthYear::new(year, month).ok().and_then(|value| {
            draft.field(
                "expiry date",
                FieldValue::MonthYear(value),
                Some(Purpose::CardExpiry),
                false,
            )
        }),
        _ => None,
    };
    let loose = (expiry.is_none())
        .then(|| {
            let text = format!(
                "{}/{}",
                card.exp_month.as_deref().unwrap_or(""),
                card.exp_year.as_deref().unwrap_or("")
            );
            (text != "/").then(|| draft.text("expiry date", &text, None))
        })
        .flatten()
        .flatten();
    draft.section("", vec![holder, brand, number, code, expiry, loose]);
}

fn read_identity(draft: &mut Draft, entry: &Entry) {
    let Some(i) = &entry.identity else { return };
    let get = |v: &Option<String>| v.clone().unwrap_or_default();
    let name = [get(&i.first_name), get(&i.middle_name), get(&i.last_name)]
        .iter()
        .filter(|p| !p.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    let identification = vec![
        draft.text("title", &get(&i.title), None),
        draft.text("first name", &get(&i.first_name), Some(Purpose::GivenName)),
        draft.text("middle name", &get(&i.middle_name), None),
        draft.text("last name", &get(&i.last_name), Some(Purpose::FamilyName)),
        draft.text("company", &get(&i.company), Some(Purpose::Organization)),
    ];
    draft.section("Identification", identification);
    let street = [get(&i.address1), get(&i.address2), get(&i.address3)]
        .iter()
        .filter(|p| !p.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    let address = crate::model::field::Address {
        street,
        city: get(&i.city),
        region: get(&i.state),
        postal_code: get(&i.postal_code),
        country: get(&i.country),
    };
    let address_field = (address != crate::model::field::Address::default())
        .then(|| {
            draft.field(
                "address",
                FieldValue::Address(address),
                Some(Purpose::StreetAddress),
                false,
            )
        })
        .flatten();
    let phone = non_empty(i.phone.as_ref()).and_then(|p| {
        draft.field(
            "phone",
            FieldValue::Phone(p.to_owned()),
            Some(Purpose::Phone),
            false,
        )
    });
    draft.section("Address", vec![address_field, phone]);
    let email = non_empty(i.email.as_ref()).and_then(|e| {
        draft.field(
            "email",
            FieldValue::Email(e.to_owned()),
            Some(Purpose::Email),
            false,
        )
    });
    let username = draft.text("username", &get(&i.username), Some(Purpose::Username));
    let ssn = draft.secret("social security number", &get(&i.ssn), None);
    let passport = draft.secret("passport number", &get(&i.passport_number), None);
    let license = draft.secret("license number", &get(&i.license_number), None);
    draft.section("Internet", vec![email, username, ssn, passport, license]);
    draft.subtitle = name;
}

fn read_ssh(draft: &mut Draft, entry: &Entry) {
    let Some(ssh) = &entry.ssh_key else { return };
    let private = draft.secret(
        "private key",
        ssh.private_key.as_deref().unwrap_or(""),
        Some(Purpose::SshPrivateKey),
    );
    let public = draft.text(
        "public key",
        ssh.public_key.as_deref().unwrap_or(""),
        Some(Purpose::SshPublicKey),
    );
    let fingerprint = draft.text(
        "fingerprint",
        ssh.key_fingerprint.as_deref().unwrap_or(""),
        None,
    );
    draft.section("", vec![private, public, fingerprint]);
}

fn read_custom_fields(draft: &mut Draft, fields: &[CustomField]) {
    let mut built = Vec::new();
    for field in fields {
        let label = field.name.as_deref().unwrap_or("field");
        let value = field.value.as_deref().unwrap_or("");
        match field.kind {
            0 | 2 => built.push(draft.text(label, value, None)),
            1 => built.push(draft.secret(label, value, None)),
            _ => draft.lost(Subject::Field(label.to_owned()), Reason::NoEquivalent),
        }
    }
    draft.section("Custom fields", built);
}

fn non_empty(value: Option<&String>) -> Option<&str> {
    value
        .map(String::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}
