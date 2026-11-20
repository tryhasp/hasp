use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use hasp_crypto::Es256Key;
use hasp_proto::VaultKind;
use secrecy::SecretSlice;
use serde_json::Value;

use crate::import::build::{Draft, decode_base64};
use crate::import::report::{
    Entry, Fate, ItemReport, MigrationReport, Note, Outcome, Reason, Subject,
};
use crate::import::{ImportBatch, ImportError, ImportItem, ImportVault, Source};
use crate::matcher::psl::PublicSuffixList;
use crate::model::field::{FieldValue, MonthYear, Purpose};
use crate::model::item::{AppAssociation, AppPlatform, AssocSource, Passkey};
use crate::model::template::Templates;
use crate::model::url::MatchMode;
use crate::webauthn::check_relying_party;

const MAX_BYTES: usize = 32 << 20;
const MAX_ACCOUNTS: usize = 64;
const MAX_ITEMS: usize = 50_000;
const MAX_COLLECTIONS: usize = 10_000;
const MAX_CREDENTIALS: usize = 64;
const MAX_CREDENTIAL_ID: usize = 1023;
const MAX_USER_HANDLE: usize = 64;
const VAULT_NAME: &str = "Credential Exchange";
const SUPPORTED_MAJOR: u64 = 1;

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn list<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn seconds(value: &Value, key: &str) -> u64 {
    value.get(key).map_or(0, |v| {
        v.as_u64()
            .or_else(|| {
                v.as_f64()
                    .filter(|f| f.is_finite() && *f >= 0.0)
                    .and_then(|f| format!("{f:.0}").parse().ok())
            })
            .unwrap_or(0)
    })
}

fn bytes(value: &Value, key: &str) -> Option<Vec<u8>> {
    text(value, key)
        .and_then(decode_base64)
        .filter(|b| !b.is_empty())
}

/// The value of a CXF `EditableField` member (`credential.member`) and its field type.
fn editable<'a>(credential: &'a Value, member: &str) -> Option<(&'a str, &'a str)> {
    let field = credential.get(member)?;
    let value = text(field, "value")?;
    (!value.is_empty()).then(|| (value, text(field, "fieldType").unwrap_or("string")))
}

fn plain<'a>(credential: &'a Value, member: &str) -> Option<&'a str> {
    editable(credential, member).map(|(value, _)| value)
}

pub fn parse(bytes: &[u8], _templates: &Templates) -> Result<ImportBatch, ImportError> {
    if bytes.len() > MAX_BYTES {
        return Err(ImportError::Limit("file size"));
    }
    if !bytes.trim_ascii_start().starts_with(b"{") {
        return Err(ImportError::Format("not a json object"));
    }
    let header: Value = serde_json::from_slice(bytes).map_err(|e| ImportError::Json {
        line: e.line(),
        column: e.column(),
    })?;
    if let Some(major) = header
        .get("version")
        .and_then(|v| v.get("major"))
        .and_then(Value::as_u64)
        && major != SUPPORTED_MAJOR
    {
        return Err(ImportError::Unsupported("credential exchange version"));
    }
    if header.get("accounts").and_then(Value::as_array).is_none() {
        return Err(ImportError::Format("no accounts"));
    }
    let accounts = list(&header, "accounts");
    if accounts.len() > MAX_ACCOUNTS {
        return Err(ImportError::Limit("accounts"));
    }
    let mut report = MigrationReport::new(Source::Cxf);
    let mut vault = ImportVault {
        source_id: String::new(),
        name: VAULT_NAME.to_owned(),
        kind: VaultKind::Private,
        items: Vec::new(),
    };
    let mut items = 0_usize;
    let mut collections = 0_usize;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for account in accounts {
        let account_id = text(account, "id").unwrap_or_default();
        let account_items = list(account, "items");
        items = items.saturating_add(account_items.len());
        if items > MAX_ITEMS {
            return Err(ImportError::Limit("items"));
        }
        let membership = collection_index(account, &mut collections)?;
        for (position, item) in account_items.iter().enumerate() {
            if list(item, "credentials").len() > MAX_CREDENTIALS {
                return Err(ImportError::Limit("credentials per item"));
            }
            let item_id = text(item, "id")
                .filter(|id| !id.is_empty())
                .map_or_else(|| format!("@{position}"), str::to_owned);
            let source_id = format!("{account_id}/{item_id}");
            if !seen.insert(source_id.clone()) {
                report.items.push(duplicate_id(source_id, item));
                continue;
            }
            let paths = membership
                .get(item_id.as_str())
                .map_or(&[][..], Vec::as_slice);
            let (imported, item_report) = read_item(item, &source_id, account_id, paths);
            report.items.push(item_report);
            vault.items.extend(imported);
        }
    }
    report.note(Note::HistoryStartsAtImport);
    Ok(ImportBatch {
        source: Source::Cxf,
        vaults: vec![vault],
        report,
    })
}

type Membership<'a> = BTreeMap<&'a str, Vec<(Option<&'a str>, String)>>;

fn collection_index<'a>(
    account: &'a Value,
    count: &mut usize,
) -> Result<Membership<'a>, ImportError> {
    fn walk<'a>(
        collection: &'a Value,
        path: &str,
        count: &mut usize,
        out: &mut Membership<'a>,
    ) -> Result<(), ImportError> {
        *count += 1;
        if *count > MAX_COLLECTIONS {
            return Err(ImportError::Limit("collections"));
        }
        let title = text(collection, "title").unwrap_or_default();
        let here = if path.is_empty() {
            title.to_owned()
        } else {
            format!("{path}/{title}")
        };
        for link in list(collection, "items") {
            if let Some(item) = text(link, "item") {
                out.entry(item)
                    .or_default()
                    .push((text(link, "account"), here.clone()));
            }
        }
        for sub in list(collection, "subCollections") {
            walk(sub, &here, count, out)?;
        }
        Ok(())
    }
    let mut out = Membership::new();
    for collection in list(account, "collections") {
        walk(collection, "", count, &mut out)?;
    }
    Ok(out)
}

fn duplicate_id(source_id: String, item: &Value) -> ItemReport {
    ItemReport {
        source_id,
        title: text(item, "title").unwrap_or_default().to_owned(),
        template: None,
        outcome: Outcome::Skipped,
        entries: vec![Entry {
            subject: Subject::Item,
            fate: Fate::Lost {
                reason: Reason::Rejected("duplicate source id".to_owned()),
            },
        }],
    }
}

fn relying_parties() -> &'static PublicSuffixList {
    static LIST: OnceLock<PublicSuffixList> = OnceLock::new();
    LIST.get_or_init(PublicSuffixList::bundled)
}

fn template_for(types: &[&str]) -> &'static str {
    let has = |wanted: &[&str]| types.iter().any(|t| wanted.contains(t));
    if has(&["basic-auth", "passkey", "totp", "generated-password"]) {
        "login"
    } else if has(&["credit-card"]) {
        "credit-card"
    } else if types.iter().all(|t| *t == "note") && !types.is_empty() {
        "secure-note"
    } else {
        "custom"
    }
}

fn read_item(
    item: &Value,
    source_id: &str,
    account_id: &str,
    collections: &[(Option<&str>, String)],
) -> (Option<ImportItem>, ItemReport) {
    let credentials = list(item, "credentials");
    let types: Vec<&str> = credentials.iter().filter_map(|c| text(c, "type")).collect();
    let template = template_for(&types);
    let mut draft = Draft::new(source_id, template, text(item, "title").unwrap_or_default());
    draft.created = seconds(item, "creationAt");
    draft.modified = {
        let modified = seconds(item, "modifiedAt");
        if modified == 0 {
            draft.created
        } else {
            modified
        }
    };
    draft.favourite = item
        .get("favorite")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        .then_some(1);
    for tag in list(item, "tags").iter().filter_map(Value::as_str) {
        draft.tag(tag);
    }
    for (_, collection) in collections
        .iter()
        .filter(|(owner, _)| owner.is_none_or(|owner| owner == account_id))
    {
        draft.tag(&format!("collection/{collection}"));
    }
    read_scope(&mut draft, item.get("scope"));
    let mut notes: Vec<String> = Vec::new();
    for credential in credentials {
        read_credential(&mut draft, credential, &mut notes);
    }
    if !notes.is_empty() {
        draft.notes = Some(notes.join("\n\n"));
    }
    if template == "login" && draft.urls.is_empty() {
        let rp = draft.passkeys.first().map(|p| p.rp_id.clone());
        if let Some(rp) = rp.filter(|rp| !rp.is_empty()) {
            draft.url(&format!("https://{rp}"), MatchMode::Domain);
        }
    }
    draft.finish()
}

fn read_scope(draft: &mut Draft, scope: Option<&Value>) {
    let Some(scope) = scope else { return };
    for url in list(scope, "urls").iter().filter_map(Value::as_str) {
        draft.url(url, MatchMode::Domain);
    }
    for app in list(scope, "androidApps") {
        let Some(bundle) = text(app, "bundleId").filter(|b| !b.is_empty()) else {
            continue;
        };
        let cert = app
            .get("certificate")
            .filter(|c| text(c, "hashAlg").is_none_or(|a| a.eq_ignore_ascii_case("sha256")))
            .and_then(|c| bytes(c, "fingerprint"))
            .and_then(|raw| <[u8; 32]>::try_from(raw).ok());
        draft.apps.push(AppAssociation {
            platform: AppPlatform::Android,
            id: bundle.to_owned(),
            cert_sha256: cert,
            source: AssocSource::User,
        });
    }
}

fn read_credential(draft: &mut Draft, credential: &Value, notes: &mut Vec<String>) {
    let kind = text(credential, "type").unwrap_or_default();
    match kind {
        "basic-auth" => read_basic_auth(draft, credential),
        "generated-password" => {
            let value = text(credential, "password").unwrap_or_default();
            let purpose = draft
                .password_field_id()
                .is_none()
                .then_some(Purpose::Password);
            let label = if purpose.is_some() {
                "password"
            } else {
                "generated password"
            };
            let field = draft.secret(label, value, purpose);
            draft.section("", vec![field]);
        }
        "totp" => read_totp(draft, credential),
        "passkey" => read_passkey(draft, credential),
        "note" => {
            if let Some(content) = plain(credential, "content") {
                notes.push(content.to_owned());
            }
        }
        "credit-card" => read_card(draft, credential),
        "custom-fields" => {
            let title = text(credential, "label")
                .unwrap_or("Custom fields")
                .to_owned();
            let fields = list(credential, "fields")
                .iter()
                .map(|f| generic_field(draft, text(f, "label").unwrap_or("field"), f))
                .collect();
            draft.section(&title, fields);
        }
        "file" => draft.lost(
            Subject::Attachment(text(credential, "name").unwrap_or_default().to_owned()),
            Reason::NotExportedBySource,
        ),
        "item-reference" => draft.lost(Subject::Reference(String::new()), Reason::NoEquivalent),
        other => read_unmapped(draft, other, credential),
    }
}

fn generic_field(
    draft: &mut Draft,
    label: &str,
    field: &Value,
) -> Option<crate::model::field::Field> {
    let value = text(field, "value").unwrap_or_default();
    match text(field, "fieldType").unwrap_or("string") {
        "concealed-string" => draft.secret(label, value, None),
        _ => draft.text(label, value, None),
    }
}

fn read_unmapped(draft: &mut Draft, kind: &str, credential: &Value) {
    let Some(members) = credential.as_object() else {
        return;
    };
    let mut fields = Vec::new();
    for (name, member) in members {
        if name == "type" || name == "extensions" {
            continue;
        }
        let label = format!("{kind}/{name}");
        if member.get("fieldType").is_some() {
            fields.push(generic_field(draft, &label, member));
        } else if let Some(value) = member.as_str() {
            fields.push(draft.secret(&label, value, None));
        }
    }
    draft.approximated(Subject::Category(kind.to_owned()), Reason::NoEquivalent);
    draft.section(kind, fields);
}

fn read_basic_auth(draft: &mut Draft, credential: &Value) {
    let user = plain(credential, "username").unwrap_or_default();
    let username = draft.text("username", user, Some(Purpose::Username));
    let password = draft.secret(
        "password",
        plain(credential, "password").unwrap_or_default(),
        Some(Purpose::Password),
    );
    if draft.subtitle.is_empty() {
        user.clone_into(&mut draft.subtitle);
    }
    draft.section("", vec![username, password]);
}

fn read_totp(draft: &mut Draft, credential: &Value) {
    let secret: String = text(credential, "secret")
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let algorithm = text(credential, "algorithm")
        .unwrap_or("sha1")
        .to_ascii_lowercase();
    let algorithm = match algorithm.as_str() {
        "sha1" => "SHA1",
        "sha256" => "SHA256",
        "sha512" => "SHA512",
        _ => {
            draft.lost(
                Subject::Field("one-time password".to_owned()),
                Reason::InvalidValue,
            );
            return;
        }
    };
    let digits = credential
        .get("digits")
        .and_then(Value::as_u64)
        .unwrap_or(6);
    let period = credential
        .get("period")
        .and_then(Value::as_u64)
        .unwrap_or(30);
    let issuer = text(credential, "issuer").unwrap_or_default();
    let account = text(credential, "username").unwrap_or_default();
    let label = match (issuer.is_empty(), account.is_empty()) {
        (false, false) => format!("{issuer}:{account}"),
        (false, true) => issuer.to_owned(),
        (true, false) => account.to_owned(),
        (true, true) => "imported".to_owned(),
    };
    let Ok(mut uri) = url::Url::parse("otpauth://totp/") else {
        return;
    };
    uri.set_path(&label);
    {
        let mut query = uri.query_pairs_mut();
        query
            .append_pair("secret", &secret)
            .append_pair("algorithm", algorithm)
            .append_pair("digits", &digits.to_string())
            .append_pair("period", &period.to_string());
        if !issuer.is_empty() {
            query.append_pair("issuer", issuer);
        }
    }
    let field = draft.otp("one-time password", uri.as_str(), Some(Purpose::Totp));
    draft.section("", vec![field]);
}

fn read_passkey(draft: &mut Draft, credential: &Value) {
    let raw_rp = text(credential, "rpId").unwrap_or_default();
    let key = bytes(credential, "key").and_then(|der| Es256Key::from_pkcs8(&der).ok());
    let id = bytes(credential, "credentialId").filter(|id| id.len() <= MAX_CREDENTIAL_ID);
    let handle = bytes(credential, "userHandle").unwrap_or_default();
    let rp = check_relying_party(relying_parties(), raw_rp);
    let (Some(key), Some(id), Ok(rp)) = (key, id, rp) else {
        draft.lost(Subject::Passkey(raw_rp.to_owned()), Reason::InvalidValue);
        return;
    };
    if handle.len() > MAX_USER_HANDLE {
        draft.lost(Subject::Passkey(rp), Reason::InvalidValue);
        return;
    }
    let Ok(pkcs8) = key.to_pkcs8() else {
        draft.lost(Subject::Passkey(rp), Reason::NoEquivalent);
        return;
    };
    if draft.subtitle.is_empty() {
        text(credential, "username")
            .unwrap_or_default()
            .clone_into(&mut draft.subtitle);
    }
    if credential.get("fido2Extensions").is_some() {
        draft.approximated(Subject::Passkey(rp.clone()), Reason::NoEquivalent);
    }
    draft.passkeys.push(Passkey {
        credential_id: id,
        rp_id: rp,
        user_handle: handle,
        user_name: text(credential, "username").unwrap_or_default().to_owned(),
        display_name: text(credential, "userDisplayName")
            .unwrap_or_default()
            .to_owned(),
        algorithm: -7,
        private_key: SecretSlice::from(pkcs8.expose().to_vec()),
        created: draft.created,
        last_used: None,
        backup_eligible: true,
        backed_up: true,
    });
}

fn read_card(draft: &mut Draft, credential: &Value) {
    let holder = draft.text(
        "cardholder name",
        plain(credential, "fullName").unwrap_or_default(),
        Some(Purpose::CardHolder),
    );
    let brand = plain(credential, "cardType").and_then(|b| {
        draft.field(
            "type",
            FieldValue::Menu(b.to_owned()),
            Some(Purpose::CardType),
            false,
        )
    });
    let number = plain(credential, "number").and_then(|n| {
        draft.field(
            "number",
            FieldValue::Text(n.to_owned()),
            Some(Purpose::CardNumber),
            true,
        )
    });
    let code = draft.secret(
        "verification number",
        plain(credential, "verificationNumber").unwrap_or_default(),
        Some(Purpose::CardCvc),
    );
    let pin = draft.secret("pin", plain(credential, "pin").unwrap_or_default(), None);
    let expiry = plain(credential, "expiryDate").and_then(|raw| {
        let parsed = parse_year_month(raw);
        match parsed {
            Some(value) => draft.field(
                "expiry date",
                FieldValue::MonthYear(value),
                Some(Purpose::CardExpiry),
                false,
            ),
            None => draft.text("expiry date", raw, None),
        }
    });
    let valid_from = draft.text(
        "valid from",
        plain(credential, "validFrom").unwrap_or_default(),
        None,
    );
    draft.section(
        "",
        vec![holder, brand, number, code, pin, expiry, valid_from],
    );
}

fn parse_year_month(text: &str) -> Option<MonthYear> {
    let (year, month) = text.trim().split_once('-')?;
    MonthYear::new(year.parse().ok()?, month.parse().ok()?).ok()
}
