use hasp_proto::base64url;
use secrecy::ExposeSecret;
use serde_json::{Value, json};

use crate::model::field::{Field, FieldValue, Purpose, Section};
use crate::model::item::Item;
use crate::otp::{OtpAlg, OtpKind};

const EXPORTER: &str = "hasp.test";

fn editable(kind: &str, value: &str, label: &str) -> Value {
    json!({ "fieldType": kind, "value": value, "label": label })
}

fn text_of(field: &Field) -> String {
    match field.value() {
        FieldValue::Text(t)
        | FieldValue::Email(t)
        | FieldValue::Menu(t)
        | FieldValue::Phone(t)
        | FieldValue::Url(t) => t.clone(),
        FieldValue::Concealed(s) => s.expose_secret().to_owned(),
        FieldValue::MonthYear(m) => format!("{:04}-{:02}", m.year(), m.month()),
        _ => String::new(),
    }
}

fn by_purpose(item: &Item, purpose: Purpose) -> Option<&Field> {
    item.details()
        .sections
        .iter()
        .flat_map(Section::fields)
        .find(|f| f.purpose() == Some(purpose))
}

fn totp_of(item: &Item) -> Option<Value> {
    let params = item
        .details()
        .sections
        .iter()
        .flat_map(Section::fields)
        .find_map(|f| match f.value() {
            FieldValue::Otp(params) => Some(params),
            _ => None,
        })?;
    let OtpKind::Totp { period_s } = params.kind() else {
        return None;
    };
    let secret = crate::otp::uri::encode(params);
    let secret = url::Url::parse(&secret)
        .ok()?
        .query_pairs()
        .find(|(key, _)| key == "secret")
        .map(|(_, value)| value.into_owned())?;
    let algorithm = match params.algorithm() {
        OtpAlg::Sha1 => "sha1",
        OtpAlg::Sha256 => "sha256",
        OtpAlg::Sha512 => "sha512",
    };
    let mut out = json!({
        "type": "totp",
        "secret": secret,
        "period": period_s,
        "digits": params.digits(),
        "algorithm": algorithm,
    });
    if let Some(issuer) = params.issuer() {
        out["issuer"] = json!(issuer);
    }
    if let Some(account) = params.account() {
        out["username"] = json!(account);
    }
    Some(out)
}

fn credentials_of(item: &Item) -> Vec<Value> {
    let mut out = Vec::new();
    let user = by_purpose(item, Purpose::Username);
    let password = by_purpose(item, Purpose::Password);
    if user.is_some() || password.is_some() {
        let mut login = json!({ "type": "basic-auth" });
        if let Some(user) = user {
            login["username"] = editable("string", &text_of(user), "username");
        }
        if let Some(password) = password {
            login["password"] = editable("concealed-string", &text_of(password), "password");
        }
        out.push(login);
    }
    out.extend(totp_of(item));
    for passkey in &item.details().passkeys {
        out.push(json!({
            "type": "passkey",
            "credentialId": base64url::encode(&passkey.credential_id),
            "rpId": passkey.rp_id,
            "username": passkey.user_name,
            "userDisplayName": passkey.display_name,
            "userHandle": base64url::encode(&passkey.user_handle),
            "key": base64url::encode(passkey.private_key.expose_secret()),
        }));
    }
    if item.overview().kind == "credit-card" {
        let mut card = json!({ "type": "credit-card" });
        for (member, purpose, kind) in [
            ("number", Purpose::CardNumber, "concealed-string"),
            ("fullName", Purpose::CardHolder, "string"),
            ("cardType", Purpose::CardType, "string"),
            ("verificationNumber", Purpose::CardCvc, "concealed-string"),
            ("expiryDate", Purpose::CardExpiry, "year-month"),
        ] {
            if let Some(field) = by_purpose(item, purpose) {
                card[member] = editable(kind, &text_of(field), member);
            }
        }
        out.push(card);
    }
    if let Some(notes) = &item.details().notes {
        out.push(json!({ "type": "note", "content": editable("string", notes, "notes") }));
    }
    out
}

/// A CXF 1.0 document holding `items` in one account, limited to what the round-trip tests
/// need: logins, TOTP, passkeys, cards and notes. It is a test helper, not a v1 export.
pub fn export_cxf(items: &[(String, &Item)]) -> String {
    let entries: Vec<Value> = items
        .iter()
        .map(|(id, item)| {
            let overview = item.overview();
            let mut entry = json!({
                "id": id,
                "creationAt": overview.created,
                "modifiedAt": overview.client_modified,
                "title": overview.title,
                "favorite": overview.favourite.is_some(),
                "credentials": credentials_of(item),
                "tags": overview.tags.iter().map(crate::model::tag::Tag::as_str).collect::<Vec<_>>(),
            });
            let urls: Vec<&str> = item.details().urls.iter().map(crate::model::url::UrlEntry::url).collect();
            if !urls.is_empty() {
                entry["scope"] = json!({ "urls": urls, "androidApps": [] });
            }
            entry
        })
        .collect();
    json!({
        "version": { "major": 1, "minor": 0 },
        "exporterRpId": EXPORTER,
        "exporterDisplayName": "Hasp tests",
        "timestamp": 1_705_228_800,
        "accounts": [{
            "id": "dGVzdC1hY2NvdW50",
            "username": "tester",
            "email": "tester@example.com",
            "collections": [],
            "items": entries,
        }],
    })
    .to_string()
}
