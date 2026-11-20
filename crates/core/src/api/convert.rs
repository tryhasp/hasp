use hasp_proto::{ItemId, VaultId};
use secrecy::{ExposeSecret, SecretString};

use super::ids;
use super::{
    AttachmentView, FieldDraft, FieldView, ItemDetail, ItemDraft, ItemRow, ItemStatus, Secret,
    SectionDraft, SectionView, UrlDraft, UrlView,
};
use crate::CoreError;
use crate::client::ItemSummary;
use crate::model::field::{
    Address, Date, Field, FieldKind, FieldValue, MonthYear, Purpose, Section,
};
use crate::model::id::Id;
use crate::model::item::{Item, ItemParts, ItemState, Overview, PasswordHistoryEntry};
use crate::model::tag::Tag;
use crate::model::url::{MatchMode, UrlEntry, UrlKind};
use crate::otp::uri as otp_uri;

const HISTORY_CAP: usize = 100;

pub(super) fn status_of(state: ItemState) -> ItemStatus {
    match state {
        ItemState::Active => ItemStatus::Active,
        ItemState::Archived { .. } => ItemStatus::Archived,
        ItemState::Trashed { .. } => ItemStatus::Trashed,
    }
}

pub(super) fn state_of(status: ItemStatus, now: u64) -> ItemState {
    match status {
        ItemStatus::Active => ItemState::Active,
        ItemStatus::Archived => ItemState::Archived { at: now },
        ItemStatus::Trashed => ItemState::Trashed { at: now },
    }
}

pub(super) fn row_of(
    vault: &VaultId,
    item: &ItemId,
    overview: &Overview,
    version: u64,
    pending: bool,
) -> ItemRow {
    ItemRow {
        vault: ids::hex(vault.as_bytes()),
        id: ids::hex(item.as_bytes()),
        kind: overview.kind.clone(),
        title: overview.title.clone(),
        subtitle: overview.subtitle.clone(),
        hosts: overview.urls.iter().map(|u| u.host.clone()).collect(),
        tags: overview
            .tags
            .iter()
            .map(|t| t.as_str().to_owned())
            .collect(),
        favourite: overview.favourite.is_some(),
        status: status_of(overview.state),
        has_totp: overview.flags.has_totp,
        has_passkey: overview.flags.has_passkey,
        has_attachments: overview.flags.has_attachments,
        modified: overview.client_modified,
        created: overview.created,
        expires_at: overview.expires_at,
        pending,
        version,
    }
}

pub(super) fn row_of_summary(summary: &ItemSummary, item: &Item) -> ItemRow {
    row_of(
        &summary.vault_id,
        &summary.item_id,
        item.overview(),
        summary.version,
        summary.pending,
    )
}

pub(super) fn purpose_name(purpose: Purpose) -> &'static str {
    match purpose {
        Purpose::Username => "username",
        Purpose::Password => "password",
        Purpose::Totp => "totp",
        Purpose::NewPassword => "new-password",
        Purpose::CardHolder => "card-holder",
        Purpose::CardNumber => "card-number",
        Purpose::CardExpiry => "card-expiry",
        Purpose::CardExpiryMonth => "card-expiry-month",
        Purpose::CardExpiryYear => "card-expiry-year",
        Purpose::CardCvc => "card-cvc",
        Purpose::CardType => "card-type",
        Purpose::Name => "name",
        Purpose::GivenName => "given-name",
        Purpose::FamilyName => "family-name",
        Purpose::Email => "email",
        Purpose::Phone => "phone",
        Purpose::Birthday => "birthday",
        Purpose::StreetAddress => "street-address",
        Purpose::AddressLine1 => "address-line1",
        Purpose::AddressLine2 => "address-line2",
        Purpose::City => "city",
        Purpose::Region => "region",
        Purpose::PostalCode => "postal-code",
        Purpose::Country => "country",
        Purpose::Organization => "organization",
        Purpose::ApiKey => "api-key",
        Purpose::Hostname => "hostname",
        Purpose::SshPrivateKey => "ssh-private-key",
        Purpose::SshPublicKey => "ssh-public-key",
    }
}

pub(super) fn kind_name(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Text => "text",
        FieldKind::Concealed => "concealed",
        FieldKind::Url => "url",
        FieldKind::Email => "email",
        FieldKind::Phone => "phone",
        FieldKind::Date => "date",
        FieldKind::MonthYear => "month-year",
        FieldKind::Otp => "otp",
        FieldKind::Address => "address",
        FieldKind::Menu => "menu",
        FieldKind::SecurityQuestion => "security-question",
        FieldKind::SignInWith => "sign-in-with",
    }
}

fn parse_name<D: serde::de::DeserializeOwned>(name: &str) -> Result<D, CoreError> {
    serde_json::from_value(serde_json::Value::String(name.to_owned()))
        .map_err(|_| CoreError::Refused("unknown name"))
}

pub(super) fn mode_name(mode: MatchMode) -> &'static str {
    match mode {
        MatchMode::Domain => "domain",
        MatchMode::Host => "host",
        MatchMode::Never => "never",
    }
}

fn mode_of(name: &str) -> Result<MatchMode, CoreError> {
    match name {
        "domain" => Ok(MatchMode::Domain),
        "host" => Ok(MatchMode::Host),
        "never" => Ok(MatchMode::Never),
        _ => Err(CoreError::Refused("match mode")),
    }
}

fn url_kind_name(kind: UrlKind) -> &'static str {
    match kind {
        UrlKind::Website => "website",
        UrlKind::SignIn => "sign-in",
        UrlKind::Api => "api",
    }
}

fn url_kind_of(name: &str) -> Result<UrlKind, CoreError> {
    match name {
        "website" => Ok(UrlKind::Website),
        "sign-in" => Ok(UrlKind::SignIn),
        "api" => Ok(UrlKind::Api),
        _ => Err(CoreError::Refused("url kind")),
    }
}

fn address_json(address: &Address) -> serde_json::Value {
    serde_json::json!({
        "street": address.street,
        "city": address.city,
        "region": address.region,
        "postalCode": address.postal_code,
        "country": address.country,
    })
}

fn address_of(text: &str) -> Result<Address, CoreError> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| CoreError::Refused("address"))?;
    let part = |key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    Ok(Address {
        street: part("street"),
        city: part("city"),
        region: part("region"),
        postal_code: part("postalCode"),
        country: part("country"),
    })
}

pub(super) fn plain_text(value: &FieldValue) -> Option<String> {
    match value {
        FieldValue::Text(t)
        | FieldValue::Url(t)
        | FieldValue::Email(t)
        | FieldValue::Phone(t)
        | FieldValue::Menu(t)
        | FieldValue::SignInWith(t) => Some(t.clone()),
        FieldValue::Date(d) => Some(format!("{:04}-{:02}-{:02}", d.year(), d.month(), d.day())),
        FieldValue::MonthYear(m) => Some(format!("{:04}-{:02}", m.year(), m.month())),
        FieldValue::Address(a) => Some(address_json(a).to_string()),
        FieldValue::SecurityQuestion { question, .. } => Some(question.clone()),
        FieldValue::Concealed(_) | FieldValue::Otp(_) => None,
    }
}

/// The raw text of a field for reveal, copy and fill: the one place a secret leaves the model.
pub(super) fn secret_text(field: &Field) -> Secret {
    let text = match field.value() {
        FieldValue::Concealed(s) => s.expose_secret().to_owned(),
        FieldValue::SecurityQuestion { answer, .. } => answer.expose_secret().to_owned(),
        FieldValue::Otp(params) => otp_uri::encode(params),
        other => plain_text(other).unwrap_or_default(),
    };
    Secret::new(text.into_bytes())
}

fn field_view(field: &Field) -> FieldView {
    FieldView {
        id: ids::hex(field.id().as_bytes()),
        label: field.label().to_owned(),
        kind: kind_name(field.kind()).to_owned(),
        purpose: field.purpose().map(|p| purpose_name(p).to_owned()),
        concealed: field.is_concealed(),
        value: if field.is_concealed() {
            None
        } else {
            plain_text(field.value())
        },
        expires_alert: field.expires_alert(),
    }
}

pub(super) fn detail_of(
    vault: &VaultId,
    item_id: &ItemId,
    item: &Item,
    version: u64,
    pending: bool,
) -> ItemDetail {
    let details = item.details();
    ItemDetail {
        row: row_of(vault, item_id, item.overview(), version, pending),
        sections: details
            .sections
            .iter()
            .map(|section| SectionView {
                id: ids::hex(section.id().as_bytes()),
                title: section.title().to_owned(),
                fields: section.fields().iter().map(field_view).collect(),
            })
            .collect(),
        notes: details.notes.clone(),
        urls: details
            .urls
            .iter()
            .map(|u| UrlView {
                id: ids::hex(u.id().as_bytes()),
                url: u.url().to_owned(),
                mode: mode_name(u.mode()).to_owned(),
                kind: url_kind_name(u.kind()).to_owned(),
                confirmed_hosts: u.confirmed_hosts().to_vec(),
            })
            .collect(),
        attachments: details
            .attachments
            .iter()
            .map(|a| AttachmentView {
                id: ids::hex(a.att_id.as_bytes()),
                name: a.name.clone(),
                mime: a.mime.clone(),
                size: a.size,
            })
            .collect(),
        passkeys: u32::try_from(details.passkeys.len()).unwrap_or(u32::MAX),
        password_history: u32::try_from(details.password_history.len()).unwrap_or(u32::MAX),
    }
}

pub(super) fn clone_value(value: &FieldValue) -> Result<FieldValue, CoreError> {
    Ok(match value {
        FieldValue::Text(t) => FieldValue::Text(t.clone()),
        FieldValue::Concealed(s) => FieldValue::Concealed(SecretString::from(s.expose_secret())),
        FieldValue::Url(t) => FieldValue::Url(t.clone()),
        FieldValue::Email(t) => FieldValue::Email(t.clone()),
        FieldValue::Phone(t) => FieldValue::Phone(t.clone()),
        FieldValue::Date(d) => FieldValue::Date(*d),
        FieldValue::MonthYear(m) => FieldValue::MonthYear(*m),
        FieldValue::Otp(p) => FieldValue::Otp(otp_uri::parse(&otp_uri::encode(p))?),
        FieldValue::Address(a) => FieldValue::Address(a.clone()),
        FieldValue::Menu(t) => FieldValue::Menu(t.clone()),
        FieldValue::SecurityQuestion { question, answer } => FieldValue::SecurityQuestion {
            question: question.clone(),
            answer: SecretString::from(answer.expose_secret()),
        },
        FieldValue::SignInWith(t) => FieldValue::SignInWith(t.clone()),
    })
}

fn parse_date(text: &str) -> Result<Date, CoreError> {
    let mut parts = text.splitn(3, '-').map(str::parse::<u32>);
    let (Some(Ok(y)), Some(Ok(m)), Some(Ok(d))) = (parts.next(), parts.next(), parts.next()) else {
        return Err(CoreError::Refused("date"));
    };
    Ok(Date::new(
        u16::try_from(y).map_err(|_| CoreError::Refused("date"))?,
        u8::try_from(m).map_err(|_| CoreError::Refused("date"))?,
        u8::try_from(d).map_err(|_| CoreError::Refused("date"))?,
    )?)
}

fn parse_month_year(text: &str) -> Result<MonthYear, CoreError> {
    let mut parts = text.splitn(2, '-').map(str::parse::<u32>);
    let (Some(Ok(y)), Some(Ok(m))) = (parts.next(), parts.next()) else {
        return Err(CoreError::Refused("month"));
    };
    Ok(MonthYear::new(
        u16::try_from(y).map_err(|_| CoreError::Refused("month"))?,
        u8::try_from(m).map_err(|_| CoreError::Refused("month"))?,
    )?)
}

fn value_from(kind: FieldKind, raw: &Secret) -> Result<FieldValue, CoreError> {
    let text = std::str::from_utf8(raw.as_bytes()).map_err(|_| CoreError::Refused("text"))?;
    Ok(match kind {
        FieldKind::Text => FieldValue::Text(text.to_owned()),
        FieldKind::Concealed => FieldValue::Concealed(SecretString::from(text)),
        FieldKind::Url => FieldValue::Url(text.to_owned()),
        FieldKind::Email => FieldValue::Email(text.to_owned()),
        FieldKind::Phone => FieldValue::Phone(text.to_owned()),
        FieldKind::Date => FieldValue::Date(parse_date(text)?),
        FieldKind::MonthYear => FieldValue::MonthYear(parse_month_year(text)?),
        FieldKind::Otp => FieldValue::Otp(otp_uri::parse(text)?),
        FieldKind::Address => FieldValue::Address(address_of(text)?),
        FieldKind::Menu => FieldValue::Menu(text.to_owned()),
        FieldKind::SecurityQuestion => {
            let value: serde_json::Value =
                serde_json::from_str(text).map_err(|_| CoreError::Refused("question"))?;
            let part = |key: &str| {
                value
                    .get(key)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            FieldValue::SecurityQuestion {
                question: part("question"),
                answer: SecretString::from(part("answer")),
            }
        }
        FieldKind::SignInWith => FieldValue::SignInWith(text.to_owned()),
    })
}

fn field_of(draft: &FieldDraft, old: &mut Vec<Field>) -> Result<Field, CoreError> {
    let id = match &draft.id {
        Some(text) => Id::from_bytes(
            hasp_crypto::from_hex(text)
                .and_then(|raw| raw.try_into().ok())
                .ok_or(CoreError::Refused("malformed identifier"))?,
        ),
        None => Id::random()?,
    };
    let existing = old.iter().position(|f| f.id() == id).map(|i| old.remove(i));
    let kind: FieldKind = parse_name(&draft.kind)?;
    let value = match (draft.keep_value, &existing) {
        (true, Some(field)) if field.kind() == kind => clone_value(field.value())?,
        _ => value_from(kind, &draft.value)?,
    };
    let mut field = Field::new(id, &draft.label, value)?;
    if let Some(purpose) = &draft.purpose {
        field = field.with_purpose(parse_name::<Purpose>(purpose)?)?;
    }
    Ok(field
        .with_concealed(draft.concealed)
        .with_expires_alert(draft.expires_alert))
}

fn section_of(
    draft: SectionDraft,
    old: &mut Vec<Field>,
    history: &mut Vec<PasswordHistoryEntry>,
    now: u64,
) -> Result<Section, CoreError> {
    let id = match &draft.id {
        Some(text) => Id::from_bytes(
            hasp_crypto::from_hex(text)
                .and_then(|raw| raw.try_into().ok())
                .ok_or(CoreError::Refused("malformed identifier"))?,
        ),
        None => Id::random()?,
    };
    let mut fields = Vec::with_capacity(draft.fields.len());
    for field in draft.fields {
        if field.value.is_empty()
            && !field.keep_value
            && matches!(
                parse_name::<FieldKind>(&field.kind)?,
                FieldKind::Otp | FieldKind::Date | FieldKind::MonthYear
            )
        {
            continue;
        }
        let previous = field
            .id
            .as_deref()
            .and_then(hasp_crypto::from_hex)
            .and_then(|raw| <[u8; 16]>::try_from(raw).ok())
            .map(Id::from_bytes);
        let before = previous
            .and_then(|id| old.iter().find(|f| f.id() == id))
            .filter(|f| f.purpose() == Some(Purpose::Password))
            .and_then(|f| match f.value() {
                FieldValue::Concealed(s) => Some((f.id(), SecretString::from(s.expose_secret()))),
                _ => None,
            });
        let built = field_of(&field, old)?;
        if let (Some((field_id, previous)), FieldValue::Concealed(now_value)) =
            (before, built.value())
            && previous.expose_secret() != now_value.expose_secret()
            && !previous.expose_secret().is_empty()
        {
            history.push(PasswordHistoryEntry {
                value: previous,
                replaced_at: now,
                field: field_id,
            });
        }
        fields.push(built);
    }
    Ok(Section::new(id, &draft.title, fields)?)
}

fn urls_of(drafts: Vec<UrlDraft>, old: &[UrlEntry]) -> Result<Vec<UrlEntry>, CoreError> {
    drafts
        .into_iter()
        .map(|draft| {
            let id = match &draft.id {
                Some(text) => Id::from_bytes(
                    hasp_crypto::from_hex(text)
                        .and_then(|raw| raw.try_into().ok())
                        .ok_or(CoreError::Refused("malformed identifier"))?,
                ),
                None => Id::random()?,
            };
            let mode = mode_of(&draft.mode)?;
            let mut entry = UrlEntry::new(id, &draft.url, mode, url_kind_of(&draft.kind)?)?;
            if let Some(previous) = old.iter().find(|u| u.id() == id && u.url() == entry.url()) {
                for host in previous.confirmed_hosts() {
                    entry.confirm_host(host)?;
                }
            }
            Ok(entry)
        })
        .collect()
}

pub(super) fn parts_from_draft(
    draft: ItemDraft,
    previous: Option<ItemParts>,
    now: u64,
) -> Result<ItemParts, CoreError> {
    let mut parts = previous.unwrap_or_else(|| ItemParts {
        kind: String::new(),
        title: String::new(),
        subtitle: String::new(),
        tags: Vec::new(),
        favourite: None,
        state: ItemState::Active,
        sections: Vec::new(),
        notes: None,
        urls: Vec::new(),
        apps: Vec::new(),
        passkeys: Vec::new(),
        attachments: Vec::new(),
        password_history: Vec::new(),
        client_modified: now,
        created: now,
        expires_at: None,
    });
    let mut old_fields: Vec<Field> = std::mem::take(&mut parts.sections)
        .into_iter()
        .flat_map(Section::into_fields)
        .collect();
    let mut history = std::mem::take(&mut parts.password_history);
    let mut sections = Vec::with_capacity(draft.sections.len());
    for section in draft.sections {
        sections.push(section_of(section, &mut old_fields, &mut history, now)?);
    }
    if history.len() > HISTORY_CAP {
        history.drain(..history.len() - HISTORY_CAP);
    }
    parts.urls = urls_of(draft.urls, &parts.urls)?;
    parts.sections = sections;
    parts.password_history = history;
    parts.kind = draft.kind;
    parts.title = draft.title;
    parts.subtitle = draft.subtitle;
    parts.tags = draft
        .tags
        .iter()
        .map(|t| Tag::new(t))
        .collect::<Result<_, _>>()?;
    parts.favourite = match (draft.favourite, parts.favourite) {
        (true, Some(rank)) => Some(rank),
        (true, None) => Some(0),
        (false, _) => None,
    };
    parts.notes = draft.notes.filter(|n| !n.is_empty());
    parts.expires_at = draft.expires_at;
    parts.client_modified = now;
    Ok(parts)
}

pub(super) fn draft_of(item: &Item) -> ItemDraft {
    let overview = item.overview();
    let details = item.details();
    ItemDraft {
        kind: overview.kind.clone(),
        title: overview.title.clone(),
        subtitle: overview.subtitle.clone(),
        tags: overview
            .tags
            .iter()
            .map(|t| t.as_str().to_owned())
            .collect(),
        favourite: overview.favourite.is_some(),
        notes: details.notes.clone(),
        expires_at: overview.expires_at,
        sections: details
            .sections
            .iter()
            .map(|section| SectionDraft {
                id: Some(ids::hex(section.id().as_bytes())),
                title: section.title().to_owned(),
                fields: section
                    .fields()
                    .iter()
                    .map(|field| {
                        let hidden = field.is_concealed()
                            || matches!(
                                field.kind(),
                                FieldKind::Concealed | FieldKind::Otp | FieldKind::SecurityQuestion
                            );
                        FieldDraft {
                            id: Some(ids::hex(field.id().as_bytes())),
                            label: field.label().to_owned(),
                            kind: kind_name(field.kind()).to_owned(),
                            purpose: field.purpose().map(|p| purpose_name(p).to_owned()),
                            concealed: field.is_concealed(),
                            expires_alert: field.expires_alert(),
                            value: if hidden {
                                Secret::new(Vec::new())
                            } else {
                                Secret::new(
                                    plain_text(field.value()).unwrap_or_default().into_bytes(),
                                )
                            },
                            keep_value: hidden,
                        }
                    })
                    .collect(),
            })
            .collect(),
        urls: details
            .urls
            .iter()
            .map(|u| UrlDraft {
                id: Some(ids::hex(u.id().as_bytes())),
                url: u.url().to_owned(),
                mode: mode_name(u.mode()).to_owned(),
                kind: url_kind_name(u.kind()).to_owned(),
            })
            .collect(),
    }
}
