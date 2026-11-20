use hasp_core::model::field::{
    Address, Date, Field, FieldKind, FieldValue, MonthYear, Purpose, Section,
};
use hasp_core::model::id::Id;
use hasp_core::model::item::{Item, ItemParts, ItemState, PasswordHistoryEntry};
use hasp_core::model::tag::Tag;
use hasp_core::model::template::{CategoryTemplate, Templates};
use hasp_core::model::url::{MatchMode, UrlEntry, UrlKind};
use hasp_core::otp;
use hasp_crypto::to_hex;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;

use crate::error::CliError;

#[derive(Debug, serde::Deserialize)]
pub(crate) struct JsonField {
    pub(crate) key: String,
    pub(crate) value: String,
    #[serde(default)]
    pub(crate) section: Option<String>,
    #[serde(default)]
    pub(crate) concealed: Option<bool>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub(crate) struct JsonTemplate {
    pub(crate) category: Option<String>,
    pub(crate) title: Option<String>,
    pub(crate) subtitle: Option<String>,
    pub(crate) tags: Vec<String>,
    pub(crate) notes: Option<String>,
    pub(crate) urls: Vec<String>,
    pub(crate) favourite: Option<bool>,
    pub(crate) fields: Vec<JsonField>,
}

pub(crate) struct FieldSet {
    pub(crate) key: String,
    pub(crate) value: SecretString,
    pub(crate) section: Option<String>,
    pub(crate) concealed: Option<bool>,
}

impl std::fmt::Debug for FieldSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldSet")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
pub(crate) struct Changes {
    pub(crate) category: Option<String>,
    pub(crate) title: Option<String>,
    pub(crate) subtitle: Option<String>,
    pub(crate) tags_add: Vec<String>,
    pub(crate) tags_remove: Vec<String>,
    pub(crate) notes: Option<String>,
    pub(crate) urls_add: Vec<String>,
    pub(crate) favourite: Option<bool>,
    pub(crate) fields: Vec<FieldSet>,
}

impl Changes {
    pub(crate) fn from_template(json: &[u8]) -> Result<Self, CliError> {
        let template: JsonTemplate = serde_json::from_slice(json)
            .map_err(|_| CliError::usage("the template is not valid item JSON"))?;
        Ok(Self {
            category: template.category,
            title: template.title,
            subtitle: template.subtitle,
            tags_add: template.tags,
            tags_remove: Vec::new(),
            notes: template.notes,
            urls_add: template.urls,
            favourite: template.favourite,
            fields: template
                .fields
                .into_iter()
                .map(|field| FieldSet {
                    key: field.key,
                    value: SecretString::from(field.value),
                    section: field.section,
                    concealed: field.concealed,
                })
                .collect(),
        })
    }

    pub(crate) fn merge(&mut self, other: Self) {
        self.category = other.category.or(self.category.take());
        self.title = other.title.or(self.title.take());
        self.subtitle = other.subtitle.or(self.subtitle.take());
        self.tags_add.extend(other.tags_add);
        self.tags_remove.extend(other.tags_remove);
        self.notes = other.notes.or(self.notes.take());
        self.urls_add.extend(other.urls_add);
        self.favourite = other.favourite.or(self.favourite);
        self.fields.extend(other.fields);
    }
}

pub(crate) fn purpose_name(purpose: Purpose) -> &'static str {
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

pub(crate) fn kind_name(kind: FieldKind) -> &'static str {
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

pub(crate) fn field_matches(field: &Field, key: &str) -> bool {
    let folded = key.to_lowercase();
    field.label().to_lowercase() == folded
        || field.purpose().is_some_and(|p| purpose_name(p) == folded)
        || to_hex(field.id().as_bytes()) == folded
}

pub(crate) fn is_secret(field: &Field) -> bool {
    field.is_concealed()
        || matches!(
            field.kind(),
            FieldKind::Concealed | FieldKind::Otp | FieldKind::SecurityQuestion
        )
}

pub(crate) fn value_text(value: &FieldValue) -> String {
    match value {
        FieldValue::Text(v)
        | FieldValue::Url(v)
        | FieldValue::Email(v)
        | FieldValue::Phone(v)
        | FieldValue::Menu(v)
        | FieldValue::SignInWith(v) => v.clone(),
        FieldValue::Concealed(v) => v.expose_secret().to_owned(),
        FieldValue::Date(d) => format!("{:04}-{:02}-{:02}", d.year(), d.month(), d.day()),
        FieldValue::MonthYear(m) => format!("{:04}-{:02}", m.year(), m.month()),
        FieldValue::Otp(params) => otp::uri::encode(params),
        FieldValue::Address(a) => [&a.street, &a.city, &a.region, &a.postal_code, &a.country]
            .iter()
            .map(|part| part.as_str())
            .collect::<Vec<_>>()
            .join("; "),
        FieldValue::SecurityQuestion { question, answer } => {
            format!("{question}::{}", answer.expose_secret())
        }
    }
}

fn parse_date(raw: &str) -> Result<Date, CliError> {
    let mut parts = raw.split('-');
    let (Some(y), Some(m), Some(d), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(CliError::usage("a date is YYYY-MM-DD"));
    };
    let bad = |_| CliError::usage("a date is YYYY-MM-DD");
    Ok(Date::new(
        y.parse().map_err(bad)?,
        m.parse().map_err(bad)?,
        d.parse().map_err(bad)?,
    )?)
}

fn parse_month_year(raw: &str) -> Result<MonthYear, CliError> {
    let Some((y, m)) = raw.split_once('-') else {
        return Err(CliError::usage("a month and year is YYYY-MM"));
    };
    let bad = |_| CliError::usage("a month and year is YYYY-MM");
    Ok(MonthYear::new(
        y.parse().map_err(bad)?,
        m.parse().map_err(bad)?,
    )?)
}

pub(crate) fn parse_value(kind: FieldKind, raw: &SecretString) -> Result<FieldValue, CliError> {
    let text = raw.expose_secret();
    let owned = || text.to_owned();
    Ok(match kind {
        FieldKind::Text => FieldValue::Text(owned()),
        FieldKind::Concealed => FieldValue::Concealed(SecretString::from(owned())),
        FieldKind::Url => FieldValue::Url(owned()),
        FieldKind::Email => FieldValue::Email(owned()),
        FieldKind::Phone => FieldValue::Phone(owned()),
        FieldKind::Menu => FieldValue::Menu(owned()),
        FieldKind::SignInWith => FieldValue::SignInWith(owned()),
        FieldKind::Date => FieldValue::Date(parse_date(text)?),
        FieldKind::MonthYear => FieldValue::MonthYear(parse_month_year(text)?),
        FieldKind::Otp => {
            let uri = if text.contains("://") {
                owned()
            } else {
                format!(
                    "otpauth://totp/hasp?secret={}",
                    text.replace(' ', "").to_uppercase()
                )
            };
            FieldValue::Otp(otp::uri::parse(&uri).map_err(hasp_core::CoreError::from)?)
        }
        FieldKind::Address => {
            let mut parts = text.split(';').map(|part| part.trim().to_owned());
            FieldValue::Address(Address {
                street: parts.next().unwrap_or_default(),
                city: parts.next().unwrap_or_default(),
                region: parts.next().unwrap_or_default(),
                postal_code: parts.next().unwrap_or_default(),
                country: parts.next().unwrap_or_default(),
            })
        }
        FieldKind::SecurityQuestion => {
            let (question, answer) = text
                .split_once("::")
                .ok_or_else(|| CliError::usage("a security question is QUESTION::ANSWER"))?;
            FieldValue::SecurityQuestion {
                question: question.to_owned(),
                answer: SecretString::from(answer.to_owned()),
            }
        }
    })
}

fn new_id() -> Result<Id, hasp_core::model::ModelError> {
    Id::random()
}

fn template_kind(template: &CategoryTemplate, key: &str) -> Option<(FieldKind, String)> {
    let folded = key.to_lowercase();
    template
        .fields()
        .find(|f| {
            f.key.to_lowercase() == folded
                || f.label.en.to_lowercase() == folded
                || f.purpose.is_some_and(|p| purpose_name(p) == folded)
        })
        .map(|f| (f.kind, f.label.en.clone()))
}

fn rebuild(field: &Field, value: FieldValue) -> Result<Field, CliError> {
    let mut next = Field::new(field.id(), field.label(), value)?
        .with_concealed(field.is_concealed())
        .with_expires_alert(field.expires_alert());
    if let Some(purpose) = field.purpose() {
        next = next.with_purpose(purpose)?;
    }
    Ok(next)
}

fn map_section(
    sections: &mut [Section],
    index: usize,
    change: impl FnOnce(Vec<Field>) -> Result<Vec<Field>, CliError>,
) -> Result<(), CliError> {
    let slot = sections
        .get_mut(index)
        .ok_or_else(|| CliError::failure("section index"))?;
    let taken = std::mem::replace(slot, Section::new(Id::from_bytes([0; 16]), "", Vec::new())?);
    let id = taken.id();
    let title = taken.title().to_owned();
    *slot = Section::new(id, &title, change(taken.into_fields())?)?;
    Ok(())
}

fn apply_field(
    sections: &mut Vec<Section>,
    template: &CategoryTemplate,
    set: &FieldSet,
    history: &mut Vec<PasswordHistoryEntry>,
    now: u64,
) -> Result<(), CliError> {
    let located = sections.iter().enumerate().find_map(|(s, section)| {
        section
            .fields()
            .iter()
            .position(|field| field_matches(field, &set.key))
            .map(|f| (s, f))
    });
    if let Some((s, f)) = located {
        return map_section(sections, s, |mut fields| {
            let existing = fields
                .get(f)
                .ok_or_else(|| CliError::failure("field index"))?;
            let value = parse_value(existing.kind(), &set.value)?;
            if existing.purpose() == Some(Purpose::Password)
                && let FieldValue::Concealed(old) = existing.value()
                && !old.expose_secret().is_empty()
                && old.expose_secret() != set.value.expose_secret()
            {
                history.push(PasswordHistoryEntry {
                    value: SecretString::from(old.expose_secret().to_owned()),
                    replaced_at: now,
                    field: existing.id(),
                });
            }
            let replaced = rebuild(existing, value)?;
            if let Some(slot) = fields.get_mut(f) {
                *slot = replaced;
            }
            Ok(fields)
        });
    }
    let (kind, label) = template_kind(template, &set.key).unwrap_or_else(|| {
        let kind = if set.concealed == Some(true) {
            FieldKind::Concealed
        } else {
            FieldKind::Text
        };
        (kind, set.key.clone())
    });
    let mut field = Field::new(new_id()?, &label, parse_value(kind, &set.value)?)?;
    if let Some(concealed) = set.concealed {
        field = field.with_concealed(concealed);
    }
    if let Some(purpose) = template
        .fields()
        .find(|f| f.label.en == label)
        .and_then(|f| f.purpose)
    {
        field = field.with_purpose(purpose)?;
    }
    let title = set.section.clone().unwrap_or_default();
    if let Some(index) = sections.iter().position(|s| s.title() == title) {
        map_section(sections, index, |mut fields| {
            fields.push(field);
            Ok(fields)
        })
    } else {
        sections.push(Section::new(new_id()?, &title, vec![field])?);
        Ok(())
    }
}

fn drop_empty(sections: Vec<Section>) -> Result<Vec<Section>, CliError> {
    let mut out = Vec::with_capacity(sections.len());
    for section in sections {
        let id = section.id();
        let title = section.title().to_owned();
        let fields: Vec<Field> = section
            .into_fields()
            .into_iter()
            .filter(|field| !field.value().is_empty())
            .collect();
        if !fields.is_empty() {
            out.push(Section::new(id, &title, fields)?);
        }
    }
    Ok(out)
}

fn tags_of(parts: &[String]) -> Result<Vec<Tag>, CliError> {
    parts.iter().map(|t| Ok(Tag::new(t)?)).collect()
}

fn url_entries(urls: &[String]) -> Result<Vec<UrlEntry>, CliError> {
    urls.iter()
        .map(|url| {
            Ok(UrlEntry::new(
                new_id()?,
                url,
                MatchMode::Domain,
                UrlKind::SignIn,
            )?)
        })
        .collect()
}

pub(crate) fn create(templates: &Templates, changes: &Changes, now: u64) -> Result<Item, CliError> {
    let category = changes.category.as_deref().unwrap_or("login");
    let template = templates
        .resolve(category)
        .map_err(|_| CliError::usage(format!("unknown category {category}")))?;
    let title = changes
        .title
        .clone()
        .ok_or_else(|| CliError::usage("an item needs --title"))?;
    let mut sections = template.blank_sections(new_id)?;
    let mut history = Vec::new();
    for set in &changes.fields {
        apply_field(&mut sections, template, set, &mut history, now)?;
    }
    let favourite = changes.favourite.and_then(|on| on.then_some(1));
    Ok(Item::new(ItemParts {
        kind: template.id.clone(),
        title,
        subtitle: changes.subtitle.clone().unwrap_or_default(),
        tags: tags_of(&changes.tags_add)?,
        favourite,
        state: ItemState::Active,
        sections: drop_empty(sections)?,
        notes: changes.notes.clone(),
        urls: url_entries(&changes.urls_add)?,
        apps: Vec::new(),
        passkeys: Vec::new(),
        attachments: Vec::new(),
        password_history: history,
        client_modified: now,
        created: now,
        expires_at: None,
    })?)
}

pub(crate) fn edit(
    templates: &Templates,
    item: Item,
    changes: &Changes,
    now: u64,
) -> Result<Item, CliError> {
    let mut parts = item.into_parts();
    let template = templates
        .resolve(&parts.kind)
        .map_err(|_| CliError::failure("the item category is unknown to this build"))?;
    if let Some(title) = &changes.title {
        parts.title.clone_from(title);
    }
    if let Some(subtitle) = &changes.subtitle {
        parts.subtitle.clone_from(subtitle);
    }
    if let Some(notes) = &changes.notes {
        parts.notes = (!notes.is_empty()).then(|| notes.clone());
    }
    let removed = tags_of(&changes.tags_remove)?;
    parts.tags.retain(|tag| !removed.contains(tag));
    parts.tags.extend(tags_of(&changes.tags_add)?);
    parts.urls.extend(url_entries(&changes.urls_add)?);
    if let Some(on) = changes.favourite {
        parts.favourite = on.then_some(1);
    }
    for set in &changes.fields {
        apply_field(
            &mut parts.sections,
            template,
            set,
            &mut parts.password_history,
            now,
        )?;
    }
    parts.sections = drop_empty(parts.sections)?;
    parts.client_modified = now;
    let edited = Item::new(parts)?;
    let kind = templates.kind_after_edit(&edited.overview().kind, edited.details());
    if kind == edited.overview().kind {
        return Ok(edited);
    }
    let mut parts = edited.into_parts();
    parts.kind = kind;
    Ok(Item::new(parts)?)
}

pub(crate) fn fields_json(item: &Item, reveal: bool) -> Vec<Value> {
    let mut out = Vec::new();
    for section in &item.details().sections {
        for field in section.fields() {
            let secret = is_secret(field);
            let value = if secret && !reveal {
                Value::String(crate::output::CONCEALED.to_owned())
            } else {
                Value::String(value_text(field.value()))
            };
            out.push(serde_json::json!({
                "id": to_hex(field.id().as_bytes()),
                "section": section.title(),
                "label": field.label(),
                "kind": kind_name(field.kind()),
                "purpose": field.purpose().map(purpose_name),
                "concealed": secret,
                "value": value,
            }));
        }
    }
    out
}
