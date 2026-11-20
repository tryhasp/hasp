use std::collections::{BTreeMap, BTreeSet};

use secrecy::SecretString;
use serde::Deserialize;

use crate::model::ModelError;
use crate::model::field::{Field, FieldKind, FieldValue, Purpose, Section};
use crate::model::id::Id;
use crate::model::item::Details;

pub const CUSTOM_ID: &str = "custom";
const MAX_ID_LEN: usize = 32;
const MAX_KEY_LEN: usize = 48;
const MAX_FIELDS: usize = 64;

const BUNDLED: [&str; 23] = [
    include_str!("../../templates/login.json"),
    include_str!("../../templates/password.json"),
    include_str!("../../templates/secure-note.json"),
    include_str!("../../templates/credit-card.json"),
    include_str!("../../templates/identity.json"),
    include_str!("../../templates/document.json"),
    include_str!("../../templates/ssh-key.json"),
    include_str!("../../templates/api-credential.json"),
    include_str!("../../templates/wireless-router.json"),
    include_str!("../../templates/bank-account.json"),
    include_str!("../../templates/passport.json"),
    include_str!("../../templates/driver-license.json"),
    include_str!("../../templates/social-security-number.json"),
    include_str!("../../templates/software-license.json"),
    include_str!("../../templates/server.json"),
    include_str!("../../templates/database.json"),
    include_str!("../../templates/email-account.json"),
    include_str!("../../templates/crypto-wallet.json"),
    include_str!("../../templates/membership.json"),
    include_str!("../../templates/reward-program.json"),
    include_str!("../../templates/medical-record.json"),
    include_str!("../../templates/outdoor-license.json"),
    include_str!("../../templates/custom.json"),
];

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedString {
    pub en: String,
    pub ko: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutofillClass {
    Login,
    Card,
    Identity,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WatchtowerCheck {
    Vulnerable,
    Reused,
    Weak,
    InsecureUrl,
    Expiring,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "flat capability flags are the template data format"
)]
pub struct Capabilities {
    pub autofill: AutofillClass,
    #[serde(default)]
    pub watchtower: Vec<WatchtowerCheck>,
    #[serde(default)]
    pub expiry_window_days: Option<u32>,
    #[serde(default)]
    pub supports_urls: bool,
    #[serde(default)]
    pub supports_passkeys: bool,
    #[serde(default)]
    pub supports_apps: bool,
    #[serde(default)]
    pub requires_attachment: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldTemplate {
    pub key: String,
    pub label: LocalizedString,
    pub kind: FieldKind,
    #[serde(default)]
    pub purpose: Option<Purpose>,
    #[serde(default)]
    pub concealed: bool,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub expires_alert_default: bool,
    #[serde(default)]
    pub options: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SectionTemplate {
    pub key: String,
    #[serde(default)]
    pub title: Option<LocalizedString>,
    pub fields: Vec<FieldTemplate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Promotion {
    pub to: String,
    pub when_filled: Purpose,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CategoryTemplate {
    pub id: String,
    pub version: u32,
    pub name: LocalizedString,
    pub icon: String,
    #[serde(default)]
    pub import_codes: BTreeMap<String, String>,
    pub sections: Vec<SectionTemplate>,
    pub capabilities: Capabilities,
    #[serde(default)]
    pub promotion: Option<Promotion>,
}

#[derive(Debug)]
pub struct Templates {
    custom: CategoryTemplate,
    others: BTreeMap<String, CategoryTemplate>,
}

impl CategoryTemplate {
    pub fn parse(json: &str) -> Result<Self, ModelError> {
        let template: Self =
            serde_json::from_str(json).map_err(|e| ModelError::TemplateJson(e.to_string()))?;
        template.validate()?;
        Ok(template)
    }

    pub fn fields(&self) -> impl Iterator<Item = &FieldTemplate> {
        self.sections.iter().flat_map(|s| s.fields.iter())
    }

    pub fn field_with_purpose(&self, purpose: Purpose) -> Option<&FieldTemplate> {
        self.fields().find(|f| f.purpose == Some(purpose))
    }

    pub fn blank_sections(
        &self,
        mut new_id: impl FnMut() -> Result<Id, ModelError>,
    ) -> Result<Vec<Section>, ModelError> {
        let mut sections = Vec::with_capacity(self.sections.len());
        for section in &self.sections {
            let mut fields = Vec::with_capacity(section.fields.len());
            for template in &section.fields {
                let Some(value) = blank_value(template.kind) else {
                    continue;
                };
                let label = template.label.en.as_str();
                let mut field = Field::new(new_id()?, label, value)?;
                let concealed = template.concealed || field.is_concealed();
                field = field.with_concealed(concealed);
                if let Some(purpose) = template.purpose {
                    field = field.with_purpose(purpose)?;
                }
                fields.push(field.with_expires_alert(template.expires_alert_default));
            }
            let title = section.title.as_ref().map_or("", |t| t.en.as_str());
            sections.push(Section::new(new_id()?, title, fields)?);
        }
        Ok(sections)
    }

    fn fail(&self, reason: &'static str) -> ModelError {
        ModelError::Template {
            template: self.id.clone(),
            reason,
        }
    }

    fn validate(&self) -> Result<(), ModelError> {
        if !valid_identifier(&self.id, MAX_ID_LEN) {
            return Err(self.fail("id"));
        }
        if self.version == 0 {
            return Err(self.fail("version"));
        }
        if self.name.en.trim().is_empty()
            || self.name.ko.trim().is_empty()
            || self.icon.trim().is_empty()
        {
            return Err(self.fail("name or icon"));
        }
        if self
            .import_codes
            .iter()
            .any(|(k, v)| k.is_empty() || v.is_empty())
        {
            return Err(self.fail("import code"));
        }
        let mut section_keys = BTreeSet::new();
        let mut field_keys = BTreeSet::new();
        let mut purposes = BTreeSet::new();
        let mut count = 0usize;
        for section in &self.sections {
            if !valid_identifier(&section.key, MAX_KEY_LEN)
                || !section_keys.insert(section.key.as_str())
            {
                return Err(self.fail("section key"));
            }
            if section
                .title
                .as_ref()
                .is_some_and(|t| t.en.trim().is_empty() || t.ko.trim().is_empty())
            {
                return Err(self.fail("section title"));
            }
            for field in &section.fields {
                count += 1;
                self.validate_field(field, &mut field_keys, &mut purposes)?;
            }
        }
        if count > MAX_FIELDS {
            return Err(self.fail("too many fields"));
        }
        self.validate_capabilities()
    }

    fn validate_field<'a>(
        &self,
        field: &'a FieldTemplate,
        keys: &mut BTreeSet<&'a str>,
        purposes: &mut BTreeSet<String>,
    ) -> Result<(), ModelError> {
        if !valid_identifier(&field.key, MAX_KEY_LEN) || !keys.insert(field.key.as_str()) {
            return Err(self.fail("field key"));
        }
        if field.label.en.trim().is_empty() || field.label.ko.trim().is_empty() {
            return Err(self.fail("field label"));
        }
        if let Some(purpose) = field.purpose {
            if !purpose.accepts(field.kind) {
                return Err(self.fail("purpose does not fit kind"));
            }
            if !purposes.insert(format!("{purpose:?}")) {
                return Err(self.fail("duplicate purpose"));
            }
        }
        let options: BTreeSet<&str> = field.options.iter().map(String::as_str).collect();
        let menu = field.kind == FieldKind::Menu;
        if menu == field.options.is_empty()
            || options.len() != field.options.len()
            || options.contains("")
        {
            return Err(self.fail("menu options"));
        }
        Ok(())
    }

    fn validate_capabilities(&self) -> Result<(), ModelError> {
        let caps = &self.capabilities;
        let has = |purpose| self.field_with_purpose(purpose).is_some();
        let autofill_ok = match caps.autofill {
            AutofillClass::Login => has(Purpose::Username) || has(Purpose::Password),
            AutofillClass::Card => has(Purpose::CardNumber),
            AutofillClass::Identity => has(Purpose::Name) || has(Purpose::GivenName),
            AutofillClass::None => true,
        };
        if !autofill_ok {
            return Err(self.fail("autofill class has no matching field"));
        }
        for check in &caps.watchtower {
            let ok = match check {
                WatchtowerCheck::Vulnerable | WatchtowerCheck::Reused | WatchtowerCheck::Weak => {
                    has(Purpose::Password)
                }
                WatchtowerCheck::InsecureUrl => caps.supports_urls,
                WatchtowerCheck::Expiring => caps.expiry_window_days.is_some(),
            };
            if !ok {
                return Err(self.fail("watchtower check without its input"));
            }
        }
        if caps.expiry_window_days == Some(0) {
            return Err(self.fail("expiry window"));
        }
        if caps.requires_attachment && self.id != "document" {
            return Err(self.fail("only document requires an attachment"));
        }
        Ok(())
    }
}

impl Templates {
    pub fn bundled() -> Result<Self, ModelError> {
        Self::from_json(BUNDLED)
    }

    pub fn from_json<'a>(documents: impl IntoIterator<Item = &'a str>) -> Result<Self, ModelError> {
        let mut others = BTreeMap::new();
        for json in documents {
            let template = CategoryTemplate::parse(json)?;
            let id = template.id.clone();
            if others.insert(id.clone(), template).is_some() {
                return Err(ModelError::Template {
                    template: id,
                    reason: "duplicate id",
                });
            }
        }
        let custom = others
            .remove(CUSTOM_ID)
            .ok_or_else(|| ModelError::Template {
                template: CUSTOM_ID.to_owned(),
                reason: "missing",
            })?;
        let templates = Self { custom, others };
        templates.validate()?;
        Ok(templates)
    }

    pub fn get(&self, id: &str) -> Option<&CategoryTemplate> {
        if id == CUSTOM_ID {
            Some(&self.custom)
        } else {
            self.others.get(id)
        }
    }

    pub fn custom(&self) -> &CategoryTemplate {
        &self.custom
    }

    pub fn resolve(&self, id: &str) -> Result<&CategoryTemplate, ModelError> {
        self.get(id)
            .ok_or_else(|| ModelError::UnknownTemplate(id.to_owned()))
    }

    pub fn iter(&self) -> impl Iterator<Item = &CategoryTemplate> {
        self.others.values().chain(std::iter::once(&self.custom))
    }

    pub fn len(&self) -> usize {
        self.others.len() + 1
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn by_import_code(&self, source: &str, code: &str) -> &CategoryTemplate {
        self.iter()
            .find(|t| t.import_codes.get(source).is_some_and(|c| c == code))
            .unwrap_or(&self.custom)
    }

    pub fn kind_after_edit(&self, kind: &str, details: &Details) -> String {
        let promoted = self
            .get(kind)
            .and_then(|template| template.promotion.as_ref())
            .filter(|p| {
                self.get(&p.to).is_some()
                    && details
                        .sections
                        .iter()
                        .flat_map(Section::fields)
                        .any(|field| {
                            field.purpose() == Some(p.when_filled) && !field.value().is_empty()
                        })
            });
        promoted.map_or_else(|| kind.to_owned(), |p| p.to.clone())
    }

    pub fn check_details(&self, kind: &str, details: &Details) -> Result<(), ModelError> {
        let Some(template) = self.get(kind) else {
            return Ok(());
        };
        if template.capabilities.requires_attachment && details.attachments.is_empty() {
            return Err(ModelError::Item("document requires an attachment"));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ModelError> {
        for template in self.iter() {
            if let Some(promotion) = &template.promotion
                && (promotion.to == template.id
                    || self.get(&promotion.to).is_none_or(|target| {
                        target.field_with_purpose(promotion.when_filled).is_none()
                    }))
            {
                return Err(ModelError::Template {
                    template: template.id.clone(),
                    reason: "promotion target",
                });
            }
        }
        Ok(())
    }
}

fn blank_value(kind: FieldKind) -> Option<FieldValue> {
    match kind {
        FieldKind::Text => Some(FieldValue::Text(String::new())),
        FieldKind::Concealed => Some(FieldValue::Concealed(SecretString::from(""))),
        FieldKind::Url => Some(FieldValue::Url(String::new())),
        FieldKind::Email => Some(FieldValue::Email(String::new())),
        FieldKind::Phone => Some(FieldValue::Phone(String::new())),
        FieldKind::Menu => Some(FieldValue::Menu(String::new())),
        FieldKind::Address => Some(FieldValue::Address(crate::model::field::Address::default())),
        FieldKind::SecurityQuestion => Some(FieldValue::SecurityQuestion {
            question: String::new(),
            answer: SecretString::from(""),
        }),
        FieldKind::SignInWith => Some(FieldValue::SignInWith(String::new())),
        FieldKind::Date | FieldKind::MonthYear | FieldKind::Otp => None,
    }
}

fn valid_identifier(text: &str, max: usize) -> bool {
    !text.is_empty()
        && text.len() <= max
        && text.starts_with(|c: char| c.is_ascii_lowercase())
        && text
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests;
