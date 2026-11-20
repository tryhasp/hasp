use secrecy::SecretString;

use crate::import::report::{Entry, Fate, ItemReport, Outcome, Reason, Subject};
use crate::import::{AttachedFile, ImportItem};
use crate::model::ModelError;
use crate::model::field::{Field, FieldValue, Purpose, Section};
use crate::model::id::Id;
use crate::model::item::{
    AppAssociation, AppPlatform, AssocSource, Item, ItemParts, ItemState, Passkey,
    PasswordHistoryEntry,
};
use crate::model::tag::Tag;
use crate::model::url::{MatchMode, UrlEntry, UrlKind};
use crate::otp::{OtpError, OtpParams, uri};

const MAX_HISTORY: usize = 100;

#[derive(Debug)]
pub(super) struct Draft {
    pub(super) source_id: String,
    pub(super) template: String,
    pub(super) title: String,
    pub(super) subtitle: String,
    pub(super) tags: Vec<Tag>,
    pub(super) favourite: Option<u32>,
    pub(super) state: ItemState,
    pub(super) notes: Option<String>,
    pub(super) urls: Vec<UrlEntry>,
    pub(super) apps: Vec<AppAssociation>,
    pub(super) passkeys: Vec<Passkey>,
    pub(super) history: Vec<PasswordHistoryEntry>,
    pub(super) sections: Vec<Section>,
    pub(super) files: Vec<AttachedFile>,
    pub(super) created: u64,
    pub(super) modified: u64,
    pub(super) entries: Vec<Entry>,
    purposes: Vec<Purpose>,
}

impl Draft {
    pub(super) fn new(source_id: &str, template: &str, title: &str) -> Self {
        Self {
            source_id: source_id.to_owned(),
            template: template.to_owned(),
            title: title.to_owned(),
            subtitle: String::new(),
            tags: Vec::new(),
            favourite: None,
            state: ItemState::Active,
            notes: None,
            urls: Vec::new(),
            apps: Vec::new(),
            passkeys: Vec::new(),
            history: Vec::new(),
            sections: Vec::new(),
            files: Vec::new(),
            created: 0,
            modified: 0,
            entries: Vec::new(),
            purposes: Vec::new(),
        }
    }

    pub(super) fn approximated(&mut self, subject: Subject, reason: Reason) {
        self.entries.push(Entry {
            subject,
            fate: Fate::Approximated { reason },
        });
    }

    pub(super) fn lost(&mut self, subject: Subject, reason: Reason) {
        self.entries.push(Entry {
            subject,
            fate: Fate::Lost { reason },
        });
    }

    pub(super) fn password_field_id(&self) -> Option<Id> {
        self.sections
            .iter()
            .flat_map(Section::fields)
            .find(|f| f.purpose() == Some(Purpose::Password))
            .map(Field::id)
    }

    pub(super) fn field(
        &mut self,
        label: &str,
        value: FieldValue,
        purpose: Option<Purpose>,
        concealed: bool,
    ) -> Option<Field> {
        let kind = value.kind();
        let purpose = purpose.filter(|p| p.accepts(kind) && !self.purposes.contains(p));
        let mut field = match random_id().and_then(|id| Field::new(id, label, value)) {
            Ok(field) => field,
            Err(error) => {
                self.lost(Subject::Field(label.to_owned()), rejected(&error));
                return None;
            }
        };
        let concealed = concealed || field.is_concealed();
        field = field.with_concealed(concealed);
        if let Some(purpose) = purpose {
            field = field.with_purpose(purpose).ok()?;
            self.purposes.push(purpose);
        }
        Some(field)
    }

    pub(super) fn text(
        &mut self,
        label: &str,
        value: &str,
        purpose: Option<Purpose>,
    ) -> Option<Field> {
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        self.field(label, FieldValue::Text(value.to_owned()), purpose, false)
    }

    pub(super) fn secret(
        &mut self,
        label: &str,
        value: &str,
        purpose: Option<Purpose>,
    ) -> Option<Field> {
        if value.is_empty() {
            return None;
        }
        let value = FieldValue::Concealed(SecretString::from(value));
        self.field(label, value, purpose, true)
    }

    pub(super) fn otp(
        &mut self,
        label: &str,
        text: &str,
        purpose: Option<Purpose>,
    ) -> Option<Field> {
        if let Ok(params) = otp_from_text(text) {
            self.field(label, FieldValue::Otp(params), purpose, true)
        } else {
            self.lost(Subject::Field(label.to_owned()), Reason::InvalidValue);
            None
        }
    }

    pub(super) fn section(&mut self, title: &str, fields: Vec<Option<Field>>) {
        let fields: Vec<Field> = fields.into_iter().flatten().collect();
        if fields.is_empty() {
            return;
        }
        match random_id().and_then(|id| Section::new(id, title, fields)) {
            Ok(section) => self.sections.push(section),
            Err(error) => self.lost(Subject::Field(title.to_owned()), rejected(&error)),
        }
    }

    pub(super) fn tag(&mut self, text: &str) {
        match Tag::new(text) {
            Ok(tag) => self.tags.push(tag),
            Err(_) => self.lost(Subject::Tag(text.to_owned()), Reason::InvalidValue),
        }
    }

    pub(super) fn url(&mut self, raw: &str, mode: MatchMode) {
        let raw = raw.trim();
        if raw.is_empty() {
            return;
        }
        if let Some(app) = app_association(raw) {
            self.apps.push(app);
            return;
        }
        let (candidate, prefixed) = if raw.contains("://") {
            (raw.to_owned(), false)
        } else {
            (format!("https://{raw}"), true)
        };
        let entry =
            random_id().and_then(|id| UrlEntry::new(id, &candidate, mode, UrlKind::Website));
        match entry {
            Ok(entry) => {
                if self.urls.iter().any(|u| u.url() == entry.url()) {
                    return;
                }
                if prefixed {
                    self.approximated(Subject::Url(raw.to_owned()), Reason::InvalidValue);
                }
                self.urls.push(entry);
            }
            Err(_) => self.lost(Subject::Url(raw.to_owned()), Reason::InvalidValue),
        }
    }

    pub(super) fn history(&mut self, entries: Vec<(String, u64)>) {
        let field = self.password_field_id();
        let total = entries.len();
        for (value, at) in entries.into_iter().take(MAX_HISTORY) {
            let Ok(field) = field.map_or_else(random_id, Ok) else {
                return;
            };
            self.history.push(PasswordHistoryEntry {
                value: SecretString::from(value),
                replaced_at: at,
                field,
            });
        }
        if total > MAX_HISTORY {
            self.approximated(Subject::PasswordHistory, Reason::TooLarge);
        }
    }

    pub(super) fn finish(mut self) -> (Option<ImportItem>, ItemReport) {
        if self.template == "document" && self.files.is_empty() {
            "custom".clone_into(&mut self.template);
            self.approximated(
                Subject::Category("document".to_owned()),
                Reason::NotExportedBySource,
            );
        }
        let source_id = self.source_id.clone();
        let title = self.title.clone();
        let template = self.template.clone();
        let mut entries = std::mem::take(&mut self.entries);
        let files = std::mem::take(&mut self.files);
        let parts = ItemParts {
            kind: self.template,
            title: self.title,
            subtitle: self.subtitle,
            tags: self.tags,
            favourite: self.favourite,
            state: self.state,
            sections: self.sections,
            notes: self.notes,
            urls: self.urls,
            apps: self.apps,
            passkeys: self.passkeys,
            attachments: Vec::new(),
            password_history: self.history,
            client_modified: self.modified.max(self.created),
            created: self.created,
            expires_at: None,
        };
        match Item::new(parts) {
            Ok(item) => {
                let outcome = if entries.iter().any(|e| e.fate.is_loss()) {
                    Outcome::ImportedWithLoss
                } else {
                    Outcome::Imported
                };
                let report = ItemReport {
                    source_id: source_id.clone(),
                    title,
                    template: Some(template),
                    outcome,
                    entries,
                };
                let imported = ImportItem {
                    source_id,
                    item,
                    files,
                };
                (Some(imported), report)
            }
            Err(error) => {
                entries.push(Entry {
                    subject: Subject::Item,
                    fate: Fate::Lost {
                        reason: rejected(&error),
                    },
                });
                let report = ItemReport {
                    source_id,
                    title,
                    template: None,
                    outcome: Outcome::Skipped,
                    entries,
                };
                (None, report)
            }
        }
    }
}

pub(super) fn random_id() -> Result<Id, ModelError> {
    Id::random()
}

pub(super) fn rejected(error: &ModelError) -> Reason {
    Reason::Rejected(error.to_string())
}

pub(super) fn otp_from_text(text: &str) -> Result<OtpParams, OtpError> {
    let text = text.trim();
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("otpauth://") || lower.starts_with("steam://") {
        return uri::parse(text);
    }
    let secret: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    uri::parse(&format!("otpauth://totp/imported?secret={secret}"))
}

pub(super) fn mime_for(name: &str) -> String {
    const TYPES: [(&str, &str); 12] = [
        ("pdf", "application/pdf"),
        ("png", "image/png"),
        ("jpg", "image/jpeg"),
        ("jpeg", "image/jpeg"),
        ("gif", "image/gif"),
        ("txt", "text/plain"),
        ("json", "application/json"),
        ("zip", "application/zip"),
        ("csv", "text/csv"),
        ("doc", "application/msword"),
        ("heic", "image/heic"),
        ("md", "text/markdown"),
    ];
    let extension = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    TYPES
        .iter()
        .find(|(e, _)| Some(*e) == extension.as_deref())
        .map_or("application/octet-stream", |(_, m)| m)
        .to_owned()
}

fn app_association(raw: &str) -> Option<AppAssociation> {
    let (scheme, id) = raw.split_once("://")?;
    let platform = match scheme.to_ascii_lowercase().as_str() {
        "androidapp" => AppPlatform::Android,
        "iosapp" => AppPlatform::Ios,
        _ => return None,
    };
    let id = id.trim().to_owned();
    (!id.is_empty()).then_some(AppAssociation {
        platform,
        id,
        cert_sha256: None,
        source: AssocSource::User,
    })
}

pub(super) fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(text.len() / 4 * 3 + 3);
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    for byte in text.trim().bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b'\n' | b'\r' | b' ' => continue,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_standard_and_url_safe_base64() {
        assert_eq!(decode_base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode_base64("-_8").unwrap(), [0xfb, 0xff]);
        assert!(decode_base64("a$b").is_none());
    }

    #[test]
    fn otp_accepts_uri_and_bare_secret() {
        let bare = otp_from_text("JBSW Y3DP EHPK 3PXP").unwrap();
        let uri = otp_from_text("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(bare.expose_secret(), uri.expose_secret());
        assert!(otp_from_text("not base32 !").is_err());
    }
}
