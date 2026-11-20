use std::collections::BTreeSet;
use std::fmt;

use hasp_crypto::SecretKey;
use secrecy::{SecretSlice, SecretString};

use crate::model::ModelError;
use crate::model::field::{Field, FieldKind, Section};
use crate::model::id::Id;
use crate::model::tag::Tag;
use crate::model::url::{UrlEntry, UrlSummary};

pub const PAYLOAD_VERSION: u32 = hasp_proto::payload::PAYLOAD_VERSION;
pub const TRASH_RETENTION_S: u64 = 30 * 24 * 60 * 60;
pub const NONCE_PREFIX_LEN: usize = 15;
const MAX_TITLE_BYTES: usize = 1024;
const MAX_NOTES_BYTES: usize = 256 * 1024;
const MAX_TAGS: usize = 64;
const MAX_URLS: usize = 64;
const MAX_SECTIONS: usize = 64;
const MAX_FIELDS: usize = 1024;
const MAX_PASSKEYS: usize = 32;
const MAX_ATTACHMENTS: usize = 256;
const MAX_HISTORY: usize = 100;
const MAX_APPS: usize = 64;
const MAX_NAME_BYTES: usize = 1024;

pub type Time = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemState {
    Active,
    Archived { at: Time },
    Trashed { at: Time },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags {
    pub has_totp: bool,
    pub has_passkey: bool,
    pub has_attachments: bool,
}

#[derive(Debug)]
pub struct Overview {
    pub pv: u32,
    pub kind: String,
    pub title: String,
    pub subtitle: String,
    pub urls: Vec<UrlSummary>,
    pub tags: Vec<Tag>,
    pub favourite: Option<u32>,
    pub state: ItemState,
    pub flags: Flags,
    pub client_modified: Time,
    pub created: Time,
    pub expires_at: Option<Time>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppPlatform {
    Ios,
    Android,
    Macos,
    Windows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssocSource {
    User,
    Dataset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppAssociation {
    pub platform: AppPlatform,
    pub id: String,
    pub cert_sha256: Option<[u8; 32]>,
    pub source: AssocSource,
}

#[derive(Debug)]
pub struct Passkey {
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub display_name: String,
    pub algorithm: i32,
    pub private_key: SecretSlice<u8>,
    pub created: Time,
    pub last_used: Option<Time>,
    pub backup_eligible: bool,
    pub backed_up: bool,
}

#[derive(Debug)]
pub struct AttachmentDesc {
    pub att_id: Id,
    pub file_key: SecretKey,
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
    pub size: u64,
    pub chunk_size: u32,
    pub name: String,
    pub mime: String,
}

#[derive(Debug)]
pub struct PasswordHistoryEntry {
    pub value: SecretString,
    pub replaced_at: Time,
    pub field: Id,
}

pub struct Details {
    pub pv: u32,
    pub sections: Vec<Section>,
    pub notes: Option<String>,
    pub urls: Vec<UrlEntry>,
    pub apps: Vec<AppAssociation>,
    pub passkeys: Vec<Passkey>,
    pub attachments: Vec<AttachmentDesc>,
    pub password_history: Vec<PasswordHistoryEntry>,
}

pub struct ItemParts {
    pub kind: String,
    pub title: String,
    pub subtitle: String,
    pub tags: Vec<Tag>,
    pub favourite: Option<u32>,
    pub state: ItemState,
    pub sections: Vec<Section>,
    pub notes: Option<String>,
    pub urls: Vec<UrlEntry>,
    pub apps: Vec<AppAssociation>,
    pub passkeys: Vec<Passkey>,
    pub attachments: Vec<AttachmentDesc>,
    pub password_history: Vec<PasswordHistoryEntry>,
    pub client_modified: Time,
    pub created: Time,
    pub expires_at: Option<Time>,
}

#[derive(Debug)]
pub struct Item {
    overview: Overview,
    details: Details,
}

impl ItemState {
    pub fn is_active(self) -> bool {
        self == Self::Active
    }

    pub fn purge_due(self, now: Time) -> bool {
        match self {
            Self::Trashed { at } => now.saturating_sub(at) > TRASH_RETENTION_S,
            Self::Active | Self::Archived { .. } => false,
        }
    }
}

impl fmt::Debug for Details {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Details")
            .field("sections", &self.sections.len())
            .field("urls", &self.urls.len())
            .field("attachments", &self.attachments.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ItemParts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemParts")
            .field("kind", &self.kind)
            .field("sections", &self.sections.len())
            .finish_non_exhaustive()
    }
}

impl Item {
    pub fn new(parts: ItemParts) -> Result<Self, ModelError> {
        let details = Details {
            pv: PAYLOAD_VERSION,
            sections: parts.sections,
            notes: parts.notes,
            urls: parts.urls,
            apps: parts.apps,
            passkeys: parts.passkeys,
            attachments: parts.attachments,
            password_history: parts.password_history,
        };
        let overview = Overview {
            pv: PAYLOAD_VERSION,
            kind: parts.kind,
            title: parts.title,
            subtitle: parts.subtitle,
            urls: summaries(&details.urls),
            tags: dedupe(parts.tags),
            favourite: parts.favourite,
            state: parts.state,
            flags: flags(&details),
            client_modified: parts.client_modified,
            created: parts.created,
            expires_at: parts.expires_at,
        };
        Self::assemble(overview, details)
    }

    pub fn assemble(overview: Overview, details: Details) -> Result<Self, ModelError> {
        if overview.pv != PAYLOAD_VERSION || details.pv != PAYLOAD_VERSION {
            return Err(ModelError::Item("unsupported payload version"));
        }
        if overview.kind.is_empty() || overview.kind.len() > MAX_NAME_BYTES {
            return Err(ModelError::Item("kind"));
        }
        if overview.title.len() > MAX_TITLE_BYTES || overview.subtitle.len() > MAX_TITLE_BYTES {
            return Err(ModelError::Item("title too long"));
        }
        if overview.tags.len() > MAX_TAGS {
            return Err(ModelError::Item("too many tags"));
        }
        if details
            .notes
            .as_ref()
            .is_some_and(|n| n.len() > MAX_NOTES_BYTES)
        {
            return Err(ModelError::Item("notes too long"));
        }
        check_counts(&details)?;
        check_unique_ids(&details)?;
        if overview.urls != summaries(&details.urls) || overview.flags != flags(&details) {
            return Err(ModelError::Item("overview does not match details"));
        }
        Ok(Self { overview, details })
    }

    pub fn overview(&self) -> &Overview {
        &self.overview
    }

    pub fn details(&self) -> &Details {
        &self.details
    }

    pub fn into_parts(self) -> ItemParts {
        ItemParts {
            kind: self.overview.kind,
            title: self.overview.title,
            subtitle: self.overview.subtitle,
            tags: self.overview.tags,
            favourite: self.overview.favourite,
            state: self.overview.state,
            sections: self.details.sections,
            notes: self.details.notes,
            urls: self.details.urls,
            apps: self.details.apps,
            passkeys: self.details.passkeys,
            attachments: self.details.attachments,
            password_history: self.details.password_history,
            client_modified: self.overview.client_modified,
            created: self.overview.created,
            expires_at: self.overview.expires_at,
        }
    }

    #[must_use]
    pub fn with_state(mut self, state: ItemState, modified: Time) -> Self {
        self.overview.state = state;
        self.overview.client_modified = modified;
        self
    }

    #[must_use]
    pub fn with_favourite(mut self, favourite: Option<u32>, modified: Time) -> Self {
        self.overview.favourite = favourite;
        self.overview.client_modified = modified;
        self
    }
}

fn summaries(urls: &[UrlEntry]) -> Vec<UrlSummary> {
    urls.iter().filter_map(UrlEntry::summary).collect()
}

fn flags(details: &Details) -> Flags {
    Flags {
        has_totp: details
            .sections
            .iter()
            .flat_map(Section::fields)
            .any(|f| f.kind() == FieldKind::Otp),
        has_passkey: !details.passkeys.is_empty(),
        has_attachments: !details.attachments.is_empty(),
    }
}

fn dedupe(tags: Vec<Tag>) -> Vec<Tag> {
    let mut seen = BTreeSet::new();
    tags.into_iter()
        .filter(|t| seen.insert(t.key().to_owned()))
        .collect()
}

fn check_counts(details: &Details) -> Result<(), ModelError> {
    let fields: usize = details.sections.iter().map(|s| s.fields().len()).sum();
    let within = details.sections.len() <= MAX_SECTIONS
        && fields <= MAX_FIELDS
        && details.urls.len() <= MAX_URLS
        && details.apps.len() <= MAX_APPS
        && details.passkeys.len() <= MAX_PASSKEYS
        && details.attachments.len() <= MAX_ATTACHMENTS
        && details.password_history.len() <= MAX_HISTORY;
    if within {
        Ok(())
    } else {
        Err(ModelError::Item("collection too large"))
    }
}

fn check_unique_ids(details: &Details) -> Result<(), ModelError> {
    let mut seen = BTreeSet::new();
    let section_and_field_ids = details
        .sections
        .iter()
        .flat_map(|s| std::iter::once(s.id()).chain(s.fields().iter().map(Field::id)));
    let ids = section_and_field_ids
        .chain(details.urls.iter().map(UrlEntry::id))
        .chain(details.attachments.iter().map(|a| a.att_id));
    for id in ids {
        if !seen.insert(id) {
            return Err(ModelError::Item("duplicate id"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;
    use crate::model::field::{Field, FieldValue, Purpose};
    use crate::model::url::{MatchMode, UrlKind};
    use crate::otp::{OtpAlg, OtpKind, OtpParams};

    fn id(n: u8) -> Id {
        Id::from_bytes([n; 16])
    }

    fn parts() -> ItemParts {
        ItemParts {
            kind: "login".to_owned(),
            title: "Example".to_owned(),
            subtitle: "alice".to_owned(),
            tags: vec![
                Tag::new("Work").unwrap(),
                Tag::new("work").unwrap(),
                Tag::new("Home").unwrap(),
            ],
            favourite: Some(2),
            state: ItemState::Active,
            sections: Vec::new(),
            notes: Some("# notes".to_owned()),
            urls: vec![
                UrlEntry::new(
                    id(10),
                    "https://example.com:8443/in",
                    MatchMode::Host,
                    UrlKind::SignIn,
                )
                .unwrap(),
            ],
            apps: Vec::new(),
            passkeys: Vec::new(),
            attachments: Vec::new(),
            password_history: Vec::new(),
            client_modified: 100,
            created: 50,
            expires_at: None,
        }
    }

    fn otp_section() -> Section {
        let otp =
            OtpParams::new(b"secret", OtpKind::Totp { period_s: 30 }, OtpAlg::Sha1, 6).unwrap();
        let field = Field::new(id(2), "otp", FieldValue::Otp(otp))
            .unwrap()
            .with_purpose(Purpose::Totp)
            .unwrap();
        Section::new(id(1), "", vec![field]).unwrap()
    }

    fn attachment(n: u8) -> AttachmentDesc {
        AttachmentDesc {
            att_id: id(n),
            file_key: SecretKey::from_bytes([n; 32]),
            nonce_prefix: [n; NONCE_PREFIX_LEN],
            size: 10,
            chunk_size: 1 << 20,
            name: "a.pdf".to_owned(),
            mime: "application/pdf".to_owned(),
        }
    }

    #[test]
    fn overview_is_derived_from_details() {
        let mut p = parts();
        p.sections = vec![otp_section()];
        p.attachments = vec![attachment(20)];
        let item = Item::new(p).unwrap();
        let overview = item.overview();
        assert_eq!(overview.urls.len(), 1);
        assert_eq!(overview.urls[0].host, "example.com");
        assert_eq!(overview.urls[0].port, Some(8443));
        assert_eq!(overview.urls[0].mode, MatchMode::Host);
        assert_eq!(
            overview.flags,
            Flags {
                has_totp: true,
                has_passkey: false,
                has_attachments: true
            }
        );
        assert_eq!(overview.tags.len(), 2);
        assert_eq!(overview.tags[0].as_str(), "Work");
        assert_eq!(overview.pv, PAYLOAD_VERSION);
    }

    #[test]
    fn passkeys_set_the_passkey_flag() {
        let mut p = parts();
        p.passkeys = vec![Passkey {
            credential_id: vec![1],
            rp_id: "example.com".to_owned(),
            user_handle: vec![2],
            user_name: "alice".to_owned(),
            display_name: "Alice".to_owned(),
            algorithm: -7,
            private_key: SecretSlice::from(vec![9, 9]),
            created: 1,
            last_used: None,
            backup_eligible: true,
            backed_up: false,
        }];
        assert!(Item::new(p).unwrap().overview().flags.has_passkey);
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let mut p = parts();
        p.sections = vec![otp_section()];
        p.urls = vec![
            UrlEntry::new(id(2), "https://a.com", MatchMode::Domain, UrlKind::Website).unwrap(),
        ];
        assert!(Item::new(p).is_err());
        let mut p = parts();
        p.attachments = vec![attachment(30), attachment(30)];
        assert!(Item::new(p).is_err());
    }

    #[test]
    fn limits_and_versions_are_enforced() {
        let mut p = parts();
        p.title = "x".repeat(1025);
        assert!(Item::new(p).is_err());
        let mut p = parts();
        p.kind = String::new();
        assert!(Item::new(p).is_err());
        let mut p = parts();
        p.notes = Some("x".repeat(256 * 1024 + 1));
        assert!(Item::new(p).is_err());
        let mut p = parts();
        p.tags = (0..65)
            .map(|n| Tag::new(&format!("t{n}")).unwrap())
            .collect();
        assert!(Item::new(p).is_err());
        let mut p = parts();
        p.password_history = (0..101u8)
            .map(|n| PasswordHistoryEntry {
                value: SecretString::from("old"),
                replaced_at: 1,
                field: id(n),
            })
            .collect();
        assert!(Item::new(p).is_err());
    }

    #[test]
    fn assemble_rejects_an_inconsistent_overview() {
        let item = Item::new(parts()).unwrap();
        let mut p = item.into_parts();
        let details_urls = std::mem::take(&mut p.urls);
        let rebuilt = Item::new(ItemParts {
            urls: Vec::new(),
            ..p
        })
        .unwrap();
        let ItemParts { .. } = ItemParts {
            urls: details_urls,
            ..rebuilt.into_parts()
        };
        let a = Item::new(parts()).unwrap();
        let b = Item::new(ItemParts {
            urls: Vec::new(),
            ..parts()
        })
        .unwrap();
        let (a_parts, b_parts) = (a.into_parts(), b.into_parts());
        let overview_with_urls = Item::new(a_parts).unwrap();
        let details_without = Item::new(b_parts).unwrap();
        let Item { overview, .. } = overview_with_urls;
        let Item { details, .. } = details_without;
        assert!(Item::assemble(overview, details).is_err());
    }

    #[test]
    fn assemble_round_trips_a_valid_pair() {
        let item = Item::new(parts()).unwrap();
        let Item { overview, details } = item;
        assert!(Item::assemble(overview, details).is_ok());
    }

    #[test]
    fn unknown_payload_versions_are_refused() {
        let Item {
            mut overview,
            details,
        } = Item::new(parts()).unwrap();
        overview.pv = 2;
        assert!(Item::assemble(overview, details).is_err());
    }

    #[test]
    fn into_parts_round_trips_and_state_changes_touch_the_item() {
        let item = Item::new(parts()).unwrap();
        let item = Item::new(item.into_parts()).unwrap();
        let trashed = item.with_state(ItemState::Trashed { at: 500 }, 501);
        assert_eq!(trashed.overview().state, ItemState::Trashed { at: 500 });
        assert_eq!(trashed.overview().client_modified, 501);
        let favourite = trashed.with_favourite(None, 502);
        assert_eq!(favourite.overview().favourite, None);
    }

    #[test]
    fn trash_is_purgeable_after_thirty_days() {
        let at = 1_000;
        let trashed = ItemState::Trashed { at };
        assert!(!trashed.purge_due(at + TRASH_RETENTION_S));
        assert!(trashed.purge_due(at + TRASH_RETENTION_S + 1));
        assert!(!ItemState::Archived { at }.purge_due(u64::MAX));
        assert!(!ItemState::Active.purge_due(u64::MAX));
        assert!(!trashed.purge_due(0));
        assert!(ItemState::Active.is_active() && !trashed.is_active());
    }

    #[test]
    fn debug_hides_secrets_and_notes() {
        let mut p = parts();
        p.notes = Some("private note".to_owned());
        p.password_history = vec![PasswordHistoryEntry {
            value: SecretString::from("hunter2"),
            replaced_at: 1,
            field: id(3),
        }];
        let item = Item::new(p).unwrap();
        let text = format!("{item:?} {:?}", item.details().password_history);
        assert!(!text.contains("private note") && !text.contains("hunter2"));
        assert_eq!(
            item.details().password_history[0].value.expose_secret(),
            "hunter2"
        );
    }
}
