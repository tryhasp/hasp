use hasp_proto::base64url;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::CoreError;
use crate::model::field::{FieldValue, Purpose, Section};
use crate::model::item::{Item, ItemState};
use crate::model::url::MatchMode;

const INDEX_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexUrl {
    pub host: String,
    pub port: Option<u16>,
    pub mode: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexPasskey {
    pub credential_id: String,
    pub rp_id: String,
    pub user_name: String,
    pub display_name: String,
    pub user_handle: String,
    pub created: u64,
    pub last_used: Option<u64>,
}

/// Metadata of one item, enough to answer every provider question that has no secret in the
/// answer. It carries no password, no OTP seed and no passkey private key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    pub vault: String,
    pub item: String,
    pub stamp: String,
    pub kind: String,
    pub title: String,
    pub user: String,
    pub urls: Vec<IndexUrl>,
    pub favourite: bool,
    pub state: u8,
    pub modified: u64,
    pub has_totp: bool,
    #[serde(default)]
    pub has_password: bool,
    pub passkeys: Vec<IndexPasskey>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    version: u32,
    pub entries: Vec<IndexEntry>,
}

pub(crate) fn mode_text(mode: MatchMode) -> &'static str {
    match mode {
        MatchMode::Domain => "domain",
        MatchMode::Host => "host",
        MatchMode::Never => "never",
    }
}

pub(crate) fn mode_of(text: &str) -> MatchMode {
    match text {
        "host" => MatchMode::Host,
        "never" => MatchMode::Never,
        _ => MatchMode::Domain,
    }
}

fn username_of(item: &Item) -> String {
    item.details()
        .sections
        .iter()
        .flat_map(Section::fields)
        .find(|field| field.purpose() == Some(Purpose::Username))
        .and_then(|field| match field.value() {
            FieldValue::Text(text) | FieldValue::Email(text) => Some(text.clone()),
            FieldValue::Concealed(secret) => Some(secret.expose_secret().to_owned()),
            _ => None,
        })
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| item.overview().subtitle.clone())
}

fn has_password(item: &Item) -> bool {
    item.details()
        .sections
        .iter()
        .flat_map(Section::fields)
        .any(|field| field.purpose() == Some(Purpose::Password) && !field.value().is_empty())
}

pub fn entry_of(vault: &str, item_id: &str, stamp: &str, item: &Item) -> IndexEntry {
    let overview = item.overview();
    IndexEntry {
        vault: vault.to_owned(),
        item: item_id.to_owned(),
        stamp: stamp.to_owned(),
        kind: overview.kind.clone(),
        title: overview.title.clone(),
        user: username_of(item),
        urls: overview
            .urls
            .iter()
            .map(|url| IndexUrl {
                host: url.host.clone(),
                port: url.port,
                mode: mode_text(url.mode).to_owned(),
            })
            .collect(),
        favourite: overview.favourite.is_some(),
        state: match overview.state {
            ItemState::Active => 0,
            ItemState::Archived { .. } => 1,
            ItemState::Trashed { .. } => 2,
        },
        modified: overview.client_modified,
        has_totp: overview.flags.has_totp,
        has_password: has_password(item),
        passkeys: item
            .details()
            .passkeys
            .iter()
            .map(|passkey| IndexPasskey {
                credential_id: base64url::encode(&passkey.credential_id),
                rp_id: passkey.rp_id.clone(),
                user_name: passkey.user_name.clone(),
                display_name: passkey.display_name.clone(),
                user_handle: base64url::encode(&passkey.user_handle),
                created: passkey.created,
                last_used: passkey.last_used,
            })
            .collect(),
    }
}

impl Index {
    pub fn new(entries: Vec<IndexEntry>) -> Self {
        Self {
            version: INDEX_VERSION,
            entries,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, CoreError> {
        serde_json::to_vec(self).map_err(|_| CoreError::Internal("provider index"))
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        serde_json::from_slice::<Self>(raw)
            .ok()
            .filter(|index| index.version == INDEX_VERSION)
    }
}

impl IndexEntry {
    pub fn hidden(vault: &str, item: &str, stamp: &str, kind: &str) -> Self {
        Self {
            vault: vault.to_owned(),
            item: item.to_owned(),
            stamp: stamp.to_owned(),
            kind: kind.to_owned(),
            title: String::new(),
            user: String::new(),
            urls: Vec::new(),
            favourite: false,
            state: 0,
            modified: 0,
            has_totp: false,
            has_password: false,
            passkeys: Vec::new(),
        }
    }

    pub fn is_active(&self) -> bool {
        self.state == 0
    }
}
