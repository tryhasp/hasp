use secrecy::ExposeSecret;

use super::convert::{plain_text, secret_text};
use super::engine::Engine;
use super::provider::limit_of;
use super::{Secret, TextCandidate, TextQuery, ids};
use crate::CoreError;
use crate::model::field::{Field, FieldKind, FieldValue, Purpose, Section};
use crate::model::item::Item;
use crate::provider::IndexEntry;
use crate::store::Store;
use crate::transport::Transport;

const LOGIN: &str = "login";
const IDENTITY: &str = "identity";
const CARD: &str = "credit-card";
const USERNAME_FIELD: &str = "username";
const MAX_OPENED: usize = 12;

fn kind_offered(kind: &str) -> bool {
    matches!(kind, LOGIN | IDENTITY | CARD)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Offer {
    Plain,
    Concealed,
}

fn offer(kind: &str, field: &Field) -> Option<Offer> {
    let purpose = field.purpose();
    if kind == LOGIN {
        return (purpose == Some(Purpose::Username) && !field.is_concealed())
            .then_some(Offer::Plain);
    }
    match purpose {
        Some(
            Purpose::Password
            | Purpose::NewPassword
            | Purpose::Totp
            | Purpose::CardCvc
            | Purpose::ApiKey
            | Purpose::SshPrivateKey
            | Purpose::SshPublicKey,
        ) => None,
        Some(Purpose::CardNumber) if kind == CARD => Some(Offer::Concealed),
        _ if field.is_concealed() => None,
        None if kind == IDENTITY && field.kind() == FieldKind::Text => Some(Offer::Concealed),
        _ => match field.kind() {
            FieldKind::Text
            | FieldKind::Email
            | FieldKind::Phone
            | FieldKind::Date
            | FieldKind::MonthYear
            | FieldKind::Address
            | FieldKind::Menu => Some(Offer::Plain),
            _ => None,
        },
    }
}

fn masked(secret: &Secret) -> String {
    let text = String::from_utf8_lossy(secret.as_bytes());
    let digits: String = text.chars().filter(char::is_ascii_digit).collect();
    let tail: String = digits
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("\u{2022}\u{2022}\u{2022}\u{2022} {tail}")
}

fn matches_text(entry: &IndexEntry, text: &str) -> bool {
    let wanted = text.trim().to_lowercase();
    wanted.is_empty()
        || entry.title.to_lowercase().contains(&wanted)
        || entry.user.to_lowercase().contains(&wanted)
        || entry.kind.contains(&wanted)
}

fn candidates_of(entry: &IndexEntry, item: &Item) -> Vec<TextCandidate> {
    item.details()
        .sections
        .iter()
        .flat_map(Section::fields)
        .filter_map(|field| {
            let mode = offer(&entry.kind, field)?;
            if field.value().is_empty() {
                return None;
            }
            let preview = match mode {
                Offer::Plain => plain_text(field.value()).unwrap_or_default(),
                Offer::Concealed => masked(&secret_text(field)),
            };
            Some(TextCandidate {
                vault: entry.vault.clone(),
                item: entry.item.clone(),
                field: if entry.kind == LOGIN {
                    USERNAME_FIELD.to_owned()
                } else {
                    ids::hex(field.id().as_bytes())
                },
                item_title: entry.title.clone(),
                item_kind: entry.kind.clone(),
                label: field.label().to_owned(),
                purpose: field
                    .purpose()
                    .map(|p| super::convert::purpose_name(p).to_owned()),
                preview,
                concealed: mode == Offer::Concealed,
            })
        })
        .collect()
}

impl<T: Transport, S: Store> Engine<T, S> {
    /// Text-to-insert candidates (iOS 18): identity and card details and the user name of a
    /// login, never a password, one-time code, CVC, key or other concealed field. A card number
    /// is listed masked and released only by `text_value`. At most 12 items are opened, the best
    /// matches of `text` first; the rest of the vault stays sealed.
    pub async fn text_candidates(&self, query: TextQuery) -> Result<Vec<TextCandidate>, CoreError> {
        let mut client = self.client.lock().await;
        let index = Self::index_of(&mut client)?;
        let mut pool: Vec<&IndexEntry> = index
            .entries
            .iter()
            .filter(|e| e.is_active() && kind_offered(&e.kind) && matches_text(e, &query.text))
            .collect();
        pool.sort_by_key(|e| std::cmp::Reverse((e.favourite, e.modified)));
        let limit = limit_of(query.limit);
        let mut out = Vec::new();
        for entry in pool.into_iter().take(MAX_OPENED) {
            let (vault, item) = (ids::vault(&entry.vault)?, ids::item(&entry.item)?);
            let Ok(loaded) = client.item(&vault, &item) else {
                continue;
            };
            out.extend(candidates_of(entry, &loaded));
            if out.len() >= limit {
                break;
            }
        }
        out.truncate(limit);
        Ok(out)
    }

    /// The value of one offered candidate. A field the policy does not offer is refused, so a
    /// caller cannot read a password through this call. `field` is the candidate's `field`.
    pub async fn text_value(
        &self,
        vault: &str,
        item: &str,
        field: &str,
    ) -> Result<Secret, CoreError> {
        let (vault_id, item_id) = (ids::vault(vault)?, ids::item(item)?);
        let client = self.client.lock().await;
        let loaded = client.item(&vault_id, &item_id)?;
        if !loaded.overview().state.is_active() {
            return Err(CoreError::Refused("item is not active"));
        }
        let kind = loaded.overview().kind.clone();
        if !kind_offered(&kind) {
            return Err(CoreError::Refused("this item has no text to insert"));
        }
        let wanted = (field != USERNAME_FIELD)
            .then(|| ids::item(field))
            .transpose()?;
        let chosen = loaded
            .details()
            .sections
            .iter()
            .flat_map(Section::fields)
            .find(|f| match &wanted {
                Some(id) => f.id().as_bytes() == id.as_bytes(),
                None => f.purpose() == Some(Purpose::Username),
            })
            .ok_or(CoreError::NotFound("field"))?;
        offer(&kind, chosen).ok_or(CoreError::Refused("this field is never inserted as text"))?;
        if let FieldValue::Concealed(secret) = chosen.value()
            && secret.expose_secret().is_empty()
        {
            return Err(CoreError::NotFound("field"));
        }
        Ok(secret_text(chosen))
    }
}
