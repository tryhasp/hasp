use std::collections::BTreeMap;

use hasp_crypto::sha256;
use hasp_proto::base64url;

use super::convert::secret_text;
use super::engine::Engine;
use super::fill::{policy_of, tier_of};
use super::{
    Candidate, CredentialIdentity, IdentityDiff, IdentityKind, ItemRow, ItemStatus,
    PasskeyCandidate, ProviderFillCheck, ProviderPasskeyQuery, ProviderPassword, ProviderQuery,
    SearchQuery, ids, search,
};
use crate::CoreError;
use crate::client::Client;
use crate::matcher::origin::Origin;
use crate::matcher::policy::{Fill, MatchLevel};
use crate::matcher::psl::PublicSuffixList;
use crate::model::field::{Purpose, Section};
use crate::model::id::Id;
use crate::model::url::{MatchMode, UrlEntry, UrlKind};
use crate::provider::{Index, IndexEntry, IndexPasskey, mode_of};
use crate::store::Store;
use crate::transport::Transport;
use crate::webauthn::check_relying_party;

const SNAPSHOT: &str = "identity-snapshot";
const LOGIN: &str = "login";
const DEFAULT_LIMIT: usize = 50;
const MAX_CREDENTIAL_ID: usize = 1023;
const MAX_USER_HANDLE: usize = 64;
const MAX_TEXT: usize = 1024;

type Best = (MatchLevel, Fill, Option<String>);

pub(super) fn limit_of(limit: u32) -> usize {
    if limit == 0 {
        DEFAULT_LIMIT
    } else {
        usize::try_from(limit).unwrap_or(DEFAULT_LIMIT)
    }
}

fn entry_urls(entry: &IndexEntry) -> Vec<UrlEntry> {
    entry
        .urls
        .iter()
        .filter_map(|url| {
            let port = url.port.map(|p| format!(":{p}")).unwrap_or_default();
            UrlEntry::new(
                Id::from_bytes([0; 16]),
                &format!("https://{}{port}/", url.host),
                mode_of(&url.mode),
                UrlKind::Website,
            )
            .ok()
        })
        .collect()
}

fn row_of_entry(entry: &IndexEntry) -> ItemRow {
    ItemRow {
        vault: entry.vault.clone(),
        id: entry.item.clone(),
        kind: entry.kind.clone(),
        title: entry.title.clone(),
        subtitle: entry.user.clone(),
        hosts: entry.urls.iter().map(|u| u.host.clone()).collect(),
        tags: Vec::new(),
        favourite: entry.favourite,
        status: match entry.state {
            0 => ItemStatus::Active,
            1 => ItemStatus::Archived,
            _ => ItemStatus::Trashed,
        },
        has_totp: entry.has_totp,
        has_passkey: !entry.passkeys.is_empty(),
        has_attachments: false,
        modified: entry.modified,
        created: 0,
        expires_at: None,
        pending: false,
        version: 0,
    }
}

fn identity_hash(identity: &CredentialIdentity) -> String {
    let kind = match identity.kind {
        IdentityKind::Password => "p",
        IdentityKind::OneTimeCode => "o",
        IdentityKind::Passkey => "k",
    };
    let favourite = if identity.favourite { "1" } else { "0" };
    let parts: [&[u8]; 8] = [
        kind.as_bytes(),
        identity.service.as_bytes(),
        identity.user.as_bytes(),
        identity.title.as_bytes(),
        favourite.as_bytes(),
        identity.credential_id.as_deref().unwrap_or("").as_bytes(),
        identity.user_handle.as_deref().unwrap_or("").as_bytes(),
        identity.record.as_bytes(),
    ];
    let mut framed = Vec::new();
    for part in parts {
        framed.extend_from_slice(&(part.len() as u64).to_be_bytes());
        framed.extend_from_slice(part);
    }
    hasp_crypto::to_hex(&sha256(&[&framed]))
}

fn valid_service(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_TEXT
        && Origin::parse(&format!("https://{host}"))
            .is_ok_and(|origin| origin.check_fillable().is_ok())
}

fn valid_passkey(psl: &PublicSuffixList, passkey: &IndexPasskey) -> bool {
    check_relying_party(psl, &passkey.rp_id).is_ok_and(|rp| rp == passkey.rp_id)
        && base64url::decode(&passkey.credential_id)
            .is_some_and(|id| (1..=MAX_CREDENTIAL_ID).contains(&id.len()))
        && base64url::decode(&passkey.user_handle)
            .is_some_and(|handle| (1..=MAX_USER_HANDLE).contains(&handle.len()))
        && passkey.user_name.len() <= MAX_TEXT
}

fn identities_of(index: &Index, psl: &PublicSuffixList) -> (Vec<CredentialIdentity>, u32) {
    let mut out = Vec::new();
    let mut skipped = 0_u32;
    for entry in index.entries.iter().filter(|e| e.is_active()) {
        let hosts: Vec<&str> = {
            let mut hosts: Vec<&str> = entry
                .urls
                .iter()
                .filter(|u| mode_of(&u.mode) != MatchMode::Never)
                .map(|u| u.host.as_str())
                .collect();
            hosts.sort_unstable();
            hosts.dedup();
            let before = hosts.len();
            hosts.retain(|host| valid_service(host));
            skipped =
                skipped.saturating_add(u32::try_from(before - hosts.len()).unwrap_or(u32::MAX));
            hosts
        };
        if entry.title.len() > MAX_TEXT || entry.user.len() > MAX_TEXT {
            skipped = skipped.saturating_add(1);
            continue;
        }
        let base = |record: String, kind, service: &str| CredentialIdentity {
            record,
            kind,
            vault: entry.vault.clone(),
            item: entry.item.clone(),
            service: service.to_owned(),
            user: entry.user.clone(),
            title: entry.title.clone(),
            favourite: entry.favourite,
            credential_id: None,
            user_handle: None,
        };
        for host in &hosts {
            if entry.kind == LOGIN && entry.has_password {
                out.push(base(
                    format!("p:{}:{}:{host}", entry.vault, entry.item),
                    IdentityKind::Password,
                    host,
                ));
            }
            if entry.has_totp {
                out.push(base(
                    format!("o:{}:{}:{host}", entry.vault, entry.item),
                    IdentityKind::OneTimeCode,
                    host,
                ));
            }
        }
        for passkey in &entry.passkeys {
            if !valid_passkey(psl, passkey) {
                skipped = skipped.saturating_add(1);
                continue;
            }
            let mut identity = base(
                format!("k:{}:{}:{}", entry.vault, entry.item, passkey.credential_id),
                IdentityKind::Passkey,
                &passkey.rp_id,
            );
            identity.user.clone_from(&passkey.user_name);
            identity.credential_id = Some(passkey.credential_id.clone());
            identity.user_handle = Some(passkey.user_handle.clone());
            out.push(identity);
        }
    }
    out.sort_by(|a, b| a.record.cmp(&b.record));
    (out, skipped)
}

fn fingerprint_of(hashes: &BTreeMap<String, String>) -> String {
    let mut framed = Vec::new();
    for (record, hash) in hashes {
        framed.extend_from_slice(record.as_bytes());
        framed.push(0);
        framed.extend_from_slice(hash.as_bytes());
        framed.push(0);
    }
    hasp_crypto::to_hex(&sha256(&[&framed]))
}

fn hashes_of(identities: &[CredentialIdentity]) -> BTreeMap<String, String> {
    identities
        .iter()
        .map(|identity| (identity.record.clone(), identity_hash(identity)))
        .collect()
}

impl<T: Transport, S: Store> Engine<T, S> {
    pub(super) async fn refresh_provider_index(&self) {
        let mut client = self.client.lock().await;
        let _best_effort = client.provider_index();
    }

    pub(super) fn index_of(client: &mut Client<T, S>) -> Result<Index, CoreError> {
        client.require_unlocked()?;
        client.provider_index()
    }

    #[cfg(feature = "testing")]
    pub async fn items_opened_for_tests(&self) -> u64 {
        self.client.lock().await.items_opened()
    }

    #[cfg(feature = "testing")]
    pub async fn drop_provider_index_for_tests(&self) -> Result<(), CoreError> {
        self.client.lock().await.drop_provider_index_for_tests()
    }

    /// Unlocks for an autofill extension: the biometric-gated device key through the platform
    /// store, no Argon2 and no network. The password-every-N-days rule still applies.
    pub async fn provider_unlock(&self) -> Result<(), CoreError> {
        let mut client = self.client.lock().await;
        if Self::password_due(&client) {
            return Err(CoreError::Refused("password required"));
        }
        client.unlock_provider(&Self::token()).await?;
        if let Err(error) = Self::ensure_password_not_due(&client) {
            client.lock();
            return Err(error);
        }
        Self::note_time(&mut client)?;
        self.emit(super::EventKind::Unlocked);
        Ok(())
    }

    /// Builds or refreshes the sealed metadata index. The app calls it after sync (`sync` does
    /// it already) so an extension finds it current and opens no other item.
    pub async fn provider_index_refresh(&self) -> Result<u32, CoreError> {
        let mut client = self.client.lock().await;
        let index = Self::index_of(&mut client)?;
        Ok(u32::try_from(index.entries.len()).unwrap_or(u32::MAX))
    }

    /// Metadata-only identities for `ASCredentialIdentityStore`, compared with the set the app
    /// last confirmed through `identity_ack`. When `changed` is false nothing needs replacing.
    pub async fn identity_diff(&self) -> Result<IdentityDiff, CoreError> {
        let mut client = self.client.lock().await;
        let (identities, skipped) =
            identities_of(&Self::index_of(&mut client)?, self.matcher.psl());
        let current = hashes_of(&identities);
        let previous = Self::snapshot(&client);
        let fingerprint = fingerprint_of(&current);
        let known = previous.as_ref().map(fingerprint_of);
        if known.as_deref() == Some(fingerprint.as_str()) {
            return Ok(IdentityDiff {
                changed: false,
                fingerprint,
                identities: Vec::new(),
                skipped,
                added: Vec::new(),
                updated: Vec::new(),
                removed: Vec::new(),
            });
        }
        let previous = previous.unwrap_or_default();
        let mut added = Vec::new();
        let mut updated = Vec::new();
        for (record, hash) in &current {
            match previous.get(record) {
                None => added.push(record.clone()),
                Some(old) if old != hash => updated.push(record.clone()),
                Some(_) => {}
            }
        }
        let removed = previous
            .keys()
            .filter(|record| !current.contains_key(*record))
            .cloned()
            .collect();
        Ok(IdentityDiff {
            changed: true,
            fingerprint,
            identities,
            skipped,
            added,
            updated,
            removed,
        })
    }

    /// Records that the system store now holds the set `identity_diff` returned. A fingerprint
    /// that no longer matches the vault is refused: fetch the diff again.
    pub async fn identity_ack(&self, fingerprint: &str) -> Result<(), CoreError> {
        let mut client = self.client.lock().await;
        let (identities, _) = identities_of(&Self::index_of(&mut client)?, self.matcher.psl());
        let current = hashes_of(&identities);
        if fingerprint_of(&current) != fingerprint {
            return Err(CoreError::Conflict("the identity set changed"));
        }
        let raw = serde_json::to_vec(&current).map_err(|_| CoreError::Internal("snapshot"))?;
        client.local_note_put(SNAPSHOT, &raw)
    }

    fn snapshot(client: &Client<T, S>) -> Option<BTreeMap<String, String>> {
        client
            .local_note_get(SNAPSHOT)
            .ok()
            .flatten()
            .and_then(|raw| serde_json::from_slice(raw.expose()).ok())
    }

    /// The password list of an extension, from the index only. Service identifiers are hosts or
    /// URLs from the system; with none, every login is listed.
    pub async fn provider_candidates(
        &self,
        query: ProviderQuery,
    ) -> Result<Vec<Candidate>, CoreError> {
        let mut client = self.client.lock().await;
        let index = Self::index_of(&mut client)?;
        let logins: Vec<&IndexEntry> = index
            .entries
            .iter()
            .filter(|e| e.is_active() && e.kind == LOGIN && e.has_password)
            .collect();
        let mut best: BTreeMap<usize, Best> = BTreeMap::new();
        let mut pages = Vec::new();
        for identifier in &query.identifiers {
            let text = if identifier.contains("://") {
                identifier.clone()
            } else {
                format!("https://{identifier}")
            };
            if let Ok(page) = Origin::parse(&text)
                && page.check_fillable().is_ok()
            {
                pages.push(page);
            }
        }
        if query.identifiers.is_empty() {
            let mut all: Vec<Candidate> = logins.iter().map(|e| candidate_of(e, None)).collect();
            all.sort_by(|a, b| {
                (!a.favourite, a.title.to_lowercase()).cmp(&(!b.favourite, b.title.to_lowercase()))
            });
            all.truncate(limit_of(query.limit));
            return Ok(all);
        }
        for page in &pages {
            let keyed: Vec<(usize, Vec<UrlEntry>)> = logins
                .iter()
                .enumerate()
                .map(|(position, entry)| (position, entry_urls(entry)))
                .collect();
            for ranked in self.matcher.rank_items(page, &keyed) {
                let host = (ranked.result.fill == Fill::ConfirmFirst).then(|| page.host_string());
                let slot = best.entry(ranked.key).or_insert((
                    ranked.result.level,
                    ranked.result.fill,
                    host.clone(),
                ));
                if (ranked.result.level, ranked.result.fill) > (slot.0, slot.1) {
                    *slot = (ranked.result.level, ranked.result.fill, host);
                }
            }
        }
        let mut found: Vec<(usize, Best)> = best.into_iter().collect();
        found.sort_by_key(|(position, (level, fill, _))| {
            let entry = logins[*position];
            std::cmp::Reverse((*level, *fill, entry.favourite, entry.modified))
        });
        Ok(found
            .into_iter()
            .take(limit_of(query.limit))
            .filter_map(|(position, (level, fill, host))| {
                let tier = tier_of(level)?;
                let mut candidate = candidate_of(logins[position], Some(policy_of(fill)));
                candidate.tier = tier;
                candidate.host_to_confirm = host;
                Some(candidate)
            })
            .collect())
    }

    /// The manual list and search of the extension UI, ranked like the app's search. It reads
    /// the index, so `tags` is empty and `has_attachments` is false in every row.
    pub async fn provider_list(&self, query: SearchQuery) -> Result<Vec<ItemRow>, CoreError> {
        let mut client = self.client.lock().await;
        let index = Self::index_of(&mut client)?;
        let rows = index.entries.iter().map(row_of_entry).collect();
        Ok(search::run(&self.matcher, rows, &query))
    }

    /// What filling this item for `service` needs: `OneClick` fills at once, `ConfirmFirst`
    /// needs a second user action that shows `host`, `Never` is refused. `manual` is set when the
    /// user picked the item from a list: an item that does not match the service then asks for
    /// confirmation instead of being refused, and no service at all needs none.
    pub async fn provider_fill_check(
        &self,
        vault: &str,
        item: &str,
        service: Option<String>,
        manual: bool,
    ) -> Result<ProviderFillCheck, CoreError> {
        let (vault_id, item_id) = (ids::vault(vault)?, ids::item(item)?);
        let client = self.client.lock().await;
        let loaded = client.item(&vault_id, &item_id)?;
        let (fill, host) = self.fill_of(&loaded, service, manual)?;
        Ok(ProviderFillCheck {
            fill: policy_of(fill),
            host,
        })
    }

    fn fill_of(
        &self,
        loaded: &crate::model::item::Item,
        service: Option<String>,
        manual: bool,
    ) -> Result<(Fill, String), CoreError> {
        if !loaded.overview().state.is_active() {
            return Err(CoreError::Refused("item is not active"));
        }
        if loaded.overview().kind != LOGIN {
            return Err(CoreError::Refused("item is not a login"));
        }
        let Some(service) = service else {
            return if manual {
                Ok((Fill::OneClick, String::new()))
            } else {
                Err(CoreError::Refused("no service"))
            };
        };
        let text = if service.contains("://") {
            service
        } else {
            format!("https://{service}")
        };
        let page = Origin::parse(&text).map_err(|_| CoreError::Refused("service"))?;
        let matched = self.matcher.rank(&page, &loaded.details().urls);
        if matched.fill == Fill::Never && matched.level != MatchLevel::None {
            return Err(CoreError::Refused("this item is never filled here"));
        }
        if matched.level == MatchLevel::None {
            return if manual {
                Ok((Fill::ConfirmFirst, page.host_string()))
            } else {
                Err(CoreError::Refused("no match for this service"))
            };
        }
        Ok((matched.fill, page.host_string()))
    }

    /// Releases the user name and password of one item for `ASPasswordCredential`. Only this
    /// item is opened. The item must be a login that fits `service` (see `provider_fill_check`);
    /// when that needs a confirmation the caller must pass `confirmed` after showing it.
    #[expect(
        clippy::too_many_arguments,
        reason = "the two consent flags mirror the FFI call one to one"
    )]
    pub async fn provider_password(
        &self,
        vault: &str,
        item: &str,
        service: Option<String>,
        manual: bool,
        confirmed: bool,
    ) -> Result<ProviderPassword, CoreError> {
        let (vault_id, item_id) = (ids::vault(vault)?, ids::item(item)?);
        let client = self.client.lock().await;
        let loaded = client.item(&vault_id, &item_id)?;
        let (fill, host) = self.fill_of(&loaded, service, manual)?;
        if fill != Fill::OneClick && !confirmed {
            return Err(CoreError::Refused("the fill needs a confirmation"));
        }
        let mut user = None;
        let mut password = None;
        for field in loaded.details().sections.iter().flat_map(Section::fields) {
            match field.purpose() {
                Some(Purpose::Username) if user.is_none() => user = Some(secret_text(field)),
                Some(Purpose::Password) if password.is_none() => {
                    password = Some(secret_text(field));
                }
                _ => {}
            }
        }
        let password = password.ok_or(CoreError::NotFound("password"))?;
        let user = user
            .and_then(|secret| String::from_utf8(secret.as_bytes().to_vec()).ok())
            .unwrap_or_else(|| loaded.overview().subtitle.clone());
        Ok(ProviderPassword {
            vault: vault.to_owned(),
            item: item.to_owned(),
            user,
            password,
            host,
        })
    }

    /// The stored passkeys of one relying party, from the index only (no item is opened).
    pub async fn provider_passkeys(
        &self,
        query: ProviderPasskeyQuery,
    ) -> Result<Vec<PasskeyCandidate>, CoreError> {
        let rp_id = check_relying_party(self.matcher.psl(), &query.rp_id)?;
        let mut client = self.client.lock().await;
        let index = Self::index_of(&mut client)?;
        Ok(passkeys_in(&index, &rp_id, &query.allow))
    }
}

pub(super) fn passkeys_in(index: &Index, rp_id: &str, allow: &[String]) -> Vec<PasskeyCandidate> {
    let mut out = Vec::new();
    for entry in index.entries.iter().filter(|e| e.is_active()) {
        for passkey in &entry.passkeys {
            if passkey.rp_id != rp_id
                || !(allow.is_empty()
                    || allow.iter().any(|a| {
                        base64url::decode(a)
                            .zip(base64url::decode(&passkey.credential_id))
                            .is_some_and(|(wanted, have)| hasp_crypto::ct_eq(&wanted, &have))
                    }))
            {
                continue;
            }
            out.push(PasskeyCandidate {
                vault: entry.vault.clone(),
                item: entry.item.clone(),
                credential_id: passkey.credential_id.clone(),
                rp_id: passkey.rp_id.clone(),
                user_name: passkey.user_name.clone(),
                display_name: passkey.display_name.clone(),
                title: entry.title.clone(),
                created: passkey.created,
                last_used: passkey.last_used,
            });
        }
    }
    out
}

fn candidate_of(entry: &IndexEntry, fill: Option<super::FillPolicy>) -> Candidate {
    Candidate {
        vault: entry.vault.clone(),
        item: entry.item.clone(),
        title: entry.title.clone(),
        subtitle: entry.user.clone(),
        tier: super::MatchTier::Related,
        fill: fill.unwrap_or(super::FillPolicy::ConfirmFirst),
        host_to_confirm: None,
        has_totp: entry.has_totp,
        has_passkey: !entry.passkeys.is_empty(),
        favourite: entry.favourite,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(passkeys: Vec<IndexPasskey>, hosts: &[&str]) -> IndexEntry {
        IndexEntry {
            vault: "v".to_owned(),
            item: "i".to_owned(),
            stamp: "s".to_owned(),
            kind: LOGIN.to_owned(),
            title: "Site".to_owned(),
            user: "u".to_owned(),
            urls: hosts
                .iter()
                .map(|host| crate::provider::IndexUrl {
                    host: (*host).to_owned(),
                    port: None,
                    mode: "domain".to_owned(),
                })
                .collect(),
            favourite: false,
            state: 0,
            modified: 0,
            has_totp: false,
            has_password: true,
            passkeys,
        }
    }

    fn key(rp: &str, id: &str, handle: &str) -> IndexPasskey {
        IndexPasskey {
            credential_id: id.to_owned(),
            rp_id: rp.to_owned(),
            user_name: "u".to_owned(),
            display_name: "u".to_owned(),
            user_handle: handle.to_owned(),
            created: 0,
            last_used: None,
        }
    }

    #[test]
    fn invalid_identities_are_skipped_and_counted_without_dropping_the_valid_ones() {
        let psl = PublicSuffixList::bundled();
        let oversize_id = base64url::encode(&[1_u8; 1024]);
        let oversize_handle = base64url::encode(&[1_u8; 65]);
        let good = base64url::encode(&[1_u8; 16]);
        let mut index = Index::default();
        index.entries.push(entry(
            vec![
                key("example.com", &good, &good),
                key("", &good, &good),
                key("com", &good, &good),
                key("example.com", &oversize_id, &good),
                key("example.com", &good, &oversize_handle),
                key("example.com", "", &good),
            ],
            &["example.com", "", "not a host"],
        ));
        let (identities, skipped) = identities_of(&index, &psl);
        assert_eq!(skipped, 7);
        let records: Vec<&str> = identities.iter().map(|i| i.record.as_str()).collect();
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|r| r.starts_with("p:v:i:example.com")));
        assert!(records.iter().any(|r| r.starts_with("k:v:i:")));
    }

    #[test]
    fn an_oversize_title_drops_the_item_but_reports_it() {
        let psl = PublicSuffixList::bundled();
        let mut index = Index::default();
        let mut long = entry(Vec::new(), &["example.com"]);
        long.title = "t".repeat(MAX_TEXT + 1);
        index.entries.push(long);
        index.entries.push(entry(Vec::new(), &["example.org"]));
        let (identities, skipped) = identities_of(&index, &psl);
        assert_eq!((identities.len(), skipped), (1, 1));
    }
}
