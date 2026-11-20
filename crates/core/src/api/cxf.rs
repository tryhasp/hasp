use std::collections::{BTreeMap, BTreeSet};

use hasp_proto::{ItemId, VaultId};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use super::convert::secret_text;
use super::engine::Engine;
use super::{CxfImportReport, CxfImportRequest, EventKind, ids};
use crate::CoreError;
use crate::import::report::MigrationReport;
use crate::import::time::civil_date;
use crate::import::{ImportItem, Source, cxf};
use crate::model::field::{Purpose, Section};
use crate::model::item::{Item, Passkey};
use crate::provider::IndexEntry;
use crate::store::Store;
use crate::transport::Transport;

const LEDGER: &str = "import-ledger/cxf";
const LEDGER_FLUSH: usize = 200;
const REPORTS: &str = "import-reports";

#[derive(Debug, Default, Serialize, Deserialize)]
struct Ledger {
    vaults: BTreeMap<String, String>,
    items: BTreeMap<String, LedgerItem>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LedgerItem {
    item: String,
    digest: String,
}

fn digest_of(item: &Item) -> String {
    let mut framed = Vec::new();
    let mut push = |part: &[u8]| {
        framed.extend_from_slice(&(part.len() as u64).to_be_bytes());
        framed.extend_from_slice(part);
    };
    push(item.overview().title.as_bytes());
    for field in item.details().sections.iter().flat_map(Section::fields) {
        push(secret_text(field).as_bytes());
    }
    for passkey in &item.details().passkeys {
        push(&passkey.credential_id);
        push(passkey.private_key.expose_secret());
    }
    hasp_crypto::to_hex(&hasp_crypto::sha256(&[&framed]))
}

fn username_of(item: &Item) -> String {
    item.overview().subtitle.trim().to_lowercase()
}

fn identifiable(item: &Item) -> bool {
    !username_of(item).is_empty() || !item.overview().urls.is_empty()
}

fn url_overlap(existing: &IndexEntry, incoming: &Item) -> bool {
    incoming.overview().urls.is_empty()
        || incoming
            .overview()
            .urls
            .iter()
            .any(|u| existing.urls.iter().any(|e| e.host == u.host))
}

fn login_key(title: &str, user: &str) -> (String, String) {
    (title.trim().to_lowercase(), user.trim().to_lowercase())
}

fn lookup<'a>(
    by_login: &BTreeMap<(String, String), Vec<&'a IndexEntry>>,
    incoming: &Item,
) -> Option<&'a IndexEntry> {
    if !identifiable(incoming) {
        return None;
    }
    by_login
        .get(&login_key(
            &incoming.overview().title,
            &username_of(incoming),
        ))?
        .iter()
        .copied()
        .find(|e| e.kind == incoming.overview().kind && url_overlap(e, incoming))
}

fn gains(known: &BTreeSet<Vec<u8>>, has_totp: bool, incoming: &Item) -> bool {
    (!has_totp && incoming.overview().flags.has_totp)
        || incoming
            .details()
            .passkeys
            .iter()
            .any(|p| !known.contains(&p.credential_id))
}

fn signature_of(item: &Item) -> (String, String, String) {
    let (title, user) = login_key(&item.overview().title, &username_of(item));
    (
        title,
        user,
        item.overview()
            .urls
            .first()
            .map(|u| u.host.clone())
            .unwrap_or_default(),
    )
}

struct Created {
    vault: VaultId,
    item: Option<ItemId>,
    credentials: BTreeSet<Vec<u8>>,
    has_totp: bool,
}

struct Run<'a> {
    by_login: BTreeMap<(String, String), Vec<&'a IndexEntry>>,
    created: BTreeMap<(String, String, String), Created>,
    ledger: Ledger,
    summary: CxfImportReport,
    tag: crate::model::tag::Tag,
    target: VaultId,
    preview: bool,
    written: usize,
}

impl Run<'_> {
    fn record(&mut self, key: String, item: String, digest: String) {
        self.ledger.items.insert(key, LedgerItem { item, digest });
        self.written += 1;
    }
}

fn empty_report(dry_run: bool) -> CxfImportReport {
    CxfImportReport {
        dry_run,
        imported: 0,
        merged_passkeys: 0,
        duplicates: 0,
        unchanged: 0,
        changed: Vec::new(),
        skipped: 0,
        with_loss: 0,
        passkeys: 0,
        report_id: None,
        report: String::new(),
    }
}

fn count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

impl<T: Transport, S: Store> Engine<T, S> {
    /// Imports a Credential Exchange (FIDO CXF 1.0) payload into the Private vault. `data` is
    /// the JSON of the accounts the system handed to the app. Re-imports skip what the ledger
    /// already holds; an item that matches an existing login by title, user name and host is
    /// a duplicate and only gains passkeys it lacks. The report is kept as `cxf-<time>`.
    pub async fn cxf_import(
        &self,
        request: CxfImportRequest,
    ) -> Result<CxfImportReport, CoreError> {
        let batch = cxf::parse(request.data.as_bytes(), &self.templates)?;
        let mut client = self.client.lock().await;
        client.require_unlocked()?;
        let index = Self::index_of(&mut client)?;
        let target: VaultId = client.private_vault()?;
        let ledger: Ledger = client
            .local_note_get(LEDGER)?
            .and_then(|raw| serde_json::from_slice(raw.expose()).ok())
            .unwrap_or_default();
        let tag = Source::Cxf.tag(&civil_date(client.now()))?;
        let mut report = batch.report;
        let incoming: Vec<ImportItem> = batch.vaults.into_iter().flat_map(|v| v.items).collect();
        let mut by_login: BTreeMap<(String, String), Vec<&IndexEntry>> = BTreeMap::new();
        for entry in index.entries.iter().filter(|e| e.is_active()) {
            by_login
                .entry(login_key(&entry.title, &entry.user))
                .or_default()
                .push(entry);
        }
        let mut run = Run {
            by_login,
            created: BTreeMap::new(),
            ledger,
            summary: empty_report(request.dry_run),
            tag,
            target,
            preview: request.dry_run,
            written: 0,
        };
        let mut applied = Ok(());
        for entry in incoming {
            applied = Self::import_one(&mut client, &mut run, entry);
            if applied.is_err() {
                break;
            }
        }
        let saved = if run.preview {
            Ok(())
        } else {
            Self::save_ledger(&mut client, &run.ledger)
        };
        applied?;
        saved?;
        let mut summary = run.summary;
        let counts = report.counts();
        summary.skipped = count(counts.skipped);
        summary.with_loss = count(counts.with_loss);
        summary.report = report.to_json()?;
        if !request.dry_run {
            summary.report_id = Some(Self::keep_report(&mut client, &mut report)?);
            self.emit(EventKind::VaultChanged);
        }
        Ok(summary)
    }

    fn import_one(
        client: &mut crate::client::Client<T, S>,
        run: &mut Run<'_>,
        entry: ImportItem,
    ) -> Result<(), CoreError> {
        let digest = digest_of(&entry.item);
        run.summary.passkeys = run
            .summary
            .passkeys
            .saturating_add(count(entry.item.details().passkeys.len()));
        let key = format!("cxf/{}", entry.source_id);
        if let Some(known) = run.ledger.items.get(&key) {
            if known.digest == digest {
                run.summary.unchanged += 1;
            } else {
                run.summary
                    .changed
                    .push(entry.item.overview().title.clone());
            }
            return Ok(());
        }
        if let Some(existing) = lookup(&run.by_login, &entry.item) {
            let known: BTreeSet<Vec<u8>> = existing
                .passkeys
                .iter()
                .filter_map(|p| hasp_proto::base64url::decode(&p.credential_id))
                .collect();
            if gains(&known, true, &entry.item) {
                run.summary.merged_passkeys += 1;
                if !run.preview {
                    let (vault, item) = (ids::vault(&existing.vault)?, ids::item(&existing.item)?);
                    Self::merge_into(client, &vault, &item, entry.item)?;
                }
            } else {
                run.summary.duplicates += 1;
            }
            if !run.preview {
                run.record(key, existing.item.clone(), digest);
            }
            return Self::flush_ledger(client, run);
        }
        let signature = signature_of(&entry.item);
        if identifiable(&entry.item)
            && let Some(first) = run.created.get_mut(&signature)
        {
            if gains(&first.credentials, first.has_totp, &entry.item) {
                run.summary.merged_passkeys += 1;
                first.credentials.extend(
                    entry
                        .item
                        .details()
                        .passkeys
                        .iter()
                        .map(|p| p.credential_id.clone()),
                );
                first.has_totp |= entry.item.overview().flags.has_totp;
                if let Some(item) = first.item {
                    Self::merge_into(client, &first.vault, &item, entry.item)?;
                }
            } else {
                run.summary.duplicates += 1;
            }
            if let Some(item) = first.item {
                run.record(key, ids::hex(item.as_bytes()), digest);
            }
            return Self::flush_ledger(client, run);
        }
        run.summary.imported += 1;
        let credentials = entry
            .item
            .details()
            .passkeys
            .iter()
            .map(|p| p.credential_id.clone())
            .collect();
        let has_totp = entry.item.overview().flags.has_totp;
        let identifiable = identifiable(&entry.item);
        let item = if run.preview {
            None
        } else {
            let mut parts = entry.item.into_parts();
            parts.tags.push(run.tag.clone());
            let id = client.create_item(&run.target, &Item::new(parts)?)?;
            run.record(key, ids::hex(id.as_bytes()), digest);
            Some(id)
        };
        if identifiable {
            run.created.insert(
                signature,
                Created {
                    vault: run.target,
                    item,
                    credentials,
                    has_totp,
                },
            );
        }
        Self::flush_ledger(client, run)
    }

    fn flush_ledger(
        client: &mut crate::client::Client<T, S>,
        run: &mut Run<'_>,
    ) -> Result<(), CoreError> {
        if run.written < LEDGER_FLUSH {
            return Ok(());
        }
        run.written = 0;
        Self::save_ledger(client, &run.ledger)
    }

    fn merge_into(
        client: &mut crate::client::Client<T, S>,
        vault: &VaultId,
        item: &ItemId,
        incoming: Item,
    ) -> Result<(), CoreError> {
        let mut parts = client.item(vault, item)?.into_parts();
        let incoming = incoming.into_parts();
        let fresh: Vec<Passkey> = incoming
            .passkeys
            .into_iter()
            .filter(|p| {
                !parts
                    .passkeys
                    .iter()
                    .any(|known| known.credential_id == p.credential_id)
            })
            .collect();
        parts.passkeys.extend(fresh);
        let has_otp = parts
            .sections
            .iter()
            .flat_map(Section::fields)
            .any(|f| f.purpose() == Some(Purpose::Totp));
        if !has_otp {
            parts
                .sections
                .extend(incoming.sections.into_iter().filter(|section| {
                    section
                        .fields()
                        .iter()
                        .any(|f| f.purpose() == Some(Purpose::Totp))
                }));
        }
        parts.client_modified = client.now();
        client.edit_item(vault, item, &Item::new(parts)?)
    }

    fn save_ledger(
        client: &mut crate::client::Client<T, S>,
        ledger: &Ledger,
    ) -> Result<(), CoreError> {
        client.local_note_put(
            LEDGER,
            &serde_json::to_vec(ledger).map_err(|_| CoreError::Internal("ledger"))?,
        )?;
        Ok(())
    }

    fn keep_report(
        client: &mut crate::client::Client<T, S>,
        report: &mut MigrationReport,
    ) -> Result<String, CoreError> {
        let id = format!("cxf-{}", client.now());
        let mut all: BTreeMap<String, serde_json::Value> = client
            .local_note_get(REPORTS)?
            .and_then(|raw| serde_json::from_slice(raw.expose()).ok())
            .unwrap_or_default();
        let value = serde_json::to_value(&*report).map_err(|_| CoreError::Internal("report"))?;
        all.insert(id.clone(), value);
        client.local_note_put(
            REPORTS,
            &serde_json::to_vec(&all).map_err(|_| CoreError::Internal("report"))?,
        )?;
        Ok(id)
    }

    #[cfg(feature = "testing")]
    pub async fn cxf_export_for_tests(&self) -> Result<String, CoreError> {
        let mut client = self.client.lock().await;
        let index = Self::index_of(&mut client)?;
        let mut owned = Vec::new();
        for entry in index.entries.iter().filter(|e| e.is_active()) {
            let loaded = client.item(&ids::vault(&entry.vault)?, &ids::item(&entry.item)?)?;
            owned.push((hasp_proto::base64url::encode(entry.item.as_bytes()), loaded));
        }
        let borrowed: Vec<(String, &Item)> =
            owned.iter().map(|(id, item)| (id.clone(), item)).collect();
        Ok(crate::testing::export_cxf(&borrowed))
    }
}
