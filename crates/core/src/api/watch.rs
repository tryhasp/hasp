use std::collections::BTreeMap;

use super::engine::Engine;
use super::{WatchFinding, WatchKind, WatchtowerReport};
use crate::CoreError;
use crate::client::Client;
use crate::model::id::Id;
use crate::store::{LocalVaultStatus, Store};
use crate::transport::Transport;
use crate::watchtower::pwned::RangeClient;
use crate::watchtower::report::{Detail, Report};
use crate::watchtower::{PwnedMode, Watchtower};

type Titles = BTreeMap<Id, (String, String, String)>;

fn refresh<T: Transport, S: Store>(
    engine: &Engine<T, S>,
    client: &Client<T, S>,
    watchtower: &mut Watchtower,
) -> Result<Titles, CoreError> {
    watchtower.clear();
    let mut titles = Titles::new();
    for vault in client.vaults()? {
        if vault.status != LocalVaultStatus::Active || vault.quarantined {
            continue;
        }
        for summary in client.items(&vault.vault_id)? {
            let Ok(item) = client.item(&summary.vault_id, &summary.item_id) else {
                continue;
            };
            let key = Id::from_bytes(*summary.item_id.as_bytes());
            watchtower.upsert(key, &item, &engine.templates);
            titles.insert(
                key,
                (
                    super::ids::hex(summary.vault_id.as_bytes()),
                    super::ids::hex(summary.item_id.as_bytes()),
                    summary.overview.title,
                ),
            );
        }
    }
    Ok(titles)
}

fn dto(report: &Report, titles: &Titles, checked: usize, ran: bool, now: u64) -> WatchtowerReport {
    let mut findings = Vec::new();
    for item in &report.items {
        let Some((vault, id, title)) = titles.get(&item.item) else {
            continue;
        };
        for finding in &item.findings {
            let (kind, detail) = match &finding.detail {
                Detail::Pwned { count } => (WatchKind::Vulnerable, Some(count.to_string())),
                Detail::Reused { items } => (WatchKind::Reused, Some(items.to_string())),
                Detail::Weak { bits, .. } => (WatchKind::Weak, Some(bits.to_string())),
                Detail::InsecureUrl => (WatchKind::InsecureUrl, None),
                Detail::Expiring { days_left } => {
                    (WatchKind::Expiring, Some(days_left.to_string()))
                }
            };
            findings.push(WatchFinding {
                kind,
                vault: vault.clone(),
                item: id.clone(),
                title: title.clone(),
                detail,
                group: None,
            });
        }
    }
    WatchtowerReport {
        findings,
        checked: u32::try_from(checked).unwrap_or(u32::MAX),
        breach_check_ran: ran,
        generated_at: now,
    }
}

impl<T: Transport, S: Store> Engine<T, S> {
    pub(super) async fn drop_watchtower(&self) {
        *self.watch.lock().await = None;
    }

    /// Local checks only: reused, weak, insecure URL and expiring, plus breach verdicts the last
    /// opted-in run cached. Nothing leaves the device.
    pub async fn watchtower_report(&self) -> Result<WatchtowerReport, CoreError> {
        let client = self.client.lock().await;
        let mut slot = self.watch.lock().await;
        let watchtower = match slot.take() {
            Some(existing) => existing,
            None => Watchtower::new()?,
        };
        let mut watchtower = watchtower;
        let titles = refresh(self, &client, &mut watchtower)?;
        let now = client.now();
        let report = watchtower.report(now);
        let ran = watchtower.pwned_mode() == PwnedMode::OptedIn;
        let out = dto(&report, &titles, watchtower.len(), ran, now);
        *slot = Some(watchtower);
        Ok(out)
    }

    /// The opt-in breach check: 5-character SHA-1 prefixes go straight to the range
    /// API through the host's `RangeClient`, never through `haspd`.
    pub async fn watchtower_check_breaches<C: RangeClient>(
        &self,
        range: &C,
    ) -> Result<WatchtowerReport, CoreError> {
        let client = self.client.lock().await;
        let mut slot = self.watch.lock().await;
        let mut watchtower = match slot.take() {
            Some(existing) => existing,
            None => Watchtower::new()?,
        };
        let titles = refresh(self, &client, &mut watchtower)?;
        watchtower.set_pwned_mode(PwnedMode::OptedIn);
        let now = client.now();
        let outcome = watchtower.check_pwned(range, now).await;
        let report = watchtower.report(now);
        let out = dto(&report, &titles, watchtower.len(), true, now);
        *slot = Some(watchtower);
        outcome?;
        Ok(out)
    }
}
