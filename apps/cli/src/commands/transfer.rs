use std::collections::BTreeMap;

use hasp_core::client::NewAttachment;
use hasp_core::export::{self, Unlock};
use hasp_core::import::report::MigrationReport;
use hasp_core::import::{ImportBatch, Source, bitwarden, cxf, delimited, onepux};
use hasp_core::model::item::Item;
use hasp_core::model::template::Templates;
use hasp_core::transport::Transport;
use hasp_crypto::to_hex;
use hasp_proto::VaultKind;
use secrecy::ExposeSecret;
use serde_json::{Value, json};

use crate::app::{App, Cli};
use crate::cli::{BackupCmd, ExportArgs, ImportArgs, ImportCmd, ReportCmd, RestoreArgs};
use crate::error::CliError;
use crate::fsx;
use crate::itemspec;
use crate::resolve::{self};

const KDF_M_KIB: u32 = 262_144;
const KDF_T: u32 = 3;
const KDF_P: u32 = 4;

fn argon() -> Result<hasp_crypto::Argon2idParams, CliError> {
    Ok(
        hasp_crypto::Argon2idParams::account(KDF_M_KIB, KDF_T, KDF_P)
            .map_err(hasp_core::CoreError::from)?,
    )
}

fn local_argon() -> Result<hasp_crypto::Argon2idParams, CliError> {
    Ok(hasp_crypto::Argon2idParams::local(KDF_M_KIB, KDF_T, KDF_P)
        .map_err(hasp_core::CoreError::from)?)
}

pub(crate) async fn export<T: Transport>(
    app: &App<'_, T>,
    args: ExportArgs,
) -> Result<(), CliError> {
    let mut client = app.open().await?;
    let password = app.account_password("account password")?;
    let passphrase = app.confirmed_secret(args.passphrase_stdin, "export passphrase")?;
    let bytes = client
        .export(&password, &passphrase, argon()?, &App::<T>::cancel())
        .await?;
    fsx::write_private(&args.out, &bytes)?;
    app.out.record(vec![
        ("written", json!(args.out.display().to_string())),
        ("bytes", json!(bytes.len())),
    ])
}

pub(crate) async fn backup<T: Transport>(app: &App<'_, T>, cmd: BackupCmd) -> Result<(), CliError> {
    let mut client = app.open().await?;
    match cmd {
        BackupCmd::Enable(args) => {
            let passphrase = app.confirmed_secret(args.passphrase_stdin, "backup passphrase")?;
            client
                .enable_backup(&passphrase, local_argon()?)
                .map_err(CliError::from)?;
            app.out.record(vec![("backup_enabled", json!(true))])
        }
        BackupCmd::Now { out } => {
            let password = app.account_password("account password")?;
            let bytes = client.backup(&password, &App::<T>::cancel()).await?;
            fsx::write_private(&out, &bytes)?;
            app.out.record(vec![
                ("written", json!(out.display().to_string())),
                ("bytes", json!(bytes.len())),
            ])
        }
    }
}

pub(crate) async fn restore<T: Transport>(
    app: &App<'_, T>,
    args: RestoreArgs,
) -> Result<(), CliError> {
    let bytes = std::fs::read(&args.file)?;
    export::peek(&bytes).map_err(hasp_core::CoreError::from)?;
    let mut client = app.open().await?;
    let passphrase = app.read_secret(args.passphrase_stdin, "passphrase")?;
    let report = client
        .restore(
            &bytes,
            &Unlock::Passphrase(&passphrase),
            &App::<T>::cancel(),
        )
        .await?;
    app.out.record(vec![
        ("vaults", json!(report.vaults)),
        ("items", json!(report.items)),
        ("attachments", json!(report.attachments)),
    ])
}

fn civil_date(unix: u64) -> String {
    let days = i64::try_from(unix / 86_400).unwrap_or(0);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Ledger {
    vaults: BTreeMap<String, String>,
    items: BTreeMap<String, LedgerItem>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct LedgerItem {
    item: String,
    digest: String,
}

fn ledger_note(source: Source) -> String {
    format!("import-ledger/{}", source.name())
}

fn load_ledger<T: Transport>(client: &Cli<T>, source: Source) -> Result<Ledger, CliError> {
    match client.local_note_get(&ledger_note(source))? {
        Some(bytes) => Ok(serde_json::from_slice(bytes.expose())?),
        None => Ok(Ledger::default()),
    }
}

fn save_ledger<T: Transport>(
    client: &mut Cli<T>,
    source: Source,
    ledger: &Ledger,
) -> Result<(), CliError> {
    client.local_note_put(&ledger_note(source), &serde_json::to_vec(ledger)?)?;
    Ok(())
}

fn digest_of(item: &Item) -> String {
    let mut parts: Vec<Vec<u8>> = vec![item.overview().title.clone().into_bytes()];
    for section in &item.details().sections {
        for field in section.fields() {
            parts.push(itemspec::value_text(field.value()).into_bytes());
        }
    }
    let mut framed = Vec::new();
    for part in &parts {
        framed.extend_from_slice(&(part.len() as u64).to_be_bytes());
        framed.extend_from_slice(part);
    }
    to_hex(&hasp_crypto::sha256(&[&framed]))
}

const REPORTS_NOTE: &str = "import-reports";

fn load_reports<T: Transport>(client: &Cli<T>) -> Result<BTreeMap<String, Value>, CliError> {
    match client.local_note_get(REPORTS_NOTE)? {
        Some(bytes) => Ok(serde_json::from_slice(bytes.expose())?),
        None => Ok(BTreeMap::new()),
    }
}

fn save_report<T: Transport>(
    app: &App<'_, T>,
    client: &mut Cli<T>,
    report: &MigrationReport,
) -> Result<String, CliError> {
    let id = format!("{}-{}", report.source.name(), app.now());
    let json = report.to_json().map_err(hasp_core::CoreError::from)?;
    let mut all = load_reports(client)?;
    all.insert(id.clone(), serde_json::from_str(&json)?);
    client.local_note_put(REPORTS_NOTE, &serde_json::to_vec(&all)?)?;
    Ok(id)
}

fn parse(source: Source, bytes: &[u8], templates: &Templates) -> Result<ImportBatch, CliError> {
    Ok(match source {
        Source::OnePassword => onepux::parse(bytes, templates),
        Source::Bitwarden => bitwarden::parse(bytes, templates),
        Source::Csv => delimited::parse(bytes, templates),
        Source::Cxf => cxf::parse(bytes, templates),
    }
    .map_err(hasp_core::CoreError::from)?)
}

pub(crate) async fn import<T: Transport>(app: &App<'_, T>, cmd: ImportCmd) -> Result<(), CliError> {
    match cmd {
        ImportCmd::Onepux(args) => import_file(app, Source::OnePassword, args).await,
        ImportCmd::Bitwarden(args) => import_file(app, Source::Bitwarden, args).await,
        ImportCmd::Csv(args) => import_file(app, Source::Csv, args).await,
        ImportCmd::Report(cmd) => reports(app, cmd).await,
    }
}

fn confirm_import<T: Transport>(
    app: &App<'_, T>,
    args: &ImportArgs,
    count: usize,
) -> Result<(), CliError> {
    if args.yes {
        return Ok(());
    }
    if app.opts.no_input || !app.env.io.interactive() {
        return Err(CliError::usage(
            "pass --yes to commit, or --dry-run to preview",
        ));
    }
    let answer = app.read_line(&format!("Import {count} items? [y/N]"))?;
    if answer.trim().eq_ignore_ascii_case("y") {
        Ok(())
    } else {
        Err(CliError::usage("import cancelled"))
    }
}

async fn import_file<T: Transport>(
    app: &App<'_, T>,
    source: Source,
    args: ImportArgs,
) -> Result<(), CliError> {
    let bytes = zeroize::Zeroizing::new(std::fs::read(&args.file)?);
    let templates = Templates::bundled()?;
    let batch = parse(source, &bytes, &templates)?;
    let counts = batch.report.counts();
    let by_kind = batch.counts_by_kind();
    let mut client = app.open_local().await?;
    let report_id = save_report(app, &mut client, &batch.report)?;
    if let Some(path) = &args.report_out {
        let json = batch.report.to_json().map_err(hasp_core::CoreError::from)?;
        fsx::write_private(path, json.as_bytes())?;
    }
    let preview = vec![
        ("source", json!(source.name())),
        ("items", json!(batch.item_count())),
        ("vaults", json!(batch.vaults.len())),
        ("with_loss", json!(counts.with_loss)),
        ("skipped", json!(counts.skipped)),
        ("categories", json!(by_kind)),
        ("report", json!(report_id)),
    ];
    if args.dry_run {
        return app.out.record(preview);
    }
    confirm_import(app, &args, batch.item_count())?;
    app.sync_quietly(&mut client).await?;
    let summary = commit(app, &mut client, source, batch).await?;
    let mut out = preview;
    out.push(("imported", json!(summary.imported)));
    out.push(("already_imported", json!(summary.unchanged)));
    out.push(("changed_since_import", json!(summary.changed)));
    app.out.record(out)?;
    if !summary.changed.is_empty() {
        app.out.warn(
            "These items changed in the source since the last import; they were left as they are. Resolve them by hand:",
        );
        for title in &summary.changed {
            app.out.warn(&format!("  {title}"));
        }
    }
    if args.delete_source {
        std::fs::remove_file(&args.file)?;
        app.out.note("source file deleted");
    } else {
        app.out
            .note("The source file holds every secret in plain text. Delete it once you have checked the import (--delete-source).");
    }
    Ok(())
}

#[derive(Debug, Default)]
struct Summary {
    imported: usize,
    unchanged: usize,
    changed: Vec<String>,
}

async fn commit<T: Transport>(
    app: &App<'_, T>,
    client: &mut Cli<T>,
    source: Source,
    batch: ImportBatch,
) -> Result<Summary, CliError> {
    let mut ledger = load_ledger(client, source)?;
    let tag = source.tag(&civil_date(app.now()))?;
    let cancel = App::<T>::cancel();
    let mut summary = Summary::default();
    let mut touched = Vec::new();
    for vault in batch.vaults {
        let target = match vault.kind {
            VaultKind::Private => client.private_vault()?,
            VaultKind::Shared => {
                let known = ledger
                    .vaults
                    .get(&vault.source_id)
                    .and_then(|id| resolve::vault(client, id).ok());
                if let Some(existing) = known {
                    existing
                } else {
                    let created = client.create_vault(&vault.name, &cancel).await?;
                    ledger
                        .vaults
                        .insert(vault.source_id.clone(), to_hex(created.as_bytes()));
                    created
                }
            }
        };
        touched.push(target);
        for entry in vault.items {
            let key = format!("{}/{}", vault.source_id, entry.source_id);
            let digest = digest_of(&entry.item);
            if let Some(known) = ledger.items.get(&key) {
                if known.digest == digest {
                    summary.unchanged += 1;
                } else {
                    summary.changed.push(entry.item.overview().title.clone());
                }
                continue;
            }
            let mut parts = entry.item.into_parts();
            parts.tags.push(tag.clone());
            let item = Item::new(parts)?;
            let id = client.create_item(&target, &item)?;
            for file in &entry.files {
                client
                    .attach_file(
                        &target,
                        &id,
                        &NewAttachment {
                            name: &file.name,
                            mime: &file.mime,
                            data: file.data.expose_secret(),
                        },
                        &cancel,
                    )
                    .await?;
            }
            ledger.items.insert(
                key,
                LedgerItem {
                    item: to_hex(id.as_bytes()),
                    digest,
                },
            );
            summary.imported += 1;
        }
    }
    save_ledger(client, source, &ledger)?;
    touched.sort();
    touched.dedup();
    app.push(client, &touched).await?;
    Ok(summary)
}

fn report_files(all: BTreeMap<String, Value>) -> Vec<(String, Value)> {
    all.into_iter().collect()
}

fn outcome_count(report: &Value, outcome: &str) -> usize {
    report["items"].as_array().map_or(0, |items| {
        items.iter().filter(|i| i["outcome"] == outcome).count()
    })
}

async fn reports<T: Transport>(app: &App<'_, T>, cmd: ReportCmd) -> Result<(), CliError> {
    let client = app.open_local().await?;
    let files = report_files(load_reports(&client)?);
    match cmd {
        ReportCmd::List => app.out.list(
            &["id", "source", "imported", "with_loss", "skipped"],
            files
                .iter()
                .map(|(id, report)| {
                    vec![
                        json!(id),
                        report["source"].clone(),
                        json!(outcome_count(report, "imported")),
                        json!(outcome_count(report, "imported-with-loss")),
                        json!(outcome_count(report, "skipped")),
                    ]
                })
                .collect(),
        ),
        ReportCmd::Show { id, out } => {
            let (_, report) = files
                .iter()
                .find(|(file, _)| *file == id)
                .ok_or_else(|| CliError::not_found(format!("no report {id}")))?;
            if let Some(path) = out {
                fsx::write_private(&path, serde_json::to_string_pretty(report)?.as_bytes())?;
                return app
                    .out
                    .record(vec![("written", json!(path.display().to_string()))]);
            }
            if app.out.format() == crate::output::Format::Json {
                return app.out.document(report);
            }
            let rows = report["items"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|item| {
                    let title = item["title"].clone();
                    item["entries"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(move |entry| {
                            vec![
                                title.clone(),
                                entry["subject"].clone(),
                                entry["fate"].clone(),
                            ]
                        })
                })
                .collect();
            app.out.list(&["item", "subject", "fate"], rows)
        }
    }
}
