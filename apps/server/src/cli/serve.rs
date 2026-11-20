use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hasp_crypto::{Argon2idParams, SecretKey};
use zeroize::Zeroizing;

use super::{CliError, Context, layout_of};
use crate::backup::{
    RestoreOptions, Staleness, create_snapshot, prune_snapshots, restore_snapshot, staleness,
};
use crate::clock::{Clock, SystemClock};
use crate::config::ServerConfig;
use crate::http::Gateway;
use crate::logging;
use crate::persist::{DataLayout, PersistError, ensure_no_restore_in_progress};
use crate::rate::WindowLimiter;
use crate::secret::{
    KeyOrigin, export_server_key, import_server_key, install_server_key,
    load_or_generate_server_key, load_server_key, server_fingerprint,
};
use crate::server::Server;
use crate::settings::Settings;
use crate::store::{SqliteStore, Store};

const MIN_PASSPHRASE: usize = 20;
const BLOB_SWEEP_EVERY: Duration = Duration::from_secs(600);

fn backup_root(settings: &Settings, layout: &DataLayout) -> PathBuf {
    settings
        .backup_dir
        .clone()
        .unwrap_or_else(|| layout.backups_dir())
}

fn read_passphrase(ctx: &mut Context<'_>) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let mut line = Zeroizing::new(String::new());
    ctx.input.read_line(&mut line)?;
    let phrase = line.trim_end_matches(['\n', '\r']);
    if phrase.chars().count() < MIN_PASSPHRASE {
        return Err(CliError::Failed(format!(
            "the passphrase is read from stdin and needs at least {MIN_PASSPHRASE} characters"
        )));
    }
    Ok(Zeroizing::new(phrase.as_bytes().to_vec()))
}

pub(super) fn init(settings: &Settings, ctx: &mut Context<'_>) -> Result<(), CliError> {
    let layout = layout_of(settings);
    ensure_no_restore_in_progress(&layout)?;
    let (key, origin) = load_or_generate_server_key(layout.key_path())?;
    let mut store = SqliteStore::open(&layout)?;
    let first_code = if store.accounts().is_empty()? {
        Some(super::admin::issue_signup_code(&mut store, true, true)?)
    } else {
        None
    };
    drop(store);
    let state = match origin {
        KeyOrigin::Generated => "created",
        KeyOrigin::Loaded => "kept",
    };
    writeln!(ctx.out, "data directory: {}", layout.root().display())?;
    writeln!(
        ctx.out,
        "server key {state}: {}",
        layout.key_path().display()
    )?;
    writeln!(ctx.out, "fingerprint: {}", server_fingerprint(&key)?)?;
    writeln!(
        ctx.out,
        "back up server.key apart from the data: without it every account password is void"
    )?;
    match first_code {
        Some(code) => writeln!(
            ctx.out,
            "first signup code (makes you the admin): {}",
            code.to_text()
        )?,
        None => writeln!(
            ctx.out,
            "this instance already has accounts; `haspd admin signup-code` makes another code"
        )?,
    }
    Ok(())
}

pub(super) fn migrate(settings: &Settings, ctx: &mut Context<'_>) -> Result<(), CliError> {
    let layout = layout_of(settings);
    SqliteStore::open(&layout)?;
    writeln!(
        ctx.out,
        "schema is at version {}",
        crate::store::latest_schema()
    )?;
    Ok(())
}

pub(super) fn backup(
    settings: &Settings,
    to: Option<&Path>,
    keep: Option<usize>,
    include_key: bool,
    ctx: &mut Context<'_>,
) -> Result<(), CliError> {
    let layout = layout_of(settings);
    let root = to.map_or_else(|| backup_root(settings, &layout), Path::to_path_buf);
    let info = create_snapshot(&layout, &root, SystemClock.now(), include_key)?;
    writeln!(ctx.out, "{}", info.dir.display())?;
    if info.manifest.key.is_some() {
        writeln!(
            ctx.out,
            "WARNING: this snapshot contains server.key; whoever holds it can test passwords against the database offline. Encrypt it and keep it away from other copies."
        )?;
    } else {
        writeln!(
            ctx.out,
            "this snapshot does not contain server.key; keep an export of it elsewhere (`haspd key export`)"
        )?;
    }
    let keep = keep.unwrap_or(settings.backup_keep).max(1);
    for removed in prune_snapshots(&root, keep)? {
        writeln!(ctx.out, "removed {}", removed.display())?;
    }
    Ok(())
}

pub(super) fn restore(
    settings: &Settings,
    from: &Path,
    acknowledge_rollback: bool,
    ctx: &mut Context<'_>,
) -> Result<(), CliError> {
    let layout = layout_of(settings);
    let options = RestoreOptions {
        acknowledge_rollback,
    };
    match restore_snapshot(from, &layout, options) {
        Ok(report) => {
            writeln!(ctx.out, "restored {}", from.display())?;
            writeln!(
                ctx.out,
                "every session was revoked and every unused signup code expired: all devices must sign in again; issue new codes with `haspd admin signup-code`"
            )?;
            for vault in &report.rolled_back {
                writeln!(
                    ctx.out,
                    "rolled back vault {} from seq {} to {}",
                    hasp_crypto::to_hex(vault.vault_id.as_bytes()),
                    vault.seen_seq,
                    vault
                        .restored_seq
                        .map_or_else(|| "none".to_owned(), |seq| seq.to_string())
                )?;
            }
            if let Some(previous) = report.previous {
                writeln!(ctx.out, "previous data kept in {}", previous.display())?;
            }
            Ok(())
        }
        Err(PersistError::RollbackRefused(vaults)) => {
            for vault in &vaults {
                writeln!(
                    ctx.out,
                    "would roll back vault {} from seq {} to {}",
                    hasp_crypto::to_hex(vault.vault_id.as_bytes()),
                    vault.seen_seq,
                    vault
                        .restored_seq
                        .map_or_else(|| "none".to_owned(), |seq| seq.to_string())
                )?;
            }
            Err(CliError::Failed(
                "restore refused: it would roll back vaults clients have seen; rerun with --acknowledge-rollback to accept".to_owned(),
            ))
        }
        Err(error) => Err(error.into()),
    }
}

pub(super) fn key_export(
    settings: &Settings,
    to: &Path,
    ctx: &mut Context<'_>,
) -> Result<(), CliError> {
    let layout = layout_of(settings);
    let to_stdout = to == Path::new("-");
    if !to_stdout {
        refuse_inside_backups(settings, &layout, to)?;
    }
    let key = load_server_key(layout.key_path())?;
    let passphrase = read_passphrase(ctx)?;
    let sealed = export_server_key(&key, &passphrase, Argon2idParams::local(65_536, 3, 4)?)?;
    if to_stdout {
        ctx.out.write_all(&sealed)?;
        return Ok(());
    }
    crate::persist::write_durable(to, &sealed)?;
    writeln!(ctx.out, "exported to {}", to.display())?;
    Ok(())
}

fn absolute(path: &Path) -> PathBuf {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let name = path.file_name().unwrap_or_default();
    let base = parent.map_or_else(
        || std::env::current_dir().unwrap_or_default(),
        |dir| std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf()),
    );
    base.join(name)
}

fn refuse_inside_backups(
    settings: &Settings,
    layout: &DataLayout,
    to: &Path,
) -> Result<(), CliError> {
    let target = absolute(to);
    for root in [backup_root(settings, layout), layout.backups_dir()] {
        let root = std::fs::canonicalize(&root).unwrap_or(root);
        if target.starts_with(&root) {
            return Err(CliError::Failed(format!(
                "the key export must not be written under the backups directory {}: choose another destination, or `--to -` to write it to stdout",
                root.display()
            )));
        }
    }
    Ok(())
}

pub(super) fn key_import(
    settings: &Settings,
    from: &Path,
    ctx: &mut Context<'_>,
) -> Result<(), CliError> {
    let layout = layout_of(settings);
    let passphrase = read_passphrase(ctx)?;
    let export = Zeroizing::new(std::fs::read(from)?);
    let key = import_server_key(&export, &passphrase)?;
    install_server_key(layout.key_path(), &key)?;
    writeln!(ctx.out, "installed {}", layout.key_path().display())?;
    writeln!(ctx.out, "fingerprint: {}", server_fingerprint(&key)?)?;
    Ok(())
}

pub(super) fn serve(settings: &Settings) -> Result<(), CliError> {
    logging::init(&settings.log);
    let origin = settings.origin()?.to_owned();
    let layout = layout_of(settings);
    ensure_no_restore_in_progress(&layout)?;
    let (master, origin_of_key) = load_or_generate_server_key(layout.key_path())?;
    if origin_of_key == KeyOrigin::Generated {
        tracing::warn!(
            path = %layout.key_path().display(),
            "server.key created; back it up apart from the data (without it every account password is void)"
        );
    }
    let store = SqliteStore::open(&layout)?;
    warn_when_backup_is_stale(&backup_root(settings, &layout));
    let server = build_server(&origin, master, store, settings)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(settings.capacity.workers.saturating_add(4))
        .enable_all()
        .build()?;
    let listen = settings.listen;
    let options = settings.http_options();
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(listen).await?;
        tracing::info!(listen = %listen, "listening");
        let sweeper = tokio::spawn(sweep_blobs(Arc::clone(&server)));
        let gateway = Gateway::new(server, options);
        let result = gateway.run(listener, shutdown_signal()).await;
        sweeper.abort();
        result
    })?;
    tracing::info!("stopped");
    Ok(())
}

fn build_server(
    origin: &str,
    master: SecretKey,
    store: SqliteStore,
    settings: &Settings,
) -> Result<Arc<Server<SqliteStore>>, CliError> {
    #[cfg_attr(
        not(feature = "testing"),
        expect(unused_mut, reason = "only the testing build changes the config")
    )]
    let mut config = ServerConfig::new(origin, master);
    #[cfg(feature = "testing")]
    if let Some(seconds) = std::env::var("HASP_TEST_RECOVERY_DELAY_SECS")
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
    {
        config.set_recovery_delay(seconds);
    }
    let limiter = Arc::new(WindowLimiter::new(settings.limits));
    let server = Server::new(config, store, Arc::new(SystemClock), limiter)
        .map_err(|error| CliError::Failed(format!("server did not start: {error}")))?;
    Ok(Arc::new(server))
}

fn warn_when_backup_is_stale(root: &Path) {
    match staleness(root, SystemClock.now()) {
        Ok(Staleness::Never) => {
            tracing::warn!("no backup yet; run haspd backup");
        }
        Ok(Staleness::Stale { age }) => {
            tracing::warn!(
                age_days = age / 86_400,
                "newest backup is older than 7 days"
            );
        }
        Ok(Staleness::Fresh { .. }) | Err(_) => {}
    }
}

async fn sweep_blobs(server: Arc<Server<SqliteStore>>) {
    let mut ticker = tokio::time::interval(BLOB_SWEEP_EVERY);
    loop {
        ticker.tick().await;
        let worker = Arc::clone(&server);
        let swept = tokio::task::spawn_blocking(move || {
            worker.with_store(|store| store.sweep_blobs().map(drop))
        })
        .await;
        if !matches!(swept, Ok(Ok(Ok(())))) {
            tracing::warn!("attachment sweep failed");
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let terminate = signal(SignalKind::terminate());
        match terminate {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _seen = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _seen = tokio::signal::ctrl_c().await;
    }
    tracing::info!("shutting down");
}
