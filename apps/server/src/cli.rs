mod admin;
mod healthcheck;
mod serve;

use std::ffi::OsString;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::persist::{DataLayout, PersistError};
use crate::settings::{Settings, SettingsError};

#[derive(Debug, Parser)]
#[command(name = "haspd", version, about = "Hasp server")]
pub struct Cli {
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve the HTTP API until SIGINT or SIGTERM
    Serve,
    /// Create the data directory, database and `server.key`
    Init,
    /// Operator actions on a stopped or running instance
    #[command(subcommand)]
    Admin(AdminCommand),
    /// Write a consistent snapshot of the database and attachments (no `server.key` by default)
    Backup {
        /// Also copy `server.key` into the snapshot; then the snapshot alone unlocks every account
        #[arg(long)]
        include_key: bool,
        /// Defaults to `backup_dir`, which defaults to `data_dir/backups`
        #[arg(long, value_name = "DIR")]
        to: Option<PathBuf>,
        /// Keep the newest N snapshots and delete the rest; defaults to `backup_keep` (7)
        #[arg(long, value_name = "N")]
        keep: Option<usize>,
    },
    /// Replace the data with a snapshot
    Restore {
        #[arg(long, value_name = "DIR")]
        from: PathBuf,
        #[arg(long)]
        acknowledge_rollback: bool,
    },
    /// Export or import `server.key` under a passphrase
    #[command(subcommand)]
    Key(KeyCommand),
    /// Apply pending schema migrations
    Migrate,
    /// Print the server key fingerprint clients compare
    Fingerprint,
    /// Exit zero when the local server answers /healthz
    Healthcheck,
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// Create a signup code
    #[command(visible_alias = "token")]
    SignupCode {
        /// The account created with it becomes an instance admin
        #[arg(long)]
        admin: bool,
    },
    /// After a lost `server.key`: one re-registration code per active account
    Reregister,
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Write an encrypted copy of `server.key` to a file outside the backups, or to stdout with `-`
    Export {
        #[arg(long, value_name = "FILE")]
        to: PathBuf,
    },
    /// Install `server.key` from an encrypted export
    Import {
        #[arg(long, value_name = "FILE")]
        from: PathBuf,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    Settings(#[from] SettingsError),
    #[error(transparent)]
    Persist(#[from] PersistError),
    #[error(transparent)]
    Store(#[from] crate::store::ServerError),
    #[error("{0}")]
    Failed(String),
    #[error("randomness or key derivation failed")]
    Crypto(#[from] hasp_crypto::CryptoError),
    #[error("io failure: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Context<'a> {
    pub env: &'a dyn Fn(&str) -> Option<String>,
    pub input: &'a mut dyn BufRead,
    pub out: &'a mut dyn Write,
}

impl std::fmt::Debug for Context<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Context(..)")
    }
}

pub(crate) fn layout_of(settings: &Settings) -> DataLayout {
    let layout = DataLayout::new(&settings.data_dir);
    match &settings.server_key {
        Some(path) => layout.with_key_path(path),
        None => layout,
    }
}

pub fn run<I, T>(args: I, ctx: &mut Context<'_>) -> Result<(), CliError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            writeln!(ctx.out, "{error}")?;
            return if error.use_stderr() {
                Err(CliError::Failed("invalid arguments".to_owned()))
            } else {
                Ok(())
            };
        }
    };
    let settings = Settings::load(cli.config.as_deref(), ctx.env)?;
    match cli.command {
        Command::Serve => serve::serve(&settings),
        Command::Init => serve::init(&settings, ctx),
        Command::Admin(AdminCommand::SignupCode { admin }) => {
            admin::signup_code(&settings, admin, ctx)
        }
        Command::Admin(AdminCommand::Reregister) => admin::reregister(&settings, ctx),
        Command::Backup {
            include_key,
            to,
            keep,
        } => serve::backup(&settings, to.as_deref(), keep, include_key, ctx),
        Command::Restore {
            from,
            acknowledge_rollback,
        } => serve::restore(&settings, &from, acknowledge_rollback, ctx),
        Command::Key(KeyCommand::Export { to }) => serve::key_export(&settings, &to, ctx),
        Command::Key(KeyCommand::Import { from }) => serve::key_import(&settings, &from, ctx),
        Command::Migrate => serve::migrate(&settings, ctx),
        Command::Fingerprint => admin::fingerprint(&settings, ctx),
        Command::Healthcheck => healthcheck::healthcheck(&settings),
    }
}

pub fn main_with(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    let env = |key: &str| std::env::var(key).ok();
    let mut stdout = std::io::stdout();
    let mut stdin = std::io::stdin().lock();
    let mut ctx = Context {
        env: &env,
        input: &mut stdin,
        out: &mut stdout,
    };
    match run(args, &mut ctx) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _written = writeln!(std::io::stderr(), "haspd: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
