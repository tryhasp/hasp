use hasp_core::generator::entropy::OsEntropy;
use hasp_core::generator::memorable::{self, MemorableOptions, Wordlist};
use hasp_core::generator::pin;
use hasp_core::generator::random::{self, RandomOptions, Symbols};
use hasp_core::generator::rules::{FieldConstraints, PasswordRules};
use hasp_core::generator::strength;
use hasp_core::store::EventKind;
use hasp_core::sync::VaultSyncState;
use hasp_core::transport::Transport;
use hasp_crypto::to_hex;
use secrecy::ExposeSecret;
use serde_json::json;

use crate::app::App;
use crate::cli::{AdminCmd, GenerateArgs, TokenCmd};
use crate::error::CliError;
use crate::output::Format;

pub(crate) fn generate<T: Transport>(
    app: &App<'_, T>,
    args: &GenerateArgs,
) -> Result<(), CliError> {
    let mut entropy = OsEntropy;
    let core = |error: hasp_core::generator::GeneratorError| {
        CliError::from(hasp_core::CoreError::from(error))
    };
    let password = if args.pin {
        pin::pin(&mut entropy, args.length.unwrap_or(6)).map_err(core)?
    } else if args.memorable {
        let mut options = MemorableOptions::standard();
        if let Some(words) = args.length {
            options.words = words;
        }
        let list = Wordlist::bundled().map_err(core)?;
        memorable::memorable(&mut entropy, &list, &options).map_err(core)?
    } else if let Some(text) = &args.rules {
        let rules = PasswordRules::parse_strict(text).map_err(core)?;
        random::from_rules(&mut entropy, &rules, args.length.unwrap_or(20)).map_err(core)?
    } else {
        let mut options = RandomOptions::standard();
        if let Some(length) = args.length {
            options.length = length;
        }
        if args.no_symbols {
            options.symbols = Symbols::None;
        }
        options.exclude_ambiguous = args.exclude_ambiguous;
        random::random(
            &mut entropy,
            &options,
            None,
            FieldConstraints {
                min_length: None,
                max_length: None,
            },
        )
        .map_err(core)?
    };
    let bits = strength::estimate_bits(password.expose_secret());
    if app.out.format() == Format::Json {
        return app.out.record(vec![
            ("password", json!(password.expose_secret())),
            ("entropy_bits", json!(bits.round())),
        ]);
    }
    app.out.raw(password.expose_secret().as_bytes())?;
    app.out.raw(b"\n")
}

pub(crate) async fn sync<T: Transport>(app: &App<'_, T>) -> Result<(), CliError> {
    let (mut client, mut state) = app.signed_in_client()?;
    app.unlock(&mut client, &mut state).await?;
    if app.opts.offline {
        return Err(CliError::usage("sync needs the network; drop --offline"));
    }
    let report = match client.sync(&App::<T>::cancel()).await {
        Ok(report) => report,
        Err(
            error @ hasp_core::CoreError::Proto(
                hasp_proto::ProtoError::Rollback | hasp_proto::ProtoError::Fork,
            ),
        ) => {
            app.warn_server_behind(&client);
            return Err(error.into());
        }
        Err(error) => return Err(error.into()),
    };
    let rows = report
        .vaults
        .iter()
        .map(|v| {
            let state = match &v.state {
                VaultSyncState::UpToDate => "up-to-date".to_owned(),
                VaultSyncState::Quarantined(check) => format!("quarantined: {check}"),
                VaultSyncState::RepairPending => "repair-pending".to_owned(),
                VaultSyncState::Removed => "removed".to_owned(),
                VaultSyncState::Dissolved => "dissolved".to_owned(),
                VaultSyncState::Left => "left".to_owned(),
            };
            vec![
                json!(to_hex(v.vault_id.as_bytes())),
                json!(state),
                json!(v.commits),
                json!(v.head_seq),
            ]
        })
        .collect();
    app.out
        .list(&["vault", "state", "commits", "head_seq"], rows)?;
    for event in &report.events {
        app.out.warn(&describe(&event.kind));
    }
    Ok(())
}

fn describe(kind: &EventKind) -> String {
    match kind {
        EventKind::Conflict {
            item_id,
            replaced_ver,
            ..
        } => format!(
            "conflict on item {}: your version replaced version {replaced_ver}; see `hasp item history`",
            to_hex(item_id.as_bytes())
        ),
        EventKind::Removed { vault_id } => {
            format!(
                "you were removed from vault {}",
                to_hex(vault_id.as_bytes())
            )
        }
        EventKind::Dissolved { vault_id } => {
            format!("vault {} was dissolved", to_hex(vault_id.as_bytes()))
        }
        EventKind::Left { vault_id } => format!("you left vault {}", to_hex(vault_id.as_bytes())),
        EventKind::LeaveRequested { vault_id, account } => format!(
            "member {} asked to leave vault {}",
            to_hex(account.as_bytes()),
            to_hex(vault_id.as_bytes())
        ),
        EventKind::Quarantined { vault_id, check } => {
            format!(
                "vault {} is quarantined: {check}",
                to_hex(vault_id.as_bytes())
            )
        }
        EventKind::NeedsAttention { vault_id, reason } => format!(
            "vault {} needs attention: {reason}",
            to_hex(vault_id.as_bytes())
        ),
        EventKind::RetentionFallback {
            vault_id,
            from_seq,
            to_seq,
        } => format!(
            "vault {} fell back from seq {from_seq} to {to_seq} after server retention",
            to_hex(vault_id.as_bytes())
        ),
        EventKind::Server { kind, .. } => notice_text(*kind),
        EventKind::ServerBehind {
            vault_id,
            server_seq,
            local_seq,
        } => format!(
            "the server holds vault {} at seq {server_seq} with a history that differs from this device at {local_seq}; if you restored the server on purpose run `hasp vault accept-rollback`",
            to_hex(vault_id.as_bytes())
        ),
        EventKind::RollbackAccepted {
            vault_id,
            from_seq,
            to_seq,
        } => format!(
            "vault {} moved from seq {from_seq} to {to_seq} on your confirmation",
            to_hex(vault_id.as_bytes())
        ),
    }
}

fn notice_text(kind: u64) -> String {
    match kind {
        1 => "ALERT: a recovery of this account was started; if it was not you, sign in on this device to stop it".to_owned(),
        2 => "a recovery of this account was stopped".to_owned(),
        3 => "the account was recovered with a recovery code".to_owned(),
        4 => "the account password or Secret Key was changed".to_owned(),
        5 => "an invitee accepted one of your vault invites".to_owned(),
        6 => "a member asked to leave a vault".to_owned(),
        7 => "you were removed from a vault".to_owned(),
        8 => "a vault was dissolved".to_owned(),
        other => format!("server notice {other}"),
    }
}

pub(crate) async fn admin<T: Transport>(app: &App<'_, T>, cmd: AdminCmd) -> Result<(), CliError> {
    match cmd {
        AdminCmd::Token(TokenCmd::Create) => {
            let mut client = app.open().await?;
            let code = client.admin_create_token(&App::<T>::cancel()).await?;
            app.out.record(vec![("signup_code", json!(code))])
        }
    }
}
