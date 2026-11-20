use hasp_proto::wire::{SignupToken, TokenKind};

use super::{CliError, Context, layout_of};
use crate::clock::{Clock, SystemClock};
use crate::config::SIGNUP_TTL;
use crate::secret::{issue_reregister_tokens, load_server_key, server_fingerprint};
use crate::settings::Settings;
use crate::store::{SqliteStore, Store, StoreResult, TokenRow};
use hasp_proto::Hash32;

const REREGISTER_TTL: u64 = 7 * 86_400;

pub(super) fn signup_code(
    settings: &Settings,
    admin: bool,
    ctx: &mut Context<'_>,
) -> Result<(), CliError> {
    let layout = layout_of(settings);
    let mut store = SqliteStore::open_shared(&layout)?;
    let token = issue_signup_code(&mut store, admin, false)?;
    writeln!(ctx.out, "{}", token.to_text())?;
    Ok(())
}

pub(super) fn issue_signup_code(
    store: &mut SqliteStore,
    admin: bool,
    supersede_bootstrap: bool,
) -> Result<SignupToken, CliError> {
    let token =
        SignupToken::random().map_err(|_| CliError::Failed("randomness unavailable".to_owned()))?;
    let row = TokenRow {
        creator: None,
        target: None,
        expires: SystemClock.now().saturating_add(SIGNUP_TTL),
        used_by: None,
        kind: TokenKind::Signup,
        makes_admin: admin,
    };
    store.begin()?;
    let stored = revoke_unused_bootstrap_tokens(store, supersede_bootstrap)
        .and_then(|()| store.signup_tokens().put(token.hash(), row));
    if stored.is_ok() {
        store.commit()?;
    } else {
        store.rollback()?;
    }
    stored?;
    Ok(token)
}

fn revoke_unused_bootstrap_tokens(store: &mut SqliteStore, supersede: bool) -> StoreResult<()> {
    if !supersede {
        return Ok(());
    }
    let stale: Vec<Hash32> = store
        .signup_tokens()
        .range(
            &Hash32::from_bytes([0; 32]),
            &Hash32::from_bytes([0xff; 32]),
        )?
        .into_iter()
        .filter(|(_, row)| {
            row.kind == TokenKind::Signup && row.makes_admin && row.used_by.is_none()
        })
        .map(|(hash, _)| hash)
        .collect();
    for hash in stale {
        store.signup_tokens().remove(&hash)?;
    }
    Ok(())
}

pub(super) fn reregister(settings: &Settings, ctx: &mut Context<'_>) -> Result<(), CliError> {
    let layout = layout_of(settings);
    let key = load_server_key(layout.key_path())?;
    let mut store = SqliteStore::open_shared(&layout)?;
    let tokens = issue_reregister_tokens(&mut store, SystemClock.now(), REREGISTER_TTL)?;
    writeln!(ctx.out, "server fingerprint: {}", server_fingerprint(&key)?)?;
    for issued in tokens {
        writeln!(ctx.out, "{}\t{}", issued.login, issued.token.to_text())?;
    }
    Ok(())
}

pub(super) fn fingerprint(settings: &Settings, ctx: &mut Context<'_>) -> Result<(), CliError> {
    let layout = layout_of(settings);
    let key = load_server_key(layout.key_path())?;
    writeln!(ctx.out, "{}", server_fingerprint(&key)?)?;
    Ok(())
}
