use hasp_core::client::{FingerprintCheck, VaultSummary};
use hasp_core::transport::Transport;
use hasp_crypto::to_hex;
use hasp_proto::{AccountId, InviteId, Role};
use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;
use serde_json::json;

use crate::app::{App, Cli};
use crate::cli::{MembersCmd, RoleArg, ShareArgs, VaultCmd};
use crate::error::CliError;
use crate::resolve::{self, parse_hex16};

fn role(arg: RoleArg) -> Role {
    match arg {
        RoleArg::Viewer => Role::Viewer,
        RoleArg::Editor => Role::Editor,
        RoleArg::Owner => Role::Owner,
    }
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Viewer => "viewer",
        Role::Editor => "editor",
        Role::Owner => "owner",
    }
}

fn kind_name(kind: hasp_proto::VaultKind) -> &'static str {
    match kind {
        hasp_proto::VaultKind::Private => "private",
        hasp_proto::VaultKind::Shared => "shared",
    }
}

fn summary_row(vault: &VaultSummary) -> Vec<serde_json::Value> {
    vec![
        json!(to_hex(vault.vault_id.as_bytes())),
        json!(vault.name),
        json!(kind_name(vault.kind)),
        json!(role_name(vault.role)),
        json!(vault.members),
        json!(vault.confirmed),
        json!(vault.quarantined),
    ]
}

const SUMMARY_HEADERS: [&str; 7] = [
    "id",
    "name",
    "kind",
    "role",
    "members",
    "confirmed",
    "quarantined",
];

fn member<T: Transport>(
    client: &Cli<T>,
    vault: &hasp_proto::VaultId,
    spec: &str,
) -> Result<AccountId, CliError> {
    let wanted = spec.to_lowercase();
    let members = client.members(vault)?;
    let matched: Vec<_> = members
        .iter()
        .filter(|m| to_hex(m.account_id.as_bytes()).starts_with(&wanted))
        .collect();
    match matched.as_slice() {
        [one] => Ok(one.account_id),
        [] => Err(CliError::not_found(format!("no member {spec}"))),
        many => Err(CliError::ambiguous(
            &format!("member {spec}"),
            many.iter()
                .map(|m| to_hex(m.account_id.as_bytes()))
                .collect(),
        )),
    }
}

pub(crate) async fn run<T: Transport>(app: &App<'_, T>, cmd: VaultCmd) -> Result<(), CliError> {
    let mut client = app.open().await?;
    let cancel = App::<T>::cancel();
    match cmd {
        VaultCmd::List => {
            let vaults = resolve::active_vaults(&client)?;
            app.out
                .list(&SUMMARY_HEADERS, vaults.iter().map(summary_row).collect())
        }
        VaultCmd::Get { vault } => {
            let id = resolve::vault(&client, &vault)?;
            let found = client
                .vaults()?
                .into_iter()
                .find(|v| v.vault_id == id)
                .ok_or_else(|| CliError::not_found("vault"))?;
            app.out.record(vec![
                ("id", json!(to_hex(found.vault_id.as_bytes()))),
                ("name", json!(found.name)),
                ("kind", json!(kind_name(found.kind))),
                ("role", json!(role_name(found.role))),
                ("members", json!(found.members)),
                ("epoch", json!(found.epoch)),
                ("seq", json!(found.seq)),
                ("confirmed", json!(found.confirmed)),
                ("quarantined", json!(found.quarantined)),
                ("repair_pending", json!(found.repair_pending)),
            ])
        }
        VaultCmd::Create { name } => {
            let id = client.create_vault(&name, &cancel).await?;
            app.push(&mut client, &[id]).await?;
            app.out.record(vec![
                ("id", json!(to_hex(id.as_bytes()))),
                ("name", json!(name)),
            ])
        }
        VaultCmd::Share(args) => share(app, &mut client, &args).await,
        VaultCmd::Join { code } => join(app, &mut client, &code).await,
        VaultCmd::Members(cmd) => members(app, &mut client, cmd).await,
        VaultCmd::Leave { vault } => {
            let id = resolve::vault(&client, &vault)?;
            client.leave_vault(&id, &cancel).await?;
            app.out.record(vec![("left", json!(to_hex(id.as_bytes())))])
        }
        VaultCmd::Dissolve(args) => {
            let id = resolve::vault(&client, &args.vault)?;
            let password = app.account_password("account password")?;
            client
                .dissolve_vault(&id, &args.confirm, &password, &cancel)
                .await?;
            app.out
                .record(vec![("dissolved", json!(to_hex(id.as_bytes())))])
        }
        VaultCmd::Bump { vault } => {
            let id = resolve::vault(&client, &vault)?;
            client.bump_epoch(&id, &cancel).await?;
            app.out
                .record(vec![("bumped", json!(to_hex(id.as_bytes())))])
        }
        VaultCmd::AcceptRollback(args) => {
            let id = resolve::vault(&client, &args.vault)?;
            let server_seq = client.server_behind(&id)?.ok_or_else(|| {
                CliError::usage("the server has not reported a history that differs from this device for that vault")
            })?;
            if !args.yes {
                return Err(CliError::usage(format!(
                    "the server holds this vault at seq {server_seq} with a history that differs from this device's. Accept only if you restored the server from a backup on purpose, then pass --yes"
                )));
            }
            let accepted = client.accept_older_server_state(&id, &cancel).await?;
            app.out
                .record(vec![("accepted", json!(format!("{accepted:?}")))])
        }
        read_only => inspect(app, &mut client, read_only),
    }
}

fn inspect<T: Transport>(
    app: &App<'_, T>,
    client: &mut Cli<T>,
    cmd: VaultCmd,
) -> Result<(), CliError> {
    match cmd {
        VaultCmd::HeadCode { vault } => {
            let wanted = vault
                .as_deref()
                .map(|spec| resolve::vault(client, spec))
                .transpose()?;
            let heads = client.heads()?;
            let rows = heads
                .iter()
                .filter(|h| wanted.is_none_or(|w| w == h.vault_id))
                .map(|h| {
                    vec![
                        json!(to_hex(h.vault_id.as_bytes())),
                        json!(h.seq),
                        json!(h.code),
                        json!(h.confirmed),
                    ]
                })
                .collect();
            app.out.list(&["vault", "seq", "code", "confirmed"], rows)
        }
        VaultCmd::Confirm(args) => {
            let id = resolve::vault(client, &args.vault)?;
            let confirmation = client.confirm_head(id, args.seq, &args.code)?;
            app.out
                .record(vec![("result", json!(format!("{confirmation:?}")))])
        }
        VaultCmd::List
        | VaultCmd::Get { .. }
        | VaultCmd::Create { .. }
        | VaultCmd::Share(_)
        | VaultCmd::Join { .. }
        | VaultCmd::Members(_)
        | VaultCmd::Leave { .. }
        | VaultCmd::Dissolve(_)
        | VaultCmd::Bump { .. }
        | VaultCmd::AcceptRollback(_) => Err(CliError::failure("not a read-only vault command")),
    }
}

async fn members<T: Transport>(
    app: &App<'_, T>,
    client: &mut Cli<T>,
    cmd: MembersCmd,
) -> Result<(), CliError> {
    let cancel = App::<T>::cancel();
    match cmd {
        MembersCmd::List { vault } => {
            let id = resolve::vault(client, &vault)?;
            let rows = client
                .members(&id)?
                .iter()
                .map(|m| {
                    vec![
                        json!(to_hex(m.account_id.as_bytes())),
                        json!(role_name(m.role)),
                        json!(m.fingerprint),
                        json!(m.is_self),
                    ]
                })
                .collect();
            app.out
                .list(&["account", "role", "fingerprint", "self"], rows)
        }
        MembersCmd::Pending { vault } => {
            let id = resolve::vault(client, &vault)?;
            let rows = client
                .pending_invitees(&id, &cancel)
                .await?
                .iter()
                .map(|p| {
                    vec![
                        json!(to_hex(p.invite_id.as_bytes())),
                        json!(role_name(p.role)),
                        json!(to_hex(p.account_id.as_bytes())),
                        json!(p.fingerprint),
                    ]
                })
                .collect();
            app.out
                .list(&["invite", "role", "account", "fingerprint"], rows)
        }
        MembersCmd::Add(args) => {
            let id = resolve::vault(client, &args.vault)?;
            let invite = InviteId::from_bytes(
                parse_hex16(&args.invite)
                    .ok_or_else(|| CliError::usage("the invite id is 32 hex characters"))?,
            );
            let check = match (&args.fingerprint, args.not_compared) {
                (Some(typed), false) => FingerprintCheck::Compared(typed.clone()),
                (None, true) => FingerprintCheck::NotCompared,
                _ => {
                    return Err(CliError::usage(
                        "pass --fingerprint FP, or --not-compared to admit without comparing",
                    ));
                }
            };
            client.add_member(&id, &invite, &check, &cancel).await?;
            app.out.record(vec![("added", json!(args.invite))])
        }
        MembersCmd::SetRole(args) => {
            let id = resolve::vault(client, &args.vault)?;
            let account = member(client, &id, &args.member)?;
            client
                .change_role(&id, &account, role(args.role), &cancel)
                .await?;
            app.out.record(vec![
                ("account", json!(to_hex(account.as_bytes()))),
                ("role", json!(role_name(role(args.role)))),
            ])
        }
        MembersCmd::Remove(args) => {
            let id = resolve::vault(client, &args.vault)?;
            let account = member(client, &id, &args.member)?;
            client.remove_member(&id, &account, &cancel).await?;
            app.out
                .record(vec![("removed", json!(to_hex(account.as_bytes())))])
        }
    }
}

async fn share<T: Transport>(
    app: &App<'_, T>,
    client: &mut Cli<T>,
    args: &ShareArgs,
) -> Result<(), CliError> {
    let id = resolve::vault(client, &args.vault)?;
    let offer = client
        .invite_create(&id, role(args.role), &App::<T>::cancel())
        .await?;
    let rendered = QrCode::new(&offer.qr)
        .map(|qr| qr.render::<Dense1x2>().quiet_zone(true).build())
        .map_err(|_| CliError::failure("the invite does not fit a QR code"))?;
    app.out.warn(&format!(
        "Scan this QR code on the invitee's device.\n{rendered}"
    ));
    app.out.record(vec![
        ("invite_id", json!(to_hex(offer.invite_id.as_bytes()))),
        ("code", json!(offer.code)),
        ("role", json!(role_name(role(args.role)))),
        ("expires", json!(offer.expires)),
    ])?;
    app.out.note(
        "When the invitee has joined, compare fingerprints and run `hasp vault members add`.",
    );
    Ok(())
}

async fn join<T: Transport>(
    app: &App<'_, T>,
    client: &mut Cli<T>,
    code: &str,
) -> Result<(), CliError> {
    let accepted = client
        .invite_accept(code.trim(), &App::<T>::cancel())
        .await?;
    app.out.record(vec![
        ("vault", json!(to_hex(accepted.vault_id.as_bytes()))),
        ("role", json!(role_name(accepted.role))),
        ("your_fingerprint", json!(accepted.my_fingerprint)),
    ])?;
    app.out
        .note("Read your fingerprint to the vault owner so they can admit you.");
    Ok(())
}
