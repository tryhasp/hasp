use hasp_core::client::{ClientState, EmergencyKit, SignIn, SignUp};
use hasp_core::transport::Transport;
use hasp_crypto::to_hex;
use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};

use crate::app::App;
use crate::cli::{
    DeleteArgs, EnrolArgs, KitArgs, PasswordArgs, RecoveryAction, RecoveryUse, ReregisterArgs,
    SigninArgs, SignupArgs,
};
use crate::error::CliError;
use crate::fsx;

const ENROL_PREFIX: &str = "ENR1-";
const KIT_CONFIRM_TRIES: u32 = 3;
const ENROL_CODE_TRIES: u32 = 3;

const SYNCED_FOLDERS: [&str; 6] = [
    "Mobile Documents",
    "iCloud",
    "Dropbox",
    "OneDrive",
    "Google Drive",
    "/Documents/",
];

pub(crate) fn synced_folder(path: &std::path::Path) -> bool {
    let text = path.to_string_lossy();
    SYNCED_FOLDERS.iter().any(|name| text.contains(name))
}

fn warn_kit_destination<T: Transport>(app: &App<'_, T>, path: &std::path::Path) {
    if synced_folder(path) {
        app.out.warn(&format!(
            "{} looks like a synced or backed-up folder; the Secret Key in it would leave this device. Write it to removable media instead.",
            path.display()
        ));
    }
}

fn require_kit_destination<T: Transport>(
    app: &App<'_, T>,
    kit_out: Option<&std::path::Path>,
) -> Result<(), CliError> {
    if app.out.format() == crate::output::Format::Json && !app.out.reveal() && kit_out.is_none() {
        return Err(CliError::usage(
            "the Secret Key is shown once: pass --kit-out FILE or --reveal",
        ));
    }
    Ok(())
}

fn show_kit<T: Transport>(
    app: &App<'_, T>,
    kit: &EmergencyKit,
    kit_out: Option<&std::path::Path>,
) -> Result<(), CliError> {
    if let Some(path) = kit_out {
        warn_kit_destination(app, path);
        fsx::write_private(path, kit.text(app.now()).as_bytes())?;
        app.out.note(&format!("kit written to {}", path.display()));
    }
    let secret = if app.out.format() == crate::output::Format::Table {
        Value::String(kit.secret_key().to_owned())
    } else {
        app.out.secret(kit.secret_key())
    };
    app.out.record(vec![
        ("origin", json!(kit.origin)),
        ("login", json!(kit.login)),
        ("server_fingerprint", json!(kit.server_fingerprint)),
        ("secret_key", secret),
    ])?;
    app.out
        .note("Store the Secret Key offline. It is not kept on the server and is needed to sign in on a new device.");
    Ok(())
}

fn confirm_kit<T: Transport>(app: &App<'_, T>, kit: &EmergencyKit) -> Result<(), CliError> {
    if app.opts.no_input || !app.env.io.interactive() {
        return Ok(());
    }
    for _ in 0..KIT_CONFIRM_TRIES {
        let typed =
            app.read_line("Type the last group of the Secret Key to confirm you saved it")?;
        if kit.confirm_last_group(&typed) {
            return Ok(());
        }
        app.out.warn("that does not match");
    }
    Err(CliError::usage("the Secret Key was not confirmed"))
}

pub(crate) async fn signup<T: Transport>(
    app: &App<'_, T>,
    args: SignupArgs,
) -> Result<(), CliError> {
    require_kit_destination(app, args.kit_out.as_deref())?;
    let code = app.read_code(args.code.clone(), args.code_stdin, "code", "signup code")?;
    let password = app.confirmed_secret(app.opts.password_stdin, "new account password")?;
    let mut client = app.client(&args.origin)?;
    let fingerprint = app.server_fingerprint(args.server_fingerprint.as_deref(), "`haspd init`")?;
    let kit = client
        .sign_up_pinned(
            &SignUp {
                origin: &args.origin,
                token: code.expose_secret(),
                login: &args.login,
                password: &password,
            },
            Some(fingerprint),
            &App::<T>::cancel(),
        )
        .await?;
    let mut state = app.state()?;
    state.origin = Some(args.origin.clone());
    state.note_password(app.now());
    app.state_file.save(&state)?;
    show_kit(app, &kit, args.kit_out.as_deref())?;
    confirm_kit(app, &kit)
}

pub(crate) async fn signin<T: Transport>(
    app: &App<'_, T>,
    args: SigninArgs,
) -> Result<(), CliError> {
    let origin = args
        .origin
        .clone()
        .ok_or_else(|| CliError::usage("--origin is required"))?;
    let mut client = app.client(&origin)?;
    if client.state()? != ClientState::Empty {
        return Err(CliError::usage(
            "this device already holds an account; run `hasp signout` first",
        ));
    }
    let password_for_enrol = if args.enrol.is_some() || args.enrol_stdin {
        let code = app.read_code(
            args.enrol.clone(),
            args.enrol_stdin,
            "enrol",
            "enrolment code",
        )?;
        join_enrolment(app, &mut client, code.expose_secret()).await?
    } else {
        let login = args
            .login
            .clone()
            .ok_or_else(|| CliError::usage("--login is required"))?;
        let fingerprint = app.server_fingerprint(args.server_fingerprint.as_deref(), "the kit")?;
        let secret_key = app.read_secret(args.secret_key_stdin, "Secret Key")?;
        let password = app.account_password("account password")?;
        client
            .sign_in(
                &SignIn {
                    origin: &origin,
                    login: &login,
                    secret_key: secret_key.expose_secret(),
                    password: &password,
                    kit_server_fp: Some(fingerprint),
                },
                &App::<T>::cancel(),
            )
            .await?;
        Some(password)
    };
    let mut state = app.state()?;
    state.origin = Some(origin);
    if password_for_enrol.is_some() {
        state.note_password(app.now());
    }
    app.state_file.save(&state)?;
    app.out.record(vec![
        ("login", json!(client.login()?)),
        ("fingerprint", json!(client.fingerprint()?)),
    ])
}

async fn join_enrolment<T: Transport>(
    app: &App<'_, T>,
    client: &mut crate::app::Cli<T>,
    code: &str,
) -> Result<Option<SecretString>, CliError> {
    let hexed = code
        .strip_prefix(ENROL_PREFIX)
        .ok_or_else(|| CliError::usage("an enrolment code starts with ENR1-"))?;
    let qr = decode_hex(hexed).ok_or_else(|| CliError::usage("the enrolment code is damaged"))?;
    let cancel = App::<T>::cancel();
    client.enrol_join(&qr, &cancel).await?;
    let shown = wait!(client.enrol_reveal(&cancel))?;
    app.out
        .warn(&format!("Type this code on the signed-in device: {shown}"));
    let password = if app.env.secure.hardware_gated() {
        None
    } else {
        Some(app.account_password("account password")?)
    };
    match wait!(client.enrol_finish(password.as_ref(), &cancel)) {
        Ok(()) => Ok(password),
        Err(error) if error.kind == crate::error::Kind::NotFound => Err(CliError::new(
            crate::error::Kind::Auth,
            "the signed-in device refused or cancelled this enrolment",
        )),
        Err(error) => Err(error),
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|p| u8::from_str_radix(p, 16).ok())
        })
        .collect()
}

pub(crate) async fn enrol<T: Transport>(app: &App<'_, T>, args: EnrolArgs) -> Result<(), CliError> {
    let mut client = app.open().await?;
    let cancel = App::<T>::cancel();
    let invite = client.enrol_open(&cancel).await?;
    let code = format!("{ENROL_PREFIX}{}", to_hex(&invite.qr));
    let rendered = QrCode::new(&invite.qr)
        .map(|qr| qr.render::<Dense1x2>().quiet_zone(true).build())
        .map_err(|_| CliError::failure("the enrolment code does not fit a QR code"))?;
    app.out.warn(&format!(
        "Scan this QR code or run `hasp signin --enrol` with the code below on the new device.\n{rendered}\n{code}"
    ));
    let request = wait!(async {
        client
            .enrol_poll_request(&cancel)
            .await?
            .ok_or(hasp_core::CoreError::Pending { retry_after: 1 })
    })?;
    app.out.warn(&format!(
        "A {} device wants to join this account.",
        request.platform
    ));
    let interactive = !args.code_stdin;
    let mut tries = 0;
    loop {
        let typed = if args.code_stdin {
            app.env
                .io
                .stdin_line()?
                .ok_or_else(|| CliError::usage("stdin ended before the code"))?
        } else {
            app.read_line("Type the code shown on the new device")?
        };
        match client.enrol_confirm(typed.trim(), &cancel).await {
            Ok(()) => break,
            Err(hasp_core::CoreError::Refused("the code does not match"))
                if interactive && tries + 1 < ENROL_CODE_TRIES =>
            {
                tries += 1;
                app.out.warn("that does not match");
            }
            Err(error) => {
                client.enrol_abort(&cancel).await.ok();
                return Err(error.into());
            }
        }
    }
    app.out.record(vec![("enrolled", json!(true))])
}

pub(crate) fn signout<T: Transport>(app: &App<'_, T>) -> Result<(), CliError> {
    let dir = &app.opts.data_dir;
    let state = app.state()?;
    if let Some(origin) = &state.origin {
        let client = app.client(origin)?;
        let _ = client.state()?;
        drop(client);
    }
    for name in ["store", "state.json", "imports", "reports"] {
        let path = dir.join(name);
        if path.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else if path.exists() {
            std::fs::remove_file(&path)?;
        }
    }
    app.env.secure.delete("hasp.duk").ok();
    app.out.record(vec![("signed_out", json!(true))])
}

pub(crate) fn whoami<T: Transport>(app: &App<'_, T>) -> Result<(), CliError> {
    let (client, state) = app.signed_in_client()?;
    app.out.record(vec![
        ("login", json!(client.login()?)),
        ("origin", json!(state.origin)),
        ("fingerprint", json!(client.fingerprint()?)),
    ])
}

pub(crate) fn lock<T: Transport>(app: &App<'_, T>) -> Result<(), CliError> {
    app.signed_in_client()?;
    app.out.record(vec![("locked", json!(true))])
}

pub(crate) async fn unlock<T: Transport>(app: &App<'_, T>) -> Result<(), CliError> {
    let client = app.open_local().await?;
    app.out.record(vec![
        ("login", json!(client.login()?)),
        ("unlocked", json!(true)),
    ])
}

pub(crate) fn status<T: Transport>(app: &App<'_, T>) -> Result<(), CliError> {
    let state = app.state()?;
    let now = app.now();
    let Some(origin) = state.origin.clone() else {
        return app.out.record(vec![("signed_in", json!(false))]);
    };
    let client = app.client(&origin)?;
    let signed_in = client.state()? != ClientState::Empty;
    let unlock = if app.env.secure.hardware_gated() {
        "device key"
    } else {
        "password"
    };
    app.out.record(vec![
        ("signed_in", json!(signed_in)),
        ("origin", json!(origin)),
        ("login", json!(client.login().ok())),
        ("unlock", json!(unlock)),
        ("password_due_in_s", json!(state.password_due_in(now))),
        ("locked_out_for_s", json!(state.lockout_remaining(now))),
    ])
}

pub(crate) async fn recovery<T: Transport>(
    app: &App<'_, T>,
    action: RecoveryAction,
) -> Result<(), CliError> {
    match action {
        RecoveryAction::Create => {
            let mut client = app.open().await?;
            let password = app.account_password("account password")?;
            let code = client
                .create_recovery_code(&password, &App::<T>::cancel())
                .await?;
            let shown = if app.out.format() == crate::output::Format::Table {
                Value::String(code.expose().to_owned())
            } else {
                app.out.secret(code.expose())
            };
            app.out.record(vec![("recovery_code", shown)])?;
            app.out
                .note("Store the recovery code offline. Recovery waits 24 hours and other devices are notified.");
            Ok(())
        }
        RecoveryAction::Use(args) => recover(app, args).await,
    }
}

async fn recover<T: Transport>(app: &App<'_, T>, args: RecoveryUse) -> Result<(), CliError> {
    let mut client = app.client(&args.origin)?;
    if args.restart {
        client.discard_recovery_ticket()?;
    }
    let (ticket, new_password) = if client.has_recovery_ticket()? {
        let password = app.account_password("new account password")?;
        let ticket = client
            .load_recovery_ticket(&password)?
            .ok_or_else(|| CliError::failure("no recovery is saved"))?;
        (ticket, password)
    } else {
        let code = app.read_secret(args.code_stdin, "recovery code")?;
        let password = app.confirmed_secret(app.opts.password_stdin, "new account password")?;
        let ticket = client
            .recover_start(&args.origin, &args.login, code.expose_secret())
            .await?;
        client.save_recovery_ticket(&ticket, &password)?;
        app.out.warn(&format!(
            "Recovery started. Other devices were notified. It can finish at unix time {}; run this command again then and enter the same new password.",
            ticket.release_at
        ));
        (ticket, password)
    };
    let cancel = App::<T>::cancel();
    let outcome = if args.wait {
        wait!(client.recover_finish(&ticket, &new_password, &cancel))?
    } else {
        match client.recover_finish(&ticket, &new_password, &cancel).await {
            Ok(outcome) => outcome,
            Err(hasp_core::CoreError::Pending { retry_after }) => {
                return app.out.record(vec![
                    ("recovered", json!(false)),
                    ("release_at", json!(ticket.release_at)),
                    ("retry_after_s", json!(retry_after)),
                ]);
            }
            Err(hasp_core::CoreError::Credentials) => {
                app.out
                    .note("the server refused this recovery; if it was cancelled, run again with --restart");
                return Err(hasp_core::CoreError::Credentials.into());
            }
            Err(error) => return Err(error.into()),
        }
    };
    let mut state = app.state()?;
    state.origin = Some(args.origin.clone());
    state.note_password(app.now());
    app.state_file.save(&state)?;
    let reveal = app.out.format() == crate::output::Format::Table;
    let secret = |text: &str| {
        if reveal {
            Value::String(text.to_owned())
        } else {
            app.out.secret(text)
        }
    };
    app.out.record(vec![
        ("recovered", json!(true)),
        ("login", json!(outcome.kit.login)),
        ("secret_key", secret(outcome.kit.secret_key())),
        ("recovery_code", secret(outcome.recovery_code.expose())),
    ])
}

pub(crate) async fn emergency_kit<T: Transport>(
    app: &App<'_, T>,
    args: KitArgs,
) -> Result<(), CliError> {
    let outputs = args.pdf_out.is_some() || args.text_out.is_some();
    if app.out.format() == crate::output::Format::Json && !app.out.reveal() && !outputs {
        return Err(CliError::usage(
            "the kit holds the Secret Key: pass --pdf-out FILE, --text-out FILE or --reveal",
        ));
    }
    let client = app.open_local().await?;
    let group = app.read_secret(args.last_group_stdin, "last Secret Key group")?;
    let document = client.emergency_kit(group.expose_secret())?;
    for path in args.pdf_out.iter().chain(args.text_out.iter()) {
        warn_kit_destination(app, path);
    }
    if let Some(path) = &args.pdf_out {
        fsx::write_private(path, &document.pdf)?;
        app.out
            .note(&format!("kit PDF written to {}", path.display()));
    }
    if let Some(path) = &args.text_out {
        fsx::write_private(path, document.text.as_bytes())?;
        app.out
            .note(&format!("kit text written to {}", path.display()));
    }
    let mut fields = vec![
        (
            "pdf",
            json!(args.pdf_out.as_ref().map(|p| p.display().to_string())),
        ),
        (
            "text",
            json!(args.text_out.as_ref().map(|p| p.display().to_string())),
        ),
    ];
    if !outputs {
        let shown = if app.out.format() == crate::output::Format::Table {
            Value::String(document.text.to_string())
        } else {
            app.out.secret(&document.text)
        };
        fields.push(("kit", shown));
    }
    app.out.record(fields)?;
    app.out
        .note("Print the kit and delete the files; deleting does not erase them from an SSD or a backup. Keep the recovery code apart from it.");
    Ok(())
}

pub(crate) async fn reregister<T: Transport>(
    app: &App<'_, T>,
    args: ReregisterArgs,
) -> Result<(), CliError> {
    let fingerprint = hasp_proto::parse_fingerprint(&args.server_fingerprint)
        .map_err(|_| CliError::usage("the server fingerprint does not parse"))?;
    let (mut client, mut state) = app.signed_in_client()?;
    let code = app.read_code(
        args.code.clone(),
        args.code_stdin,
        "code",
        "re-registration code",
    )?;
    let password = app.account_password("account password")?;
    client
        .reregister(
            code.expose_secret(),
            &password,
            fingerprint,
            &App::<T>::cancel(),
        )
        .await?;
    state.note_password(app.now());
    app.state_file.save(&state)?;
    app.out.record(vec![
        ("reregistered", json!(true)),
        ("fingerprint", json!(client.fingerprint()?)),
    ])
}

pub(crate) async fn password<T: Transport>(
    app: &App<'_, T>,
    args: PasswordArgs,
) -> Result<(), CliError> {
    let mut client = app.open().await?;
    let current = app.account_password("current account password")?;
    let new = app.confirmed_secret(args.new_password_stdin, "new account password")?;
    let kit = client
        .change_password(&current, &new, args.new_secret_key, &App::<T>::cancel())
        .await?;
    let mut state = app.state()?;
    state.note_password(app.now());
    app.state_file.save(&state)?;
    match kit {
        Some(kit) => show_kit(app, &kit, None),
        None => app.out.record(vec![("changed", json!(true))]),
    }
}

pub(crate) async fn delete<T: Transport>(
    app: &App<'_, T>,
    args: DeleteArgs,
) -> Result<(), CliError> {
    if !args.yes {
        return Err(CliError::usage(
            "deleting the account is permanent; pass --yes",
        ));
    }
    let mut client = app.open().await?;
    let password = app.account_password("account password")?;
    client
        .delete_account(&password, &App::<T>::cancel())
        .await?;
    signout(app)
}

#[cfg(test)]
mod tests {
    use super::synced_folder;

    #[test]
    fn synced_folders_are_recognised() {
        for path in [
            "/Users/a/Library/Mobile Documents/com~apple~CloudDocs/kit.pdf",
            "/Users/a/Dropbox/kit.txt",
            "/Users/a/Documents/kit.txt",
        ] {
            assert!(synced_folder(std::path::Path::new(path)), "{path}");
        }
        assert!(!synced_folder(std::path::Path::new("/Volumes/usb/kit.txt")));
    }
}
