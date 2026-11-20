macro_rules! wait {
    ($call:expr) => {
        loop {
            match $call.await {
                Err(hasp_core::CoreError::Pending { .. }) => {
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
                other => break other.map_err($crate::error::CliError::from),
            }
        }
    };
}

mod account;
mod devices;
mod file;
mod item;
mod read;
mod tools;
mod transfer;
mod vault;

use hasp_core::transport::Transport;

use crate::app::App;
use crate::cli::{AccountCmd, Command};
use crate::error::CliError;

pub(crate) async fn dispatch<T: Transport>(
    app: &App<'_, T>,
    command: Command,
) -> Result<(), CliError> {
    match command {
        Command::Signup(args) => account::signup(app, args).await,
        Command::Signin(args) => account::signin(app, args).await,
        Command::Signout => account::signout(app),
        Command::Whoami => account::whoami(app),
        Command::Lock => account::lock(app),
        Command::Unlock => account::unlock(app).await,
        Command::Status => account::status(app),
        Command::Account(cmd) => match cmd {
            AccountCmd::RecoveryCode(args) => account::recovery(app, args.action).await,
            AccountCmd::Password(args) => account::password(app, args).await,
            AccountCmd::Enrol(args) => account::enrol(app, args).await,
            AccountCmd::EmergencyKit(args) => account::emergency_kit(app, args).await,
            AccountCmd::Reregister(args) => account::reregister(app, args).await,
            AccountCmd::Delete(args) => account::delete(app, args).await,
        },
        Command::Devices(cmd) => devices::run(app, cmd).await,
        Command::Vault(cmd) => vault::run(app, cmd).await,
        Command::Item(cmd) => item::run(app, cmd).await,
        Command::File(cmd) => file::run(app, cmd).await,
        Command::Read(args) => read::run(app, args).await,
        Command::Otp(target) => item::totp(app, target).await,
        Command::Generate(args) => tools::generate(app, &args),
        Command::Import(cmd) => transfer::import(app, cmd).await,
        Command::Export(args) => transfer::export(app, args).await,
        Command::Backup(cmd) => transfer::backup(app, cmd).await,
        Command::Restore(args) => transfer::restore(app, args).await,
        Command::Sync => tools::sync(app).await,
        Command::Admin(cmd) => tools::admin(app, cmd).await,
    }
}
