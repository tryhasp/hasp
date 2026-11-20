use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use hasp_core::platform::SystemClock;
use hasp_core::transport::Transport;

use crate::app::{App, Opts};
use crate::cli::{Cli, FormatArg};
use crate::commands;
use crate::env::{Env, StdIo, TransportFactory};
use crate::error::CliError;
use crate::output::{Format, Output, report_error};
use crate::secure::{StoreGate, platform_name, platform_store};

fn default_data_dir() -> PathBuf {
    let home = |relative: &str| {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default()
            .join(relative)
    };
    if cfg!(target_os = "macos") {
        home("Library/Application Support/hasp")
    } else if cfg!(target_os = "windows") {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_default()
            .join("hasp")
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .unwrap_or_else(|| home(".local/share"))
            .join("hasp")
    }
}

pub fn system_env<T>(transport: TransportFactory<T>) -> Env<T> {
    let secure = platform_store();
    let biometric = Arc::new(StoreGate::new(secure.as_ref()));
    Env {
        io: Box::new(StdIo),
        default_data_dir: default_data_dir(),
        platform_name: platform_name().to_owned(),
        secure,
        biometric,
        clock: Arc::new(SystemClock),
        transport,
    }
}

pub fn run<T: Transport>(args: &[OsString], env: &Env<T>) -> u8 {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let code = u8::from(error.use_stderr()) * 2;
            let text = error.render().to_string();
            if error.use_stderr() {
                env.io.err(&text);
            } else {
                env.io.out(text.as_bytes()).ok();
            }
            return code;
        }
    };
    let requested = if cli.json {
        Some(Format::Json)
    } else {
        cli.format.map(|f| match f {
            FormatArg::Table => Format::Table,
            FormatArg::Json => Format::Json,
        })
    };
    let out = Output::new(env.io.as_ref(), requested, cli.quiet, cli.reveal);
    let format = out.format();
    let opts = Opts {
        data_dir: cli
            .data_dir
            .clone()
            .unwrap_or_else(|| env.default_data_dir.clone()),
        offline: cli.offline,
        no_input: cli.no_input,
        password_stdin: cli.password_stdin,
    };
    let app = App::new(env, out, opts);
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        report_error(
            env.io.as_ref(),
            format,
            &CliError::failure("the async runtime did not start"),
        );
        return 1;
    };
    match runtime.block_on(commands::dispatch(&app, cli.command)) {
        Ok(()) => 0,
        Err(error) => {
            report_error(env.io.as_ref(), format, &error);
            error.exit_code()
        }
    }
}
