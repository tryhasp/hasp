use std::process::ExitCode;

use hasp_cli::{CliError, run, system_env};
use hasp_net::{HttpTransport, NetConfig, Origin};

fn connect(origin: &str) -> Result<HttpTransport, CliError> {
    let origin = Origin::parse(origin).map_err(|error| CliError::usage(error.to_string()))?;
    HttpTransport::new(
        origin,
        NetConfig::new(concat!("hasp-cli/", env!("CARGO_PKG_VERSION"))),
    )
    .map_err(|error| CliError::failure(error.to_string()))
}

fn main() -> ExitCode {
    let env = system_env(Box::new(connect));
    ExitCode::from(run(&std::env::args_os().collect::<Vec<_>>(), &env))
}
