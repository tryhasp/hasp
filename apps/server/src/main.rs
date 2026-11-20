use std::process::ExitCode;

fn main() -> ExitCode {
    hasp_server::main_with(std::env::args_os())
}
