use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use hasp_core::platform::{Biometric, Clock, SecureStore};
use secrecy::SecretString;

use crate::error::CliError;

pub trait Io {
    fn out(&self, bytes: &[u8]) -> Result<(), CliError>;
    fn err(&self, text: &str);
    fn stdout_is_tty(&self) -> bool;
    fn interactive(&self) -> bool;
    fn prompt_secret(&self, prompt: &str) -> Result<SecretString, CliError>;
    fn prompt_line(&self, prompt: &str) -> Result<String, CliError>;
    fn stdin_line(&self) -> Result<Option<String>, CliError>;
    fn stdin_all(&self) -> Result<Vec<u8>, CliError>;
}

#[derive(Debug)]
pub struct StdIo;

impl Io for StdIo {
    fn out(&self, bytes: &[u8]) -> Result<(), CliError> {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(bytes)?;
        stdout.flush()?;
        Ok(())
    }

    fn err(&self, text: &str) {
        let mut stderr = std::io::stderr().lock();
        stderr.write_all(text.as_bytes()).ok();
    }

    fn stdout_is_tty(&self) -> bool {
        std::io::stdout().is_terminal()
    }

    fn interactive(&self) -> bool {
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
    }

    fn prompt_secret(&self, prompt: &str) -> Result<SecretString, CliError> {
        self.err(prompt);
        let typed = rpassword::read_password()?;
        Ok(SecretString::from(typed))
    }

    fn prompt_line(&self, prompt: &str) -> Result<String, CliError> {
        self.err(prompt);
        Ok(self.stdin_line()?.unwrap_or_default())
    }

    fn stdin_line(&self) -> Result<Option<String>, CliError> {
        let mut line = String::new();
        let read = std::io::stdin().lock().read_line(&mut line)?;
        if read == 0 {
            return Ok(None);
        }
        Ok(Some(line.trim_end_matches(['\n', '\r']).to_owned()))
    }

    fn stdin_all(&self) -> Result<Vec<u8>, CliError> {
        let mut bytes = Vec::new();
        std::io::stdin().lock().read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

pub type TransportFactory<T> = Box<dyn Fn(&str) -> Result<T, CliError>>;

pub struct Env<T> {
    pub io: Box<dyn Io>,
    pub default_data_dir: PathBuf,
    pub platform_name: String,
    pub secure: Arc<dyn SecureStore>,
    pub biometric: Arc<dyn Biometric>,
    pub clock: Arc<dyn Clock>,
    pub transport: TransportFactory<T>,
}

impl<T> std::fmt::Debug for Env<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Env(..)")
    }
}
