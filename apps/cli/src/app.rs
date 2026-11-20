use std::cell::RefCell;
use std::path::PathBuf;

use hasp_core::CoreError;
use hasp_core::client::{Client, ClientConfig};
use hasp_core::platform::Platform;
use hasp_core::store::FileStore;
use hasp_core::transport::{Transport, TransportError};
use secrecy::{ExposeSecret, SecretString};
use tokio_util::sync::CancellationToken;

use crate::env::Env;
use crate::error::{CliError, Kind};
use crate::fsx;
use crate::output::Output;
use crate::state::{State, StateFile};

pub(crate) type Cli<T> = Client<T, FileStore>;

#[derive(Clone, Debug)]
pub(crate) struct Opts {
    pub(crate) data_dir: PathBuf,
    pub(crate) offline: bool,
    pub(crate) no_input: bool,
    pub(crate) password_stdin: bool,
}

#[derive(Debug)]
pub(crate) struct App<'a, T> {
    pub(crate) env: &'a Env<T>,
    pub(crate) out: Output<'a>,
    pub(crate) opts: Opts,
    pub(crate) state_file: StateFile,
    password: RefCell<Option<SecretString>>,
}

impl<'a, T: Transport> App<'a, T> {
    pub(crate) fn new(env: &'a Env<T>, out: Output<'a>, opts: Opts) -> Self {
        let state_file = StateFile::new(&opts.data_dir);
        Self {
            env,
            out,
            opts,
            state_file,
            password: RefCell::new(None),
        }
    }

    pub(crate) fn now(&self) -> u64 {
        self.env.clock.now()
    }

    pub(crate) fn cancel() -> CancellationToken {
        CancellationToken::new()
    }

    pub(crate) fn state(&self) -> Result<State, CliError> {
        self.state_file.load()
    }

    pub(crate) fn read_secret(
        &self,
        from_stdin: bool,
        prompt: &str,
    ) -> Result<SecretString, CliError> {
        if from_stdin {
            let line = self
                .env
                .io
                .stdin_line()?
                .ok_or_else(|| CliError::usage(format!("stdin ended before the {prompt}")))?;
            return Ok(SecretString::from(line));
        }
        if self.opts.no_input || !self.env.io.interactive() {
            return Err(CliError::usage(format!(
                "the {prompt} needs a terminal; read it from stdin with the matching --*-stdin flag"
            )));
        }
        self.env.io.prompt_secret(&format!("{prompt}: "))
    }

    pub(crate) fn read_code(
        &self,
        argv: Option<String>,
        from_stdin: bool,
        flag: &str,
        prompt: &str,
    ) -> Result<SecretString, CliError> {
        let Some(code) = argv else {
            return self.read_secret(from_stdin, prompt);
        };
        self.out.warn(&format!(
            "--{flag} puts the {prompt} in the process list and the shell history; use --{flag}-stdin or the prompt"
        ));
        Ok(SecretString::from(code))
    }

    pub(crate) fn server_fingerprint(
        &self,
        given: Option<&str>,
        source: &str,
    ) -> Result<[u8; 15], CliError> {
        let typed = match given {
            Some(text) => text.to_owned(),
            None if self.opts.no_input || !self.env.io.interactive() => {
                return Err(CliError::usage(
                    "pass --server-fingerprint: the server fingerprint must be compared before the first sign-in",
                ));
            }
            None => self.env.io.prompt_line(&format!(
                "Type the server fingerprint from {source} to confirm this is your server: "
            ))?,
        };
        hasp_proto::parse_fingerprint(typed.trim())
            .map_err(|_| CliError::usage("the server fingerprint does not parse"))
    }

    pub(crate) fn read_line(&self, prompt: &str) -> Result<String, CliError> {
        if self.opts.no_input || !self.env.io.interactive() {
            return Err(CliError::usage(format!("{prompt} needs a terminal")));
        }
        self.env.io.prompt_line(&format!("{prompt}: "))
    }

    pub(crate) fn account_password(&self, prompt: &str) -> Result<SecretString, CliError> {
        if !self.opts.password_stdin {
            return self.read_secret(false, prompt);
        }
        let mut cached = self.password.borrow_mut();
        if let Some(known) = cached.as_ref() {
            return Ok(SecretString::from(known.expose_secret().to_owned()));
        }
        let typed = self.read_secret(true, prompt)?;
        *cached = Some(SecretString::from(typed.expose_secret().to_owned()));
        Ok(typed)
    }

    pub(crate) fn confirmed_secret(
        &self,
        from_stdin: bool,
        prompt: &str,
    ) -> Result<SecretString, CliError> {
        let first = self.read_secret(from_stdin, prompt)?;
        if from_stdin {
            return Ok(first);
        }
        let again = self.read_secret(false, &format!("{prompt} again"))?;
        if hasp_crypto::ct_eq(
            first.expose_secret().as_bytes(),
            again.expose_secret().as_bytes(),
        ) {
            Ok(first)
        } else {
            Err(CliError::usage("the two entries differ"))
        }
    }

    fn platform(&self) -> Platform {
        Platform {
            secure: self.env.secure.clone(),
            biometric: self.env.biometric.clone(),
            clock: self.env.clock.clone(),
        }
    }

    pub(crate) fn client(&self, origin: &str) -> Result<Cli<T>, CliError> {
        fsx::private_dir(&self.opts.data_dir)?;
        let store = FileStore::open(&self.opts.data_dir.join("store")).map_err(CoreError::from)?;
        let transport = (self.env.transport)(origin)?;
        Ok(Client::new(
            transport,
            store,
            self.platform(),
            ClientConfig::new(&self.env.platform_name),
        ))
    }

    pub(crate) fn signed_in_client(&self) -> Result<(Cli<T>, State), CliError> {
        let state = self.state()?;
        let origin = state
            .origin
            .clone()
            .ok_or_else(|| CliError::locked("not signed in; run `hasp signin`"))?;
        let client = self.client(&origin)?;
        if client.state()? == hasp_core::client::ClientState::Empty {
            return Err(CliError::locked("not signed in; run `hasp signin`"));
        }
        Ok((client, state))
    }

    pub(crate) async fn unlock(
        &self,
        client: &mut Cli<T>,
        state: &mut State,
    ) -> Result<(), CliError> {
        if client.is_unlocked() {
            return Ok(());
        }
        let now = self.now();
        if let Some(wait) = state.lockout_remaining(now) {
            let mut error = CliError::new(Kind::Auth, "too many failed attempts");
            error.retry_after = Some(wait);
            return Err(error);
        }
        let cancel = Self::cancel();
        if self.env.secure.hardware_gated() && !state.password_due(now) && !self.opts.password_stdin
        {
            match client.unlock_biometric(&cancel).await {
                Ok(()) => return Ok(()),
                Err(CoreError::Refused(_) | CoreError::SessionExpired | CoreError::Platform(_)) => {
                    self.out
                        .note("the device gate did not release the key; using the password");
                }
                Err(error) => return Err(error.into()),
            }
        }
        let password = self.account_password("account password")?;
        match client.unlock_password(&password, &cancel).await {
            Ok(()) => {
                state.note_password(now);
                self.state_file.save(state)?;
                Ok(())
            }
            Err(CoreError::Credentials) => {
                state.note_failure(now);
                self.state_file.save(state)?;
                Err(CoreError::Credentials.into())
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) async fn sync_quietly(&self, client: &mut Cli<T>) -> Result<(), CliError> {
        if self.opts.offline {
            return Ok(());
        }
        match client.sync(&Self::cancel()).await {
            Ok(_) => Ok(()),
            Err(CoreError::Transport(TransportError::Unreachable)) => {
                self.out
                    .note("the server is unreachable; showing the local copy");
                Ok(())
            }
            Err(CoreError::Proto(
                hasp_proto::ProtoError::Rollback | hasp_proto::ProtoError::Fork,
            )) => {
                self.warn_server_behind(client);
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn warn_server_behind(&self, client: &Cli<T>) {
        let Ok(vaults) = client.vaults() else { return };
        for vault in vaults.iter().filter(|v| v.server_behind.is_some()) {
            self.out.warn(&format!(
                "the server holds vault {} at a state that differs from this device's; if you restored the server on purpose run `hasp vault accept-rollback {} --yes`",
                vault.name,
                hasp_crypto::to_hex(vault.vault_id.as_bytes()),
            ));
        }
    }

    pub(crate) async fn open(&self) -> Result<Cli<T>, CliError> {
        let (mut client, mut state) = self.signed_in_client()?;
        self.unlock(&mut client, &mut state).await?;
        self.sync_quietly(&mut client).await?;
        Ok(client)
    }

    pub(crate) async fn open_local(&self) -> Result<Cli<T>, CliError> {
        let (mut client, mut state) = self.signed_in_client()?;
        self.unlock(&mut client, &mut state).await?;
        Ok(client)
    }

    pub(crate) async fn push(
        &self,
        client: &mut Cli<T>,
        vaults: &[hasp_proto::VaultId],
    ) -> Result<(), CliError> {
        if self.opts.offline {
            self.out.note("queued; run `hasp sync` to upload");
            return Ok(());
        }
        for vault in vaults {
            match client.flush(vault, &Self::cancel()).await {
                Ok(_) => {}
                Err(CoreError::Transport(TransportError::Unreachable)) => {
                    self.out
                        .note("the server is unreachable; the change is queued for the next sync");
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}
