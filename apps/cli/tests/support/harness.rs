#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness aborts on a broken fixture"
)]

use std::ffi::OsString;
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Condvar, Mutex};

use hasp_cli::{CliError, Env, Io};
use hasp_core::platform::{ManualClock, MemorySecureStore, ScriptedBiometric};
use hasp_core::transport::{Transport, TransportError};
use hasp_proto::wire::{Operation, SessionToken};
use hasp_server::{MemoryStore, Server};
use hasp_testsupport::{InProcess, World, block_on};
use secrecy::SecretString;
use tempfile::TempDir;

#[derive(Debug)]
pub(crate) struct Outcome {
    pub(crate) code: u8,
    pub(crate) out: String,
    pub(crate) err: String,
}

impl Outcome {
    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::from_str(self.out.trim()).expect("stdout is json")
    }

    pub(crate) fn data(&self) -> serde_json::Value {
        self.json()["data"].clone()
    }

    pub(crate) fn ok(self) -> Self {
        assert_eq!(self.code, 0, "exit {} stderr: {}", self.code, self.err);
        self
    }
}

#[derive(Debug, Default)]
pub(crate) struct Stderr {
    text: Mutex<String>,
    changed: Condvar,
}

impl Stderr {
    fn push(&self, text: &str) {
        self.text.lock().unwrap().push_str(text);
        self.changed.notify_all();
    }

    fn len(&self) -> usize {
        self.text.lock().unwrap().len()
    }

    fn since(&self, start: usize) -> String {
        self.text.lock().unwrap()[start..].to_owned()
    }
}

pub(crate) struct ScriptIo {
    out: Arc<Mutex<Vec<u8>>>,
    err: Arc<Stderr>,
    stdin: Receiver<String>,
}

impl Io for ScriptIo {
    fn out(&self, bytes: &[u8]) -> Result<(), CliError> {
        self.out
            .lock()
            .map_err(|_| CliError::failure("poisoned"))?
            .extend_from_slice(bytes);
        Ok(())
    }

    fn err(&self, text: &str) {
        self.err.push(text);
    }

    fn stdout_is_tty(&self) -> bool {
        false
    }

    fn interactive(&self) -> bool {
        false
    }

    fn prompt_secret(&self, _prompt: &str) -> Result<SecretString, CliError> {
        Err(CliError::usage("no terminal"))
    }

    fn prompt_line(&self, _prompt: &str) -> Result<String, CliError> {
        Err(CliError::usage("no terminal"))
    }

    fn stdin_line(&self) -> Result<Option<String>, CliError> {
        Ok(self.stdin.recv().ok())
    }

    fn stdin_all(&self) -> Result<Vec<u8>, CliError> {
        let lines: Vec<String> = self.stdin.try_iter().collect();
        Ok(lines.join("\n").into_bytes())
    }
}

#[derive(Debug)]
pub(crate) struct Down;

impl Transport for Down {
    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the failure is immediate; async is the trait signature"
    )]
    async fn call<O: Operation + Sync>(
        &self,
        _token: Option<&SessionToken>,
        _request: &O,
    ) -> Result<O::Response, TransportError> {
        Err(TransportError::Unreachable)
    }
}

pub(crate) struct Device {
    pub(crate) dir: TempDir,
    stderr: Arc<Stderr>,
    pub(crate) secure: Arc<MemorySecureStore>,
    pub(crate) clock: Arc<ManualClock>,
    server: Arc<Server<MemoryStore>>,
}

impl Device {
    pub(crate) fn new(world: &World, hardware: bool) -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            stderr: Arc::new(Stderr::default()),
            secure: Arc::new(MemorySecureStore::new(hardware)),
            clock: Arc::new(ManualClock::new(1_000_000)),
            server: Arc::clone(&world.server),
        }
    }

    pub(crate) fn run(&self, args: &[&str], stdin: &[&str]) -> Outcome {
        let (sender, receiver) = channel();
        for line in stdin {
            sender.send((*line).to_owned()).unwrap();
        }
        drop(sender);
        self.run_with(args, receiver)
    }

    pub(crate) fn run_with(&self, args: &[&str], stdin: Receiver<String>) -> Outcome {
        let start = self.stderr.len();
        let (env, out) = self.env(stdin, Arc::clone(&self.server));
        let mut outcome = run_env(&env, self.dir.path(), args, &out);
        outcome.err = self.stderr.since(start);
        outcome
    }

    pub(crate) fn run_down(&self, args: &[&str], stdin: &[&str]) -> Outcome {
        let (sender, receiver) = channel();
        for line in stdin {
            sender.send((*line).to_owned()).unwrap();
        }
        drop(sender);
        let (out, err, io) = capture(receiver, Arc::clone(&self.stderr));
        let env = Env {
            io: Box::new(io),
            default_data_dir: self.dir.path().to_path_buf(),
            platform_name: "linux".to_owned(),
            secure: self.secure.clone(),
            biometric: Arc::new(ScriptedBiometric::new(false, false)),
            clock: self.clock.clone(),
            transport: Box::new(|_| Ok(Down)),
        };
        let start = err.len();
        let mut outcome = finish(&env, self.dir.path(), args, &out);
        outcome.err = err.since(start);
        outcome
    }

    fn env(
        &self,
        stdin: Receiver<String>,
        server: Arc<Server<MemoryStore>>,
    ) -> (Env<InProcess<MemoryStore>>, Arc<Mutex<Vec<u8>>>) {
        let (out, _, io) = capture(stdin, Arc::clone(&self.stderr));
        let hardware = self.secure_gated();
        let env = Env {
            io: Box::new(io),
            default_data_dir: self.dir.path().to_path_buf(),
            platform_name: if hardware { "macos" } else { "linux" }.to_owned(),
            secure: self.secure.clone(),
            biometric: Arc::new(ScriptedBiometric::new(hardware, hardware)),
            clock: self.clock.clone(),
            transport: Box::new(move |_| Ok(InProcess::new(Arc::clone(&server)))),
        };
        (env, out)
    }

    fn secure_gated(&self) -> bool {
        use hasp_core::platform::SecureStore;
        self.secure.hardware_gated()
    }
}

type Captured = Arc<Mutex<Vec<u8>>>;

fn capture(stdin: Receiver<String>, err: Arc<Stderr>) -> (Captured, Arc<Stderr>, ScriptIo) {
    let out = Arc::new(Mutex::new(Vec::new()));
    let io = ScriptIo {
        out: Arc::clone(&out),
        err: Arc::clone(&err),
        stdin,
    };
    (out, err, io)
}

fn run_env(
    env: &Env<InProcess<MemoryStore>>,
    dir: &std::path::Path,
    args: &[&str],
    out: &Arc<Mutex<Vec<u8>>>,
) -> Outcome {
    finish(env, dir, args, out)
}

fn finish<T: Transport>(
    env: &Env<T>,
    dir: &std::path::Path,
    args: &[&str],
    out: &Arc<Mutex<Vec<u8>>>,
) -> Outcome {
    let mut full: Vec<OsString> = vec!["hasp".into(), "--data-dir".into(), dir.into()];
    full.extend(args.iter().map(OsString::from));
    let code = hasp_cli::run(&full, env);
    Outcome {
        code,
        out: String::from_utf8(out.lock().unwrap().clone()).unwrap(),
        err: String::new(),
    }
}

pub(crate) fn wait_for_line(device: &Device, pick: impl Fn(&str) -> Option<String>) -> String {
    let mut text = device.stderr.text.lock().unwrap();
    loop {
        if let Some(found) = text.lines().find_map(&pick) {
            return found;
        }
        text = device.stderr.changed.wait(text).unwrap();
    }
}

pub(crate) fn fingerprint(world: &World) -> String {
    hasp_proto::format_fingerprint(&world.fingerprint())
}

pub(crate) fn signup_code(world: &mut World) -> String {
    block_on(world.token())
}

pub(crate) const ORIGIN: &str = hasp_testsupport::TEST_ORIGIN;
pub(crate) const PASSWORD: &str = "correct horse battery staple";

pub(crate) fn signed_up(world: &mut World, login: &str, hardware: bool) -> Device {
    let device = Device::new(world, hardware);
    let code = signup_code(world);
    let result = device.run(
        &[
            "--password-stdin",
            "signup",
            "--origin",
            ORIGIN,
            "--login",
            login,
            "--code-stdin",
            "--server-fingerprint",
            &fingerprint(world),
            "--reveal",
        ],
        &[&code, PASSWORD],
    );
    assert_eq!(result.code, 0, "signup failed: {}", result.err);
    device
}

pub(crate) fn assert_golden(name: &str, actual: &str) {
    let normalised = normalise(actual);
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{name}.txt"));
    if std::env::var_os("HASP_UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, &normalised).unwrap();
        return;
    }
    let expected =
        std::fs::read_to_string(&path).expect("missing golden file; run with HASP_UPDATE_GOLDEN=1");
    assert_eq!(normalised, expected, "golden {name}");
}

fn normalise(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let run = bytes[i..]
            .iter()
            .take_while(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            .count();
        if run >= 32 {
            out.push_str("<id>");
            i += 32;
        } else {
            out.push(char::from(bytes[i]));
            i += 1;
        }
    }
    out
}
