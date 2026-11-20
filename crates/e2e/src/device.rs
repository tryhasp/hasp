use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::TempDir;

use crate::bins::bins;

static FINGERPRINTS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

pub(crate) fn remember_fingerprint(origin: &str, fingerprint: &str) {
    let mut known = FINGERPRINTS.lock().unwrap();
    known.retain(|(known_origin, _)| known_origin != origin);
    known.push((origin.to_owned(), fingerprint.to_owned()));
}

fn fingerprint_of(origin: &str) -> String {
    let known = FINGERPRINTS.lock().unwrap();
    let Some((_, fingerprint)) = known.iter().find(|(known, _)| known == origin) else {
        panic!("no fingerprint was printed for {origin}")
    };
    fingerprint.clone()
}

const COMMAND_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug)]
pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Out {
    #[track_caller]
    #[expect(
        clippy::return_self_not_must_use,
        reason = "an assertion helper usually called for its panic"
    )]
    pub fn ok(self) -> Self {
        assert_eq!(
            self.code, 0,
            "exit {} stdout: {} stderr: {}",
            self.code, self.stdout, self.stderr
        );
        self
    }

    #[track_caller]
    #[expect(
        clippy::return_self_not_must_use,
        reason = "an assertion helper usually called for its panic"
    )]
    pub fn exit(self, code: i32) -> Self {
        assert_eq!(
            self.code, code,
            "exit {} stdout: {} stderr: {}",
            self.code, self.stdout, self.stderr
        );
        self
    }

    #[track_caller]
    pub fn json(&self) -> Value {
        serde_json::from_str(self.stdout.trim())
            .unwrap_or_else(|_| panic!("stdout is not json: {}", self.stdout))
    }

    #[track_caller]
    pub fn data(&self) -> Value {
        let document = self.json();
        assert_eq!(document["schema_version"], 1, "{}", self.stdout);
        assert!(document.get("error").is_none(), "{}", self.stdout);
        document["data"].clone()
    }

    #[track_caller]
    pub fn error(&self) -> Value {
        let document = self.json();
        assert_eq!(document["schema_version"], 1, "{}", self.stdout);
        assert_eq!(document["error"]["exit"], self.code, "{}", self.stdout);
        document["error"].clone()
    }

    #[track_caller]
    pub fn text(&self, key: &str) -> String {
        self.data()[key]
            .as_str()
            .unwrap_or_else(|| panic!("no string {key} in {}", self.stdout))
            .to_owned()
    }
}

#[derive(Debug)]
pub struct Device {
    home: TempDir,
    pub origin: String,
    pub login: String,
    pub password: String,
}

impl Device {
    pub fn new(origin: &str, login: &str, password: &str) -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            origin: origin.to_owned(),
            login: login.to_owned(),
            password: password.to_owned(),
        }
    }

    pub fn home(&self) -> &Path {
        self.home.path()
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.home.path().join(name)
    }

    pub fn start_raw(&self, args: &[&str], stdin: &str) -> Running {
        let mut command = Command::new(&bins().hasp);
        command
            .arg("--data-dir")
            .arg(self.home.path())
            .arg("--json")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut running = Running::spawn(command);
        running.write(stdin);
        running
    }

    pub fn raw(&self, args: &[&str], stdin: &str) -> Out {
        self.start_raw(args, stdin).finish()
    }

    pub fn start(&self, args: &[&str], stdin: &[&str]) -> Running {
        let mut full = vec!["--password-stdin"];
        full.extend_from_slice(args);
        let mut text = format!("{}\n", self.password);
        for line in stdin {
            text.push_str(line);
            text.push('\n');
        }
        self.start_raw(&full, &text)
    }

    pub fn run(&self, args: &[&str], stdin: &[&str]) -> Out {
        self.start(args, stdin).finish()
    }

    #[track_caller]
    pub fn data(&self, args: &[&str]) -> Value {
        self.run(args, &[]).ok().data()
    }

    pub fn signup(&self, code: &str) -> Out {
        self.raw(
            &[
                "--password-stdin",
                "--reveal",
                "signup",
                "--origin",
                &self.origin,
                "--login",
                &self.login,
                "--code-stdin",
                "--server-fingerprint",
                &fingerprint_of(&self.origin),
            ],
            &format!("{code}\n{}\n", self.password),
        )
    }

    pub fn signin_with_kit(&self, secret_key: &str, fingerprint: Option<&str>) -> Out {
        let mut args = vec![
            "--password-stdin",
            "signin",
            "--origin",
            &self.origin,
            "--login",
            &self.login,
            "--secret-key-stdin",
        ];
        let trusted = fingerprint_of(&self.origin);
        args.push("--server-fingerprint");
        args.push(fingerprint.unwrap_or(&trusted));
        self.raw(&args, &format!("{secret_key}\n{}\n", self.password))
    }
}

#[derive(Debug)]
pub struct Running {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    stderr: Arc<Mutex<String>>,
    stderr_reader: Option<JoinHandle<()>>,
    stdout_reader: Option<JoinHandle<String>>,
}

impl Running {
    fn spawn(mut command: Command) -> Self {
        let mut child = command.spawn().unwrap();
        let stdin = child.stdin.take();
        let stderr_pipe = child.stderr.take().unwrap();
        let mut stdout_pipe = child.stdout.take().unwrap();
        let (sender, lines) = channel();
        let stderr = Arc::new(Mutex::new(String::new()));
        let collected = Arc::clone(&stderr);
        let stderr_reader = std::thread::spawn(move || {
            for line in BufReader::new(stderr_pipe).lines() {
                let Ok(line) = line else { break };
                let mut all = collected.lock().unwrap();
                all.push_str(&line);
                all.push('\n');
                drop(all);
                sender.send(line).ok();
            }
        });
        let stdout_reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout_pipe.read_to_end(&mut bytes).ok();
            String::from_utf8_lossy(&bytes).into_owned()
        });
        Self {
            child,
            stdin,
            lines,
            stderr,
            stderr_reader: Some(stderr_reader),
            stdout_reader: Some(stdout_reader),
        }
    }

    pub fn write(&mut self, text: &str) {
        if let Some(stdin) = self.stdin.as_mut() {
            stdin.write_all(text.as_bytes()).ok();
            stdin.flush().ok();
        }
    }

    pub fn stderr_so_far(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    #[track_caller]
    pub fn wait_stderr(&mut self, needle: &str, within: Duration) -> String {
        let deadline = Instant::now() + within;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(remaining) {
                Ok(line) if line.contains(needle) => return line,
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => panic!(
                    "stderr never showed {needle:?}; so far: {}",
                    self.stderr_so_far()
                ),
            }
        }
    }

    pub fn finish(mut self) -> Out {
        self.stdin = None;
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                self.child.kill().ok();
                self.child.wait().ok();
                panic!("command timed out; stderr: {}", self.stderr_so_far());
            }
            crate::pause(Duration::from_millis(10));
        };
        self.stderr_reader.take().unwrap().join().ok();
        let stdout = self.stdout_reader.take().unwrap().join().unwrap();
        Out {
            code: status.code().unwrap_or(-1),
            stdout,
            stderr: self.stderr_so_far(),
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}
