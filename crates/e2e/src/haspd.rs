use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

use crate::bins::bins;
use crate::device::Out;

pub fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[derive(Debug)]
pub struct Init {
    pub code: String,
    pub fingerprint: String,
    pub output: String,
}

#[derive(Debug)]
pub struct Haspd {
    root: TempDir,
    pub port: u16,
    pub origin: String,
    recovery_delay: Option<u64>,
    production_limits: bool,
    child: Option<Child>,
}

impl Haspd {
    pub fn new() -> Self {
        let port = free_port();
        Self {
            root: tempfile::tempdir().unwrap(),
            port,
            origin: format!("http://127.0.0.1:{port}"),
            recovery_delay: None,
            production_limits: false,
            child: None,
        }
    }

    #[must_use]
    pub fn recovery_delay(mut self, seconds: u64) -> Self {
        self.recovery_delay = Some(seconds);
        self
    }

    #[must_use]
    pub fn production_limits(mut self) -> Self {
        self.production_limits = true;
        self
    }

    pub fn data_dir(&self) -> PathBuf {
        self.root.path().join("data")
    }

    pub fn backups_dir(&self) -> PathBuf {
        self.root.path().join("snapshots")
    }

    pub fn key_path(&self) -> PathBuf {
        self.data_dir().join("secrets").join("server.key")
    }

    pub fn log_path(&self) -> PathBuf {
        self.root.path().join("haspd.log")
    }

    pub fn scratch(&self) -> &Path {
        self.root.path()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(&bins().haspd);
        command
            .args(args)
            .env("HASP_DATA_DIR", self.data_dir())
            .env("HASP_PUBLIC_URL", &self.origin)
            .env("HASP_LISTEN", format!("127.0.0.1:{}", self.port))
            .env(
                "HASP_LOG",
                std::env::var("HASP_E2E_LOG").unwrap_or_else(|_| "warn".to_owned()),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if !self.production_limits {
            command
                .env("HASP_LIMIT_LOGIN_PER_PEER", "100000")
                .env("HASP_LIMIT_REGISTER_PER_PEER", "100000")
                .env("HASP_LIMIT_GENERAL_PER_SUBJECT", "10000000");
        }
        if let Some(seconds) = self.recovery_delay {
            command.env("HASP_TEST_RECOVERY_DELAY_SECS", seconds.to_string());
        }
        command
    }

    pub fn run(&self, args: &[&str], stdin: &str) -> Out {
        let mut child = self.command(args).spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        Out {
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    pub fn init(&self) -> Init {
        let out = self.run(&["init"], "").ok();
        let fingerprint = out
            .stdout
            .lines()
            .find_map(|line| line.strip_prefix("fingerprint: "))
            .map(|text| text.trim().to_owned());
        if let Some(fingerprint) = fingerprint {
            crate::device::remember_fingerprint(&self.origin, &fingerprint);
        }
        let find = |prefix: &str| {
            out.stdout
                .lines()
                .find_map(|line| line.strip_prefix(prefix))
                .unwrap_or_else(|| panic!("init prints {prefix}: {}", out.stdout))
                .trim()
                .to_owned()
        };
        Init {
            code: find("first signup code (makes you the admin): "),
            fingerprint: find("fingerprint: "),
            output: out.stdout.clone(),
        }
    }

    pub fn fingerprint(&self) -> String {
        let fingerprint = self.run(&["fingerprint"], "").ok().stdout.trim().to_owned();
        crate::device::remember_fingerprint(&self.origin, &fingerprint);
        fingerprint
    }

    pub fn signup_code(&self) -> String {
        self.run(&["admin", "signup-code"], "")
            .ok()
            .stdout
            .trim()
            .to_owned()
    }

    pub fn start(&mut self) {
        assert!(self.child.is_none(), "already running");
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log_path())
            .unwrap();
        self.child = Some(
            self.command(&["serve"])
                .stdout(Stdio::null())
                .stderr(log)
                .spawn()
                .unwrap(),
        );
        self.wait_ready();
    }

    pub fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "haspd did not stop on SIGTERM");
            crate::pause(Duration::from_millis(20));
        }
    }

    pub fn restart(&mut self) {
        self.stop();
        self.start();
    }

    pub fn healthz(&self) -> Option<u16> {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, self.port));
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(500)).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .ok()?;
        let mut head = [0_u8; 12];
        stream.read_exact(&mut head).ok()?;
        String::from_utf8_lossy(&head)
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
    }

    fn wait_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if self.healthz() == Some(200) {
                return;
            }
            let exited = self
                .child
                .as_mut()
                .and_then(|child| child.try_wait().unwrap());
            if let Some(status) = exited {
                let log = std::fs::read_to_string(self.log_path()).unwrap_or_default();
                panic!("haspd exited early with {status}: {log}");
            }
            assert!(Instant::now() < deadline, "haspd did not become healthy");
            crate::pause(Duration::from_millis(25));
        }
    }
}

impl Default for Haspd {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Haspd {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            child.kill().ok();
            child.wait().ok();
        }
    }
}

pub const PASSWORD: &str = "correct horse battery staple";

impl Haspd {
    pub fn boot() -> (Self, Init) {
        let mut server = Self::new();
        let init = server.init();
        server.start();
        (server, init)
    }

    pub fn account(&self, login: &str, code: &str) -> crate::device::Device {
        let device = crate::device::Device::new(&self.origin, login, PASSWORD);
        device.signup(code).ok();
        device
    }
}
