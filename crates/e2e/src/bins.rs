use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

#[derive(Debug)]
pub struct Bins {
    pub haspd: PathBuf,
    pub hasp: PathBuf,
}

pub fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/e2e sits two levels below the repo root")
}

// Why: the workspace test build links `hasp` and `haspd` without the `testing`
// feature into the same paths, so a shared target dir swaps the binaries
// under running tests.
fn e2e_target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| repo_root().join("target"), PathBuf::from)
        .join("e2e-bins")
}

pub fn bins() -> &'static Bins {
    static BINS: OnceLock<Bins> = OnceLock::new();
    BINS.get_or_init(build)
}

fn build() -> Bins {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(repo_root())
        .env("CARGO_TARGET_DIR", e2e_target_dir())
        .args([
            "build",
            "--locked",
            "-p",
            "hasp-server",
            "-p",
            "hasp-cli",
            "--features",
            "hasp-server/testing",
            "--message-format=json-render-diagnostics",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .expect("cargo runs");
    assert!(output.status.success(), "building haspd and hasp failed");
    let mut haspd = None;
    let mut hasp = None;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if message["reason"] != "compiler-artifact" {
            continue;
        }
        let Some(path) = message["executable"].as_str() else {
            continue;
        };
        match message["target"]["name"].as_str() {
            Some("haspd") => haspd = Some(PathBuf::from(path)),
            Some("hasp") => hasp = Some(PathBuf::from(path)),
            _ => {}
        }
    }
    Bins {
        haspd: haspd.expect("haspd binary was built"),
        hasp: hasp.expect("hasp binary was built"),
    }
}
