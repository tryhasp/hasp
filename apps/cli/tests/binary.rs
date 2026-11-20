#![expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]

use std::io::Write;
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

use hasp_proto::{SecretAscii, SecretKind, encode_secret_key};
use hasp_server::{Gateway, HttpOptions, MemoryStore, Server};
use hasp_testsupport::World;
use serde_json::Value;

const PASSWORD: &str = "correct horse battery staple";

struct Live {
    origin: String,
    world: World,
    home: tempfile::TempDir,
}

fn hasp() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin("hasp"))
}

fn serve() -> Live {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let adjusted = origin.clone();
    let world = World::with_config(move |config| config.origin = adjusted);
    let server: Arc<Server<MemoryStore>> = Arc::clone(&world.server);
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let gateway: Gateway<MemoryStore> = Gateway::new(server, HttpOptions::default());
            gateway.run(listener, std::future::pending()).await.unwrap();
        });
    });
    Live {
        origin,
        world,
        home: tempfile::tempdir().unwrap(),
    }
}

fn run(live: &Live, args: &[&str], stdin: &str) -> Output {
    let mut child = hasp()
        .arg("--data-dir")
        .arg(live.home.path())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn data(output: &Output) -> Value {
    let text = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str::<Value>(text.trim()).unwrap()["data"].clone()
}

fn failed(output: &Output) -> String {
    format!(
        "exit {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn usage_errors_exit_two_and_help_exits_zero() {
    let bad = hasp().arg("frobnicate").output().unwrap();
    assert_eq!(bad.status.code(), Some(2));
    let help = hasp().arg("--help").output().unwrap();
    assert_eq!(help.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage: hasp"));
    let version = hasp().arg("--version").output().unwrap();
    assert_eq!(version.status.code(), Some(0));
}

#[test]
fn commands_that_need_an_account_exit_three_when_signed_out() {
    let home = tempfile::tempdir().unwrap();
    let out = hasp()
        .arg("--data-dir")
        .arg(home.path())
        .args(["--json", "item", "list"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["error"]["exit"], 3);
    assert_eq!(body["schema_version"], 1);
}

#[test]
fn an_unreachable_server_exits_seven() {
    let home = tempfile::tempdir().unwrap();
    let mut child = hasp()
        .arg("--data-dir")
        .arg(home.path())
        .args([
            "--password-stdin",
            "signin",
            "--origin",
            "http://127.0.0.1:1",
            "--login",
            "ada",
            "--secret-key-stdin",
            "--server-fingerprint",
            "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let key = encode_secret_key(SecretKind::SecretKey, &SecretAscii::generate().unwrap()).unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{}\npassword\n", key.expose()).as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(7), "{}", failed(&out));
}

#[test]
fn the_binary_runs_a_full_session_over_real_http() {
    let live = serve();
    let code = live.world.server.issue_bootstrap_token().unwrap().to_text();
    let signup = run(
        &live,
        &[
            "--password-stdin",
            "--json",
            "--reveal",
            "signup",
            "--origin",
            &live.origin,
            "--login",
            "ada",
            "--code-stdin",
            "--server-fingerprint",
            &hasp_proto::format_fingerprint(&live.world.fingerprint()),
        ],
        &format!("{code}\n{PASSWORD}\n"),
    );
    assert_eq!(signup.status.code(), Some(0), "{}", failed(&signup));
    assert!(
        data(&signup)["secret_key"]
            .as_str()
            .unwrap()
            .starts_with("V1-")
    );

    let created = run(
        &live,
        &[
            "--password-stdin",
            "--json",
            "item",
            "create",
            "--title",
            "GitHub",
            "--field",
            "username=ada",
            "--field-stdin",
            "password",
        ],
        &format!("{PASSWORD}\nreal-http-secret-1\n"),
    );
    assert_eq!(created.status.code(), Some(0), "{}", failed(&created));

    let read = run(
        &live,
        &[
            "--password-stdin",
            "--format",
            "table",
            "read",
            "hasp://Private/GitHub/password",
        ],
        &format!("{PASSWORD}\n"),
    );
    assert_eq!(read.status.code(), Some(0), "{}", failed(&read));
    assert_eq!(String::from_utf8_lossy(&read.stdout), "real-http-secret-1");

    let wrong = run(
        &live,
        &["--password-stdin", "item", "list"],
        "nope nope nope\n",
    );
    assert_eq!(wrong.status.code(), Some(8));

    let listed = run(
        &live,
        &["--password-stdin", "--json", "item", "list"],
        &format!("{PASSWORD}\n"),
    );
    assert_eq!(data(&listed).as_array().unwrap().len(), 1);
    assert!(!String::from_utf8_lossy(&listed.stdout).contains("real-http-secret-1"));
}
