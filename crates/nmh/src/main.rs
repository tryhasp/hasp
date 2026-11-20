use std::process::ExitCode;

#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    use std::io;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    use hasp_nmh::host::{HostIo, HostPolicy, run};
    use hasp_nmh::identity;
    use hasp_nmh::ipc::{connect, group_container_dir};
    use hasp_nmh::origin::ExtensionAllowlist;
    use hasp_nmh::peer::{Requirement, Signing};

    #[cfg(feature = "dev-extension")]
    std::hint::black_box(identity::DEV_BUILD_MARKER);
    let Some(team) = identity::TEAM_ID else {
        return ExitCode::from(2);
    };
    let Some(home) = std::env::home_dir() else {
        return ExitCode::from(2);
    };
    let Ok(app) = Requirement::signed_by(&[identity::APP_IDENTIFIER], team, Signing::DeveloperId)
    else {
        return ExitCode::from(2);
    };
    let allowlist = ExtensionAllowlist::published();
    let policy = HostPolicy {
        allowlist: &allowlist,
        app,
    };
    let dir: PathBuf = group_container_dir(&home, team);
    let Ok(owner) = std::fs::metadata(&home).map(|m| m.uid()) else {
        return ExitCode::from(2);
    };
    let args: Vec<String> = std::env::args().collect();
    let outcome = run(
        &hasp_nmh::macos::SystemVerifier,
        &policy,
        &args,
        HostIo {
            connect: || connect(&dir, owner).map_err(|e| io::Error::other(e.to_string())),
            browser_in: io::stdin(),
            browser_out: io::stdout(),
        },
    );
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

#[cfg(not(target_os = "macos"))]
fn main() -> ExitCode {
    ExitCode::from(2)
}
