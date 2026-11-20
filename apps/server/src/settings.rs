use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use axum::http::HeaderName;
use serde::Deserialize;
use url::Url;

use crate::http::{Capacity, Cidr, HttpOptions};
use crate::rate::Limits;

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error("cannot read config file {0}")]
    Read(PathBuf),
    #[error("config file is invalid: {0}")]
    Parse(String),
    #[error("{name}: {reason}")]
    Invalid {
        name: &'static str,
        reason: &'static str,
    },
}

fn invalid(name: &'static str, reason: &'static str) -> SettingsError {
    SettingsError::Invalid { name, reason }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    login_per_peer: Option<u32>,
    login_failures: Option<u32>,
    register_per_peer: Option<u32>,
    recovery_per_subject: Option<u32>,
    recovery_per_peer: Option<u32>,
    general_per_subject: Option<u32>,
    socket_per_peer: Option<u32>,
    backoff_cap: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTimeouts {
    request_secs: Option<u64>,
    transfer_secs: Option<u64>,
    shutdown_secs: Option<u64>,
    header_secs: Option<u64>,
    body_idle_secs: Option<u64>,
    chunk_transfers: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCapacity {
    connections: Option<usize>,
    inflight_mib: Option<usize>,
    peer_inflight_mib: Option<usize>,
    peer_requests: Option<usize>,
    workers: Option<usize>,
    queue_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSettings {
    public_url: Option<String>,
    listen: Option<String>,
    data_dir: Option<PathBuf>,
    server_key: Option<PathBuf>,
    backup_dir: Option<PathBuf>,
    backup_keep: Option<usize>,
    trusted_proxies: Option<Vec<String>>,
    client_ip_header: Option<String>,
    log: Option<String>,
    limits: Option<RawLimits>,
    timeouts: Option<RawTimeouts>,
    capacity: Option<RawCapacity>,
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub origin: Option<String>,
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub server_key: Option<PathBuf>,
    pub backup_dir: Option<PathBuf>,
    pub backup_keep: usize,
    pub trusted_proxies: Vec<Cidr>,
    pub client_ip_header: Option<HeaderName>,
    pub log: String,
    pub limits: Limits,
    pub request_timeout: Duration,
    pub transfer_timeout: Duration,
    pub shutdown_grace: Duration,
    pub header_timeout: Duration,
    pub body_idle_timeout: Duration,
    pub chunk_transfers: usize,
    pub capacity: Capacity,
}

pub const CONFIG_ENV: &str = "HASP_CONFIG";

impl Settings {
    pub fn load(
        file: Option<&Path>,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, SettingsError> {
        let named = file
            .map(Path::to_path_buf)
            .or_else(|| env(CONFIG_ENV).map(PathBuf::from));
        let mut raw = match named {
            Some(path) => {
                let text = std::fs::read_to_string(&path).map_err(|_| SettingsError::Read(path))?;
                toml::from_str::<RawSettings>(&text)
                    .map_err(|error| SettingsError::Parse(error.message().to_owned()))?
            }
            None => RawSettings::default(),
        };
        overlay(&mut raw, env)?;
        raw.resolve()
    }

    pub fn origin(&self) -> Result<&str, SettingsError> {
        self.origin
            .as_deref()
            .ok_or_else(|| invalid("public_url", "required to serve"))
    }

    pub fn http_options(&self) -> HttpOptions {
        HttpOptions {
            trusted_proxies: self.trusted_proxies.clone(),
            client_ip_header: self.client_ip_header.clone(),
            request_timeout: self.request_timeout,
            transfer_timeout: self.transfer_timeout,
            chunk_transfers: self.chunk_transfers,
            shutdown_grace: self.shutdown_grace,
            header_timeout: self.header_timeout,
            body_idle_timeout: self.body_idle_timeout,
            capacity: self.capacity,
            ..HttpOptions::default()
        }
    }
}

fn number<T: std::str::FromStr>(
    env: &dyn Fn(&str) -> Option<String>,
    key: &str,
    name: &'static str,
) -> Result<Option<T>, SettingsError> {
    env(key)
        .map(|text| text.trim().parse::<T>())
        .transpose()
        .map_err(|_| invalid(name, "must be a number"))
}

macro_rules! set_number {
    ($env:expr, $target:expr, $field:ident, $key:literal) => {
        if let Some(value) = number($env, $key, stringify!($field))? {
            $target.$field = Some(value);
        }
    };
}

fn overlay(
    raw: &mut RawSettings,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<(), SettingsError> {
    overlay_values(raw, env)?;
    overlay_limits(raw.limits.get_or_insert_with(RawLimits::default), env)?;
    overlay_timeouts(raw.timeouts.get_or_insert_with(RawTimeouts::default), env)?;
    overlay_capacity(raw.capacity.get_or_insert_with(RawCapacity::default), env)
}

fn overlay_values(
    raw: &mut RawSettings,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<(), SettingsError> {
    if let Some(value) = env("HASP_PUBLIC_URL") {
        raw.public_url = Some(value);
    }
    if let Some(value) = env("HASP_LISTEN") {
        raw.listen = Some(value);
    }
    if let Some(value) = env("HASP_DATA_DIR") {
        raw.data_dir = Some(PathBuf::from(value));
    }
    if let Some(value) = env("HASP_SERVER_KEY") {
        raw.server_key = Some(PathBuf::from(value));
    }
    if let Some(value) = env("HASP_BACKUP_DIR") {
        raw.backup_dir = Some(PathBuf::from(value));
    }
    set_number!(env, raw, backup_keep, "HASP_BACKUP_KEEP");
    if let Some(value) = env("HASP_CLIENT_IP_HEADER") {
        raw.client_ip_header = Some(value);
    }
    if let Some(value) = env("HASP_TRUSTED_PROXIES") {
        raw.trusted_proxies = Some(
            value
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(str::to_owned)
                .collect(),
        );
    }
    if let Some(value) = env("HASP_LOG") {
        raw.log = Some(value);
    }
    Ok(())
}

fn overlay_limits(
    limits: &mut RawLimits,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<(), SettingsError> {
    set_number!(env, limits, login_per_peer, "HASP_LIMIT_LOGIN_PER_PEER");
    set_number!(env, limits, login_failures, "HASP_LIMIT_LOGIN_FAILURES");
    set_number!(
        env,
        limits,
        register_per_peer,
        "HASP_LIMIT_REGISTER_PER_PEER"
    );
    set_number!(
        env,
        limits,
        recovery_per_subject,
        "HASP_LIMIT_RECOVERY_PER_SUBJECT"
    );
    set_number!(
        env,
        limits,
        recovery_per_peer,
        "HASP_LIMIT_RECOVERY_PER_PEER"
    );
    set_number!(
        env,
        limits,
        general_per_subject,
        "HASP_LIMIT_GENERAL_PER_SUBJECT"
    );
    set_number!(env, limits, socket_per_peer, "HASP_LIMIT_SOCKET_PER_PEER");
    set_number!(env, limits, backoff_cap, "HASP_LIMIT_BACKOFF_CAP");
    Ok(())
}

fn overlay_timeouts(
    timeouts: &mut RawTimeouts,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<(), SettingsError> {
    set_number!(env, timeouts, request_secs, "HASP_REQUEST_TIMEOUT_SECS");
    set_number!(env, timeouts, transfer_secs, "HASP_TRANSFER_TIMEOUT_SECS");
    set_number!(env, timeouts, shutdown_secs, "HASP_SHUTDOWN_SECS");
    set_number!(env, timeouts, header_secs, "HASP_HEADER_TIMEOUT_SECS");
    set_number!(env, timeouts, body_idle_secs, "HASP_BODY_IDLE_TIMEOUT_SECS");
    Ok(())
}

fn overlay_capacity(
    capacity: &mut RawCapacity,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<(), SettingsError> {
    set_number!(env, capacity, connections, "HASP_MAX_CONNECTIONS");
    set_number!(env, capacity, inflight_mib, "HASP_INFLIGHT_MIB");
    set_number!(env, capacity, peer_inflight_mib, "HASP_PEER_INFLIGHT_MIB");
    set_number!(env, capacity, peer_requests, "HASP_PEER_REQUESTS");
    set_number!(env, capacity, workers, "HASP_WORKERS");
    Ok(())
}

fn positive<T: PartialOrd + Default>(
    value: Option<T>,
    default: T,
    name: &'static str,
) -> Result<T, SettingsError> {
    let value = value.unwrap_or(default);
    if value > T::default() {
        Ok(value)
    } else {
        Err(invalid(name, "must be greater than zero"))
    }
}

fn resolve_capacity(
    raw: RawCapacity,
    secs: impl Fn(Option<u64>, u64, &'static str) -> Result<Duration, SettingsError>,
) -> Result<Capacity, SettingsError> {
    let fallback = Capacity::default();
    let mib = |value: Option<usize>, default: usize, name| {
        positive(
            value.map(|mib| mib.saturating_mul(1024 * 1024)),
            default,
            name,
        )
    };
    Ok(Capacity {
        max_connections: positive(raw.connections, fallback.max_connections, "connections")?,
        inflight_bytes: mib(raw.inflight_mib, fallback.inflight_bytes, "inflight_mib")?,
        peer_inflight_bytes: mib(
            raw.peer_inflight_mib,
            fallback.peer_inflight_bytes,
            "peer_inflight_mib",
        )?,
        peer_requests: positive(raw.peer_requests, fallback.peer_requests, "peer_requests")?,
        workers: positive(raw.workers, fallback.workers, "workers")?,
        queue_wait: secs(raw.queue_secs, 5, "queue_secs")?,
    })
}

impl RawSettings {
    fn resolve(self) -> Result<Settings, SettingsError> {
        let origin = self.public_url.as_deref().map(parse_origin).transpose()?;
        let data_dir = self.data_dir.unwrap_or_else(|| PathBuf::from("data"));
        if data_dir.as_os_str().is_empty() {
            return Err(invalid("data_dir", "must not be empty"));
        }
        let timeouts = self.timeouts.unwrap_or_default();
        let secs = |value: Option<u64>, default: u64, name| {
            positive(value, default, name).map(Duration::from_secs)
        };
        let capacity = resolve_capacity(self.capacity.unwrap_or_default(), secs)?;
        Ok(Settings {
            origin,
            listen: parse_listen(self.listen.as_deref())?,
            data_dir,
            server_key: self.server_key,
            backup_dir: self.backup_dir,
            backup_keep: positive(self.backup_keep, crate::backup::DEFAULT_KEEP, "backup_keep")?,
            trusted_proxies: parse_proxies(&self.trusted_proxies.unwrap_or_default())?,
            client_ip_header: parse_client_ip_header(self.client_ip_header.as_deref())?,
            log: parse_log(self.log)?,
            limits: resolve_limits(self.limits.unwrap_or_default())?,
            request_timeout: secs(timeouts.request_secs, 30, "request_secs")?,
            transfer_timeout: secs(timeouts.transfer_secs, 120, "transfer_secs")?,
            shutdown_grace: secs(timeouts.shutdown_secs, 10, "shutdown_secs")?,
            header_timeout: secs(timeouts.header_secs, 10, "header_secs")?,
            body_idle_timeout: secs(timeouts.body_idle_secs, 10, "body_idle_secs")?,
            chunk_transfers: positive(timeouts.chunk_transfers, 64, "chunk_transfers")?,
            capacity,
        })
    }
}

fn parse_listen(text: Option<&str>) -> Result<SocketAddr, SettingsError> {
    match text {
        Some(text) => text
            .trim()
            .parse::<SocketAddr>()
            .map_err(|_| invalid("listen", "must be host:port with an IP address")),
        None => Ok(SocketAddr::from(([127, 0, 0, 1], 8080))),
    }
}

fn parse_proxies(entries: &[String]) -> Result<Vec<Cidr>, SettingsError> {
    entries
        .iter()
        .map(|text| Cidr::parse(text))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            invalid(
                "trusted_proxies",
                "entries must be IP addresses or CIDR blocks",
            )
        })
}

fn parse_client_ip_header(text: Option<&str>) -> Result<Option<HeaderName>, SettingsError> {
    match text.map(str::trim) {
        None | Some("") => Ok(None),
        Some(name) => HeaderName::from_bytes(name.as_bytes())
            .map(Some)
            .map_err(|_| invalid("client_ip_header", "must be an HTTP header name")),
    }
}

fn parse_log(level: Option<String>) -> Result<String, SettingsError> {
    let level = level.unwrap_or_else(|| "info".to_owned());
    if matches!(
        level.as_str(),
        "error" | "warn" | "info" | "debug" | "trace"
    ) {
        Ok(level)
    } else {
        Err(invalid("log", "must be error, warn, info, debug or trace"))
    }
}

fn resolve_limits(raw: RawLimits) -> Result<Limits, SettingsError> {
    let defaults = Limits::default();
    Ok(Limits {
        login_per_peer: positive(
            raw.login_per_peer,
            defaults.login_per_peer,
            "login_per_peer",
        )?,
        login_failures: positive(
            raw.login_failures,
            defaults.login_failures,
            "login_failures",
        )?,
        register_per_peer: positive(
            raw.register_per_peer,
            defaults.register_per_peer,
            "register_per_peer",
        )?,
        recovery_per_subject: positive(
            raw.recovery_per_subject,
            defaults.recovery_per_subject,
            "recovery_per_subject",
        )?,
        recovery_per_peer: positive(
            raw.recovery_per_peer,
            defaults.recovery_per_peer,
            "recovery_per_peer",
        )?,
        general_per_subject: positive(
            raw.general_per_subject,
            defaults.general_per_subject,
            "general_per_subject",
        )?,
        socket_per_peer: positive(
            raw.socket_per_peer,
            defaults.socket_per_peer,
            "socket_per_peer",
        )?,
        backoff_cap: positive(raw.backoff_cap, defaults.backoff_cap, "backoff_cap")?,
        max_entries: defaults.max_entries,
    })
}

fn parse_origin(text: &str) -> Result<String, SettingsError> {
    let url = Url::parse(text.trim()).map_err(|_| invalid("public_url", "is not a URL"))?;
    let clean = url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    if !clean {
        return Err(invalid(
            "public_url",
            "must be an origin without path, query or credentials",
        ));
    }
    let loopback = match url.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => return Err(invalid("public_url", "has no host")),
    };
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => {
            return Err(invalid(
                "public_url",
                "must be https (http only for localhost)",
            ));
        }
    }
    Ok(url.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(pairs: &'static [(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        move |key| {
            pairs
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    fn load(pairs: &'static [(&str, &str)]) -> Result<Settings, SettingsError> {
        Settings::load(None, &env_of(pairs))
    }

    #[test]
    fn snapshot_retention_defaults_to_seven_and_is_configurable() {
        assert_eq!(load(&[]).unwrap().backup_keep, 7);
        assert_eq!(load(&[("HASP_BACKUP_KEEP", "14")]).unwrap().backup_keep, 14);
        assert!(load(&[("HASP_BACKUP_KEEP", "0")]).is_err());
        assert!(load(&[("HASP_BACKUP_KEEP", "some")]).is_err());
    }

    #[test]
    fn defaults_are_valid_without_any_input() {
        let settings = load(&[]).unwrap();
        assert_eq!(settings.listen, SocketAddr::from(([127, 0, 0, 1], 8080)));
        assert_eq!(settings.log, "info");
        assert!(settings.origin.is_none());
        assert!(settings.origin().is_err());
        assert_eq!(
            settings.limits.login_per_peer,
            Limits::default().login_per_peer
        );
    }

    #[test]
    fn environment_overrides_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("haspd.toml");
        std::fs::write(
            &path,
            "public_url = \"https://a.example\"\nlisten = \"0.0.0.0:9000\"\n[limits]\nlogin_per_peer = 3\n",
        )
        .unwrap();
        let env = env_of(&[
            ("HASP_PUBLIC_URL", "https://b.example"),
            ("HASP_LIMIT_LOGIN_FAILURES", "9"),
        ]);
        let settings = Settings::load(Some(&path), &env).unwrap();
        assert_eq!(settings.origin().unwrap(), "https://b.example");
        assert_eq!(settings.listen.port(), 9000);
        assert_eq!(settings.limits.login_per_peer, 3);
        assert_eq!(settings.limits.login_failures, 9);
    }

    #[test]
    fn config_path_comes_from_the_environment() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, "public_url = \"https://c.example\"\n").unwrap();
        let text = path.to_str().unwrap().to_owned();
        let env = move |key: &str| (key == CONFIG_ENV).then(|| text.clone());
        assert_eq!(
            Settings::load(None, &env).unwrap().origin().unwrap(),
            "https://c.example"
        );
    }

    #[test]
    fn origin_must_be_a_clean_https_origin() {
        for bad in [
            "http://hasp.example.com",
            "https://hasp.example.com/path",
            "https://u:p@hasp.example.com",
            "https://hasp.example.com/?q=1",
            "hasp.example.com",
            "ftp://hasp.example.com",
        ] {
            let text = Box::leak(bad.to_owned().into_boxed_str());
            let pairs: &'static [(&str, &str)] =
                Box::leak(vec![("HASP_PUBLIC_URL", &*text)].into_boxed_slice());
            assert!(load(pairs).is_err(), "{bad}");
        }
        assert_eq!(
            load(&[("HASP_PUBLIC_URL", "https://Hasp.Example.com:443/")])
                .unwrap()
                .origin()
                .unwrap(),
            "https://hasp.example.com"
        );
        assert!(load(&[("HASP_PUBLIC_URL", "http://localhost:8080")]).is_ok());
    }

    #[test]
    fn rejects_unknown_keys_zero_limits_and_bad_proxies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "surprise = 1\n").unwrap();
        assert!(Settings::load(Some(&path), &env_of(&[])).is_err());
        assert!(load(&[("HASP_LIMIT_LOGIN_PER_PEER", "0")]).is_err());
        assert!(load(&[("HASP_LIMIT_LOGIN_PER_PEER", "many")]).is_err());
        assert!(load(&[("HASP_TRUSTED_PROXIES", "10.0.0.0/40")]).is_err());
        assert!(load(&[("HASP_LISTEN", "localhost")]).is_err());
        assert!(load(&[("HASP_LOG", "loud")]).is_err());
    }

    #[test]
    fn trusted_proxies_parse_from_a_comma_list() {
        let settings = load(&[("HASP_TRUSTED_PROXIES", "172.16.0.0/12, ::1")]).unwrap();
        assert_eq!(settings.trusted_proxies.len(), 2);
    }

    #[test]
    fn client_ip_header_is_empty_by_default_and_validated() {
        assert!(load(&[]).unwrap().client_ip_header.is_none());
        assert!(
            load(&[("HASP_CLIENT_IP_HEADER", "")])
                .unwrap()
                .client_ip_header
                .is_none()
        );
        let settings = load(&[("HASP_CLIENT_IP_HEADER", "CF-Connecting-IP")]).unwrap();
        assert_eq!(
            settings.client_ip_header.unwrap().as_str(),
            "cf-connecting-ip"
        );
        assert!(load(&[("HASP_CLIENT_IP_HEADER", "not a header")]).is_err());
    }
}
