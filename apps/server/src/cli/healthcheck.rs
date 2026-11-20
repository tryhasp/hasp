use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use super::CliError;
use crate::settings::Settings;

pub(super) fn healthcheck(settings: &Settings) -> Result<(), CliError> {
    check(local_address(settings.listen))
}

fn local_address(listen: SocketAddr) -> SocketAddr {
    let ip = match listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::from([127, 0, 0, 1]),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]),
        other => other,
    };
    SocketAddr::new(ip, listen.port())
}

pub(crate) fn check(address: SocketAddr) -> Result<(), CliError> {
    let timeout = Duration::from_secs(5);
    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut head = [0_u8; 12];
    stream.read_exact(&mut head)?;
    if head.starts_with(b"HTTP/1.1 200") {
        Ok(())
    } else {
        Err(CliError::Failed("server is not healthy".to_owned()))
    }
}
