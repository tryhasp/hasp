use std::time::Duration;

use axum::http::HeaderName;

use super::identity::Cidr;

#[derive(Clone, Copy, Debug)]
pub struct SocketOptions {
    pub auth_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_per_session: usize,
    pub max_frame: usize,
    pub queue: usize,
    pub max_messages: u32,
    pub message_window: Duration,
}

impl Default for SocketOptions {
    fn default() -> Self {
        Self {
            auth_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(90),
            max_per_session: 5,
            max_frame: 4096,
            queue: 64,
            max_messages: 60,
            message_window: Duration::from_secs(10),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Capacity {
    pub max_connections: usize,
    pub inflight_bytes: usize,
    pub peer_inflight_bytes: usize,
    pub peer_requests: usize,
    pub workers: usize,
    pub queue_wait: Duration,
}

impl Default for Capacity {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            inflight_bytes: 128 * 1024 * 1024,
            peer_inflight_bytes: 32 * 1024 * 1024,
            peer_requests: 64,
            workers: 32,
            queue_wait: Duration::from_secs(5),
        }
    }
}

#[derive(Clone, Debug)]
pub struct HttpOptions {
    pub trusted_proxies: Vec<Cidr>,
    pub client_ip_header: Option<HeaderName>,
    pub request_timeout: Duration,
    pub transfer_timeout: Duration,
    pub chunk_transfers: usize,
    pub maintenance_interval: Duration,
    pub shutdown_grace: Duration,
    pub header_timeout: Duration,
    pub body_idle_timeout: Duration,
    pub capacity: Capacity,
    pub socket: SocketOptions,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            client_ip_header: None,
            request_timeout: Duration::from_secs(30),
            transfer_timeout: Duration::from_secs(120),
            chunk_transfers: 64,
            maintenance_interval: Duration::from_secs(30),
            shutdown_grace: Duration::from_secs(10),
            header_timeout: Duration::from_secs(10),
            body_idle_timeout: Duration::from_secs(10),
            capacity: Capacity::default(),
            socket: SocketOptions::default(),
        }
    }
}
