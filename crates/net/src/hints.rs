use std::collections::BTreeSet;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hasp_proto::VaultId;
use hasp_proto::base64url;
use hasp_proto::wire::SessionToken;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::{Connector, connect_async_tls_with_config};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{NetError, tls};
use hasp_core::transport::origin::Origin;
use hasp_core::transport::retry::{RetryPolicy, entropy};

const PATH: &str = "/v1/ws";
const MAX_FRAME: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hint {
    Vault { vault: VaultId, seq: u64 },
    Notice,
    SessionRevoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HintEnd {
    Cancelled,
    SessionRevoked,
    Rejected,
}

#[derive(Clone, Debug)]
pub struct HintConfig {
    pub connect_timeout: Duration,
    pub ping_every: Duration,
    /// The server answers every ping, so silence for this long means the socket is dead.
    pub silence_limit: Duration,
    /// A connection that delivered a frame resets the backoff.
    pub reconnect: RetryPolicy,
    pub channel: usize,
}

impl HintConfig {
    pub const fn standard() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            ping_every: Duration::from_secs(30),
            silence_limit: Duration::from_secs(75),
            reconnect: RetryPolicy {
                max_attempts: u32::MAX,
                base_delay: Duration::from_secs(1),
                max_delay: Duration::from_secs(300),
            },
            channel: 64,
        }
    }
}

pub struct HintClient {
    origin: Origin,
    config: HintConfig,
    connector: Connector,
}

impl std::fmt::Debug for HintClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HintClient")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct AuthFrame<'a> {
    t: &'static str,
    token: &'a str,
}

#[derive(Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum Frame {
    Hint {
        vault: String,
        seq: u64,
    },
    Notice,
    Pong,
    SessionRevoked,
    #[serde(other)]
    Unknown,
}

enum Ended {
    Dropped { delivered: bool },
    Revoked,
    Rejected,
    Cancelled,
}

impl HintClient {
    pub fn new(origin: Origin, config: HintConfig) -> Result<Self, NetError> {
        let connector = if origin.is_secure() {
            Connector::Rustls(std::sync::Arc::new(tls::client_config()?))
        } else {
            Connector::Plain
        };
        Ok(Self {
            origin,
            config,
            connector,
        })
    }

    pub fn channel(&self) -> (mpsc::Sender<Hint>, mpsc::Receiver<Hint>) {
        mpsc::channel(self.config.channel)
    }

    /// Reconnects with backoff until cancelled, the session is revoked or the server refuses the
    /// token. A full channel drops a hint, because the hint already queued wakes the same pull.
    pub async fn run(
        &self,
        token: &SessionToken,
        hints: &mpsc::Sender<Hint>,
        cancel: &CancellationToken,
    ) -> HintEnd {
        let mut failures = 0_u32;
        loop {
            let ended = tokio::select! {
                () = cancel.cancelled() => Ended::Cancelled,
                ended = self.session(token, hints) => ended,
            };
            match ended {
                Ended::Cancelled => return HintEnd::Cancelled,
                Ended::Revoked => return HintEnd::SessionRevoked,
                Ended::Rejected => return HintEnd::Rejected,
                Ended::Dropped { delivered } => {
                    failures = if delivered {
                        1
                    } else {
                        failures.saturating_add(1)
                    };
                    let wait = self.config.reconnect.delay(failures, entropy());
                    tracing::debug!(failures, ?wait, "hint socket down");
                    tokio::select! {
                        () = cancel.cancelled() => return HintEnd::Cancelled,
                        () = tokio::time::sleep(wait) => {}
                    }
                }
            }
        }
    }

    async fn session(&self, token: &SessionToken, hints: &mpsc::Sender<Hint>) -> Ended {
        let Ok(url) = self.origin.websocket(PATH) else {
            return Ended::Rejected;
        };
        let limits = WebSocketConfig::default()
            .max_message_size(Some(MAX_FRAME))
            .max_frame_size(Some(MAX_FRAME));
        let connect = connect_async_tls_with_config(
            url.as_str(),
            Some(limits),
            true,
            Some(self.connector.clone()),
        );
        let Ok(Ok((mut socket, _))) = timeout(self.config.connect_timeout, connect).await else {
            return Ended::Dropped { delivered: false };
        };
        let encoded = Zeroizing::new(base64url::encode(token.as_bytes()));
        let Ok(auth) = serde_json::to_string(&AuthFrame {
            t: "auth",
            token: &encoded,
        }) else {
            return Ended::Rejected;
        };
        if socket.send(Message::text(auth)).await.is_err() {
            return Ended::Dropped { delivered: false };
        }
        let mut delivered = false;
        let mut last_heard = Instant::now();
        let mut ticker = tokio::time::interval(self.config.ping_every);
        ticker.reset();
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if last_heard.elapsed() > self.config.silence_limit
                        || socket.send(Message::text(r#"{"t":"ping"}"#)).await.is_err()
                    {
                        return Ended::Dropped { delivered };
                    }
                }
                message = socket.next() => {
                    let Some(Ok(message)) = message else {
                        return Ended::Dropped { delivered };
                    };
                    last_heard = Instant::now();
                    match message {
                        Message::Text(text) => match parse(text.as_str()) {
                            Some(Hint::SessionRevoked) => {
                                let _delivered = hints.try_send(Hint::SessionRevoked);
                                return Ended::Revoked;
                            }
                            Some(hint) => {
                                delivered = true;
                                let _queued = hints.try_send(hint);
                            }
                            None => delivered = true,
                        },
                        Message::Close(frame) => {
                            let policy = frame
                                .is_some_and(|frame| frame.code == CloseCode::Policy);
                            return if policy && !delivered {
                                Ended::Rejected
                            } else {
                                Ended::Dropped { delivered }
                            };
                        }
                        Message::Binary(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
                    }
                }
            }
        }
    }
}

fn parse(text: &str) -> Option<Hint> {
    match serde_json::from_str::<Frame>(text).ok()? {
        Frame::Hint { vault, seq } => Some(Hint::Vault {
            vault: VaultId::from_bytes(base64url::decode_array(&vault)?),
            seq,
        }),
        Frame::Notice => Some(Hint::Notice),
        Frame::SessionRevoked => Some(Hint::SessionRevoked),
        Frame::Pong | Frame::Unknown => None,
    }
}

/// What a burst of hints asks for: one pull covers all of it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Wake {
    pub vaults: BTreeSet<VaultId>,
    pub notice: bool,
    pub session_revoked: bool,
}

impl Wake {
    fn absorb(&mut self, hint: Hint) {
        match hint {
            Hint::Vault { vault, .. } => {
                self.vaults.insert(vault);
            }
            Hint::Notice => self.notice = true,
            Hint::SessionRevoked => self.session_revoked = true,
        }
    }
}

/// Waits for a hint, then keeps absorbing for `quiet` after the last one, so a burst of commits
/// costs one sync. Returns `None` when every sender is gone.
pub async fn next_wake(hints: &mut mpsc::Receiver<Hint>, quiet: Duration) -> Option<Wake> {
    let mut wake = Wake::default();
    wake.absorb(hints.recv().await?);
    while let Ok(Some(hint)) = timeout(quiet, hints.recv()).await {
        wake.absorb(hint);
    }
    Some(wake)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault(byte: u8) -> VaultId {
        VaultId::from_bytes([byte; 16])
    }

    #[test]
    fn parses_each_server_frame() {
        let id = base64url::encode(&[9; 16]);
        assert_eq!(
            parse(&format!(r#"{{"t":"hint","vault":"{id}","seq":7}}"#)),
            Some(Hint::Vault {
                vault: vault(9),
                seq: 7
            })
        );
        assert_eq!(parse(r#"{"t":"notice"}"#), Some(Hint::Notice));
        assert_eq!(
            parse(r#"{"t":"session_revoked"}"#),
            Some(Hint::SessionRevoked)
        );
        assert_eq!(parse(r#"{"t":"pong"}"#), None);
    }

    #[test]
    fn ignores_unknown_and_malformed_frames() {
        assert_eq!(parse(r#"{"t":"future"}"#), None);
        assert_eq!(parse("not json"), None);
        assert_eq!(parse(r#"{"t":"hint","vault":"@@","seq":1}"#), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_becomes_one_wake() {
        let (tx, mut rx) = mpsc::channel(8);
        tx.send(Hint::Vault {
            vault: vault(1),
            seq: 1,
        })
        .await
        .unwrap();
        tx.send(Hint::Vault {
            vault: vault(2),
            seq: 4,
        })
        .await
        .unwrap();
        tx.send(Hint::Vault {
            vault: vault(1),
            seq: 2,
        })
        .await
        .unwrap();
        tx.send(Hint::Notice).await.unwrap();
        let wake = next_wake(&mut rx, Duration::from_millis(50)).await.unwrap();
        assert_eq!(wake.vaults, BTreeSet::from([vault(1), vault(2)]));
        assert!(wake.notice && !wake.session_revoked);
    }

    #[tokio::test(start_paused = true)]
    async fn the_wake_ends_after_the_quiet_window() {
        let (tx, mut rx) = mpsc::channel(8);
        tx.send(Hint::Notice).await.unwrap();
        let first = next_wake(&mut rx, Duration::from_millis(50)).await.unwrap();
        assert!(first.vaults.is_empty());
        tx.send(Hint::SessionRevoked).await.unwrap();
        let second = next_wake(&mut rx, Duration::from_millis(50)).await.unwrap();
        assert!(second.session_revoked && !second.notice);
        drop(tx);
        assert_eq!(next_wake(&mut rx, Duration::from_millis(50)).await, None);
    }
}
