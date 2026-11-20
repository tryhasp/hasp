use std::time::Duration;

use hasp_core::transport::http::{
    BODY_SLACK, CBOR, Classified, MAX_RETRY_AFTER_S, OVERRIDE_HEADER, PROTOCOL_HEADER, Route,
    bearer_text, classify, is_bulk, is_idempotent, is_transient, resolve,
};
use hasp_core::transport::{Transport, TransportError};
use hasp_proto::wire::{OpId, Operation, PROTOCOL_VERSION, SessionToken};
use hasp_proto::{MAX_RECORD, ProtoError};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderName, HeaderValue, RETRY_AFTER};
use reqwest::{Client, Method, Response, StatusCode, redirect};

use crate::{NetError, tls};
use hasp_core::transport::origin::Origin;
use hasp_core::transport::retry::{RetryPolicy, entropy};

const OVERRIDE: HeaderName = HeaderName::from_static(OVERRIDE_HEADER);
const PROTOCOL: HeaderName = HeaderName::from_static(PROTOCOL_HEADER);

#[derive(Clone, Debug)]
pub struct NetConfig {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    /// Commits, repairs and attachment chunks carry up to 16 MiB; the server allows them 120 s.
    pub bulk_timeout: Duration,
    pub retry: RetryPolicy,
    pub user_agent: String,
}

impl NetConfig {
    pub fn new(user_agent: &str) -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            bulk_timeout: Duration::from_secs(120),
            retry: RetryPolicy::standard(),
            user_agent: user_agent.to_owned(),
        }
    }
}

#[derive(Clone)]
pub struct HttpTransport {
    client: Client,
    origin: Origin,
    config: NetConfig,
}

impl std::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransport")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

struct Reply {
    status: StatusCode,
    retry_after: Option<Duration>,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
struct Outgoing<'a> {
    op: OpId,
    route: &'a Route,
    body: &'a [u8],
    token: Option<&'a SessionToken>,
    timeout: Duration,
}

enum Attempt {
    Reply(Reply),
    Again { retry_after: Option<Duration> },
}

impl HttpTransport {
    pub fn new(origin: Origin, config: NetConfig) -> Result<Self, NetError> {
        let client = Client::builder()
            .user_agent(config.user_agent.as_str())
            .connect_timeout(config.connect_timeout)
            .redirect(redirect::Policy::none())
            .https_only(origin.is_secure())
            .no_proxy()
            .use_preconfigured_tls(tls::client_config()?)
            .build()
            .map_err(|_| NetError::Client)?;
        Ok(Self {
            client,
            origin,
            config,
        })
    }

    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    fn timeout_for(&self, op: OpId) -> Duration {
        if is_bulk(op) {
            self.config.bulk_timeout
        } else {
            self.config.request_timeout
        }
    }

    async fn attempt(&self, outgoing: &Outgoing<'_>) -> Result<Attempt, TransportError> {
        let Outgoing {
            op,
            route,
            body,
            token,
            timeout,
        } = *outgoing;
        let url = self
            .origin
            .http(&route.path)
            .map_err(|_| TransportError::Codec(ProtoError::Format))?;
        let mut request = self
            .client
            .request(Method::POST, url)
            .timeout(timeout)
            .header(CONTENT_TYPE, CBOR)
            .header(ACCEPT, CBOR)
            .header(PROTOCOL, PROTOCOL_VERSION.to_string())
            .body(body.to_vec());
        if let Some(verb) = route.verb.override_name() {
            request = request.header(OVERRIDE, verb);
        }
        if let Some(token) = token {
            request = request.header(AUTHORIZATION, bearer(token)?);
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                tracing::debug!(
                    op = ?op,
                    timeout = error.is_timeout(),
                    connect = error.is_connect(),
                    "request did not complete"
                );
                return Ok(Attempt::Again { retry_after: None });
            }
        };
        let status = response.status();
        let retry_after = retry_after(&response);
        let is_cbor = is_cbor(&response);
        let bytes = match read_body(response).await {
            Ok(bytes) => bytes,
            Err(BodyFault::Oversized) => {
                return Err(TransportError::Codec(ProtoError::Format));
            }
            Err(BodyFault::Interrupted) => return Ok(Attempt::Again { retry_after }),
        };
        if is_transient(status.as_u16(), is_cbor) {
            return Ok(Attempt::Again { retry_after });
        }
        Ok(Attempt::Reply(Reply {
            status,
            retry_after,
            bytes,
        }))
    }
}

impl Transport for HttpTransport {
    async fn call<O: Operation + Sync>(
        &self,
        token: Option<&SessionToken>,
        request: &O,
    ) -> Result<O::Response, TransportError> {
        let body = request.to_cbor()?;
        let route = resolve(O::ID, &body)?;
        let outgoing = Outgoing {
            op: O::ID,
            route: &route,
            body: &body,
            token,
            timeout: self.timeout_for(O::ID),
        };
        let policy = if is_idempotent(O::ID) {
            self.config.retry
        } else {
            RetryPolicy::never()
        };
        let mut tries = 0_u32;
        loop {
            tries = tries.saturating_add(1);
            match self.attempt(&outgoing).await? {
                Attempt::Reply(reply) => {
                    return match classify::<O::Response>(
                        reply.status.as_u16(),
                        reply.retry_after.map(|wait| wait.as_secs()),
                        &reply.bytes,
                    ) {
                        Classified::Reply(result) => result,
                        Classified::Transient => Err(TransportError::Unreachable),
                    };
                }
                Attempt::Again { retry_after } => {
                    if tries >= policy.max_attempts {
                        return Err(TransportError::Unreachable);
                    }
                    let wait = policy
                        .delay(tries, entropy())
                        .max(retry_after.unwrap_or_default().min(policy.max_delay));
                    tracing::debug!(op = ?O::ID, tries, ?wait, "retrying");
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }
}

fn bearer(token: &SessionToken) -> Result<HeaderValue, TransportError> {
    let text = bearer_text(token);
    let mut value =
        HeaderValue::from_str(&text).map_err(|_| TransportError::Codec(ProtoError::Format))?;
    value.set_sensitive(true);
    Ok(value)
}

fn is_cbor(response: &Response) -> bool {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with(CBOR))
}

fn retry_after(response: &Response) -> Option<Duration> {
    let seconds: u64 = response
        .headers()
        .get(RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some(Duration::from_secs(seconds.min(MAX_RETRY_AFTER_S)))
}

enum BodyFault {
    Oversized,
    Interrupted,
}

async fn read_body(mut response: Response) -> Result<Vec<u8>, BodyFault> {
    let limit = MAX_RECORD.saturating_add(BODY_SLACK);
    if response
        .content_length()
        .is_some_and(|length| usize::try_from(length).map_or(true, |length| length > limit))
    {
        return Err(BodyFault::Oversized);
    }
    let mut bytes = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if bytes.len().saturating_add(chunk.len()) > limit {
                    return Err(BodyFault::Oversized);
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(bytes),
            Err(_) => return Err(BodyFault::Interrupted),
        }
    }
}
