use std::future::Future;
use std::time::Duration;

use hasp_core::transport::http::{
    CBOR, Classified, MAX_RETRY_AFTER_S, OVERRIDE_HEADER, PROTOCOL_HEADER, Route, bearer_text,
    classify, is_bulk, is_idempotent, is_transient, resolve,
};
use hasp_core::transport::origin::Origin;
use hasp_core::transport::retry::{RetryPolicy, entropy};
use hasp_core::transport::{Transport, TransportError};
use hasp_proto::wire::{OpId, Operation, PROTOCOL_VERSION, SessionToken};
use hasp_proto::{MAX_RECORD, ProtoError};
use js_sys::{Function, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use crate::js::AssertSend;

const REQUEST_TIMEOUT_MS: f64 = 30_000.0;
const BULK_TIMEOUT_MS: f64 = 120_000.0;
const BODY_SLACK: usize = 4096;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = fetch)]
    fn global_fetch(url: &str, init: &JsValue) -> Promise;
}

#[derive(Clone, Debug)]
pub(crate) struct FetchTransport {
    origin: Origin,
    retry: RetryPolicy,
}

enum Attempt {
    Reply {
        status: u16,
        retry_after: Option<u64>,
        bytes: Vec<u8>,
    },
    Again {
        retry_after: Option<u64>,
    },
}

fn set(target: &Object, key: &str, value: &JsValue) {
    Reflect::set(target, &JsValue::from_str(key), value).ok();
}

fn timeout_signal(ms: f64) -> Option<JsValue> {
    let class = Reflect::get(&js_sys::global(), &JsValue::from_str("AbortSignal")).ok()?;
    let make: Function = Reflect::get(&class, &JsValue::from_str("timeout"))
        .ok()?
        .dyn_into()
        .ok()?;
    make.call1(&class, &JsValue::from_f64(ms)).ok()
}

async fn sleep(ms: f64) {
    let promise = Promise::new(&mut |resolve, _| {
        if let Ok(timer) = Reflect::get(&js_sys::global(), &JsValue::from_str("setTimeout"))
            && let Ok(timer) = timer.dyn_into::<Function>()
        {
            let _started = timer.call2(&JsValue::UNDEFINED, &resolve, &JsValue::from_f64(ms));
        }
    });
    let _woken = JsFuture::from(promise).await;
}

fn header(response: &JsValue, name: &str) -> Option<String> {
    let headers = Reflect::get(response, &JsValue::from_str("headers")).ok()?;
    let getter: Function = Reflect::get(&headers, &JsValue::from_str("get"))
        .ok()?
        .dyn_into()
        .ok()?;
    getter
        .call1(&headers, &JsValue::from_str(name))
        .ok()?
        .as_string()
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "an HTTP status is an integer between 100 and 599"
)]
fn status_of(response: &JsValue) -> u16 {
    Reflect::get(response, &JsValue::from_str("status"))
        .ok()
        .and_then(|value| value.as_f64())
        .map_or(0, |value| value as u16)
}

fn retry_after(response: &JsValue) -> Option<u64> {
    let seconds: u64 = header(response, "retry-after")?.trim().parse().ok()?;
    Some(seconds.min(MAX_RETRY_AFTER_S))
}

impl FetchTransport {
    pub(crate) fn new(origin: &str) -> Result<Self, hasp_core::transport::origin::OriginError> {
        Ok(Self {
            origin: Origin::parse(origin)?,
            retry: RetryPolicy::standard(),
        })
    }

    async fn attempt(
        &self,
        op: OpId,
        route: &Route,
        body: &[u8],
        token: Option<&SessionToken>,
    ) -> Result<Attempt, TransportError> {
        let url = self
            .origin
            .http(&route.path)
            .map_err(|_| TransportError::Codec(ProtoError::Format))?;
        let headers = Object::new();
        set(&headers, "content-type", &JsValue::from_str(CBOR));
        set(&headers, "accept", &JsValue::from_str(CBOR));
        set(
            &headers,
            PROTOCOL_HEADER,
            &JsValue::from_str(&PROTOCOL_VERSION.to_string()),
        );
        if let Some(verb) = route.verb.override_name() {
            set(&headers, OVERRIDE_HEADER, &JsValue::from_str(verb));
        }
        if let Some(token) = token {
            set(
                &headers,
                "authorization",
                &JsValue::from_str(&bearer_text(token)),
            );
        }
        let init = Object::new();
        set(&init, "method", &JsValue::from_str("POST"));
        set(&init, "headers", &headers);
        set(&init, "body", &Uint8Array::from(body));
        set(&init, "redirect", &JsValue::from_str("error"));
        set(&init, "credentials", &JsValue::from_str("omit"));
        set(&init, "cache", &JsValue::from_str("no-store"));
        let ms = if is_bulk(op) {
            BULK_TIMEOUT_MS
        } else {
            REQUEST_TIMEOUT_MS
        };
        if let Some(signal) = timeout_signal(ms) {
            set(&init, "signal", &signal);
        }
        let Ok(response) = JsFuture::from(global_fetch(url.as_str(), &init)).await else {
            return Ok(Attempt::Again { retry_after: None });
        };
        let status = status_of(&response);
        let retry_after = retry_after(&response);
        let is_cbor =
            header(&response, "content-type").is_some_and(|value| value.starts_with(CBOR));
        let limit = MAX_RECORD.saturating_add(BODY_SLACK);
        if header(&response, "content-length")
            .and_then(|value| value.trim().parse::<usize>().ok())
            .is_some_and(|length| length > limit)
        {
            return Err(TransportError::Codec(ProtoError::Format));
        }
        let buffer = Reflect::get(&response, &JsValue::from_str("arrayBuffer"))
            .ok()
            .and_then(|method| method.dyn_into::<Function>().ok())
            .and_then(|method| method.call0(&response).ok());
        let Some(buffer) = buffer else {
            return Ok(Attempt::Again { retry_after });
        };
        let Ok(buffer) = JsFuture::from(Promise::resolve(&buffer)).await else {
            return Ok(Attempt::Again { retry_after });
        };
        let bytes = Uint8Array::new(&buffer).to_vec();
        if bytes.len() > limit {
            return Err(TransportError::Codec(ProtoError::Format));
        }
        if is_transient(status, is_cbor) {
            return Ok(Attempt::Again { retry_after });
        }
        Ok(Attempt::Reply {
            status,
            retry_after,
            bytes,
        })
    }

    async fn call_inner<O: Operation + Sync>(
        &self,
        token: Option<&SessionToken>,
        request: &O,
    ) -> Result<O::Response, TransportError> {
        let body = request.to_cbor()?;
        let route = resolve(O::ID, &body)?;
        let policy = if is_idempotent(O::ID) {
            self.retry
        } else {
            RetryPolicy::never()
        };
        let mut tries = 0_u32;
        loop {
            tries = tries.saturating_add(1);
            match self.attempt(O::ID, &route, &body, token).await? {
                Attempt::Reply {
                    status,
                    retry_after,
                    bytes,
                } => {
                    return match classify::<O::Response>(status, retry_after, &bytes) {
                        Classified::Reply(result) => result,
                        Classified::Transient => Err(TransportError::Unreachable),
                    };
                }
                Attempt::Again { retry_after } => {
                    if tries >= policy.max_attempts {
                        return Err(TransportError::Unreachable);
                    }
                    let hint =
                        Duration::from_secs(retry_after.unwrap_or_default()).min(policy.max_delay);
                    let wait = policy.delay(tries, entropy()).max(hint);
                    sleep(wait.as_secs_f64() * 1000.0).await;
                }
            }
        }
    }
}

impl Transport for FetchTransport {
    fn call<O: Operation + Sync>(
        &self,
        token: Option<&SessionToken>,
        request: &O,
    ) -> impl Future<Output = Result<O::Response, TransportError>> + Send {
        AssertSend::new(self.call_inner(token, request))
    }
}
