use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use hasp_core::client::{Channel, ChannelError};
use hasp_core::platform::Clock;
use hasp_core::watchtower::WatchtowerError;
use hasp_core::watchtower::pwned::{Prefix, RangeClient};
use js_sys::{Function, Uint8Array};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

/// A future that crosses a `Send` bound on a target that has one thread: WebAssembly in a page,
/// a worker or Node runs every task on the thread that created it.
pub(crate) struct AssertSend<F>(Pin<Box<F>>);

impl<F> AssertSend<F> {
    pub(crate) fn new(future: F) -> Self {
        Self(Box::pin(future))
    }
}

#[expect(
    unsafe_code,
    reason = "wasm32-unknown-unknown has one thread, so no future is ever moved to another"
)]
// SAFETY: this crate is built for wasm32-unknown-unknown without the atomics feature.
unsafe impl<F> Send for AssertSend<F> {}

impl<F: Future> Future for AssertSend<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        self.0.as_mut().poll(cx)
    }
}

#[derive(Debug)]
pub(crate) struct JsClock;

impl Clock for JsClock {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "Date.now() is a positive number of milliseconds far below 2^63"
    )]
    fn now(&self) -> u64 {
        (js_sys::Date::now() / 1000.0) as u64
    }
}

pub(crate) struct JsHandle<T>(pub(crate) T);

#[expect(unsafe_code, reason = "single-threaded target, see AssertSend")]
// SAFETY: see AssertSend.
unsafe impl<T> Send for JsHandle<T> {}
#[expect(unsafe_code, reason = "single-threaded target, see AssertSend")]
// SAFETY: see AssertSend.
unsafe impl<T> Sync for JsHandle<T> {}

pub(crate) struct JsChannel {
    pub(crate) send: JsHandle<Function>,
    pub(crate) recv: JsHandle<Function>,
}

async fn settle(value: Result<JsValue, JsValue>) -> Result<JsValue, ChannelError> {
    let promise = value.map_err(|_| ChannelError::Closed)?;
    JsFuture::from(js_sys::Promise::resolve(&promise))
        .await
        .map_err(|_| ChannelError::Closed)
}

impl Channel for JsChannel {
    fn send(&self, message: Vec<u8>) -> impl Future<Output = Result<(), ChannelError>> + Send {
        AssertSend::new(async move {
            let bytes = Uint8Array::from(message.as_slice());
            settle(self.send.0.call1(&JsValue::UNDEFINED, &bytes)).await?;
            Ok(())
        })
    }

    fn recv(&self) -> impl Future<Output = Result<Vec<u8>, ChannelError>> + Send {
        AssertSend::new(async move {
            let reply = settle(self.recv.0.call0(&JsValue::UNDEFINED)).await?;
            Ok(Uint8Array::new(&reply).to_vec())
        })
    }
}

pub(crate) struct JsRange(pub(crate) JsHandle<Function>);

impl RangeClient for JsRange {
    fn range(
        &self,
        prefix: &Prefix,
    ) -> impl Future<Output = Result<String, WatchtowerError>> + Send {
        let prefix = prefix.as_str().to_owned();
        AssertSend::new(async move {
            let call = self
                .0
                .0
                .call1(&JsValue::UNDEFINED, &JsValue::from_str(&prefix))
                .map_err(|_| WatchtowerError::Network)?;
            JsFuture::from(js_sys::Promise::resolve(&call))
                .await
                .map_err(|_| WatchtowerError::Network)?
                .as_string()
                .ok_or(WatchtowerError::Response)
        })
    }
}
