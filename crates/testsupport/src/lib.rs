use std::future::Future;
use std::net::IpAddr;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

use hasp_core::transport::{Transport, TransportError};
use hasp_proto::wire::{Operation, SessionToken, decode_reply};
use hasp_server::{Caller, Server, Store};

pub use hasp_server::fixture;
use tokio_util::sync::CancellationToken;
pub use world::{Device, ORIGIN as TEST_ORIGIN, TestClient, World};

mod world;

// Why: core is Apache-2.0 and must not depend on the AGPL server, even optionally.
#[derive(Debug)]
pub struct InProcess<S: Store> {
    server: Arc<Server<S>>,
    peer: Option<IpAddr>,
}

impl<S: Store> InProcess<S> {
    pub fn new(server: Arc<Server<S>>) -> Self {
        Self { server, peer: None }
    }

    #[must_use]
    pub fn from_peer(mut self, peer: IpAddr) -> Self {
        self.peer = Some(peer);
        self
    }

    pub fn server(&self) -> &Arc<Server<S>> {
        &self.server
    }
}

impl<S: Store + 'static> Transport for InProcess<S> {
    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the in-process call completes at once; async is the trait signature"
    )]
    async fn call<O: Operation + Sync>(
        &self,
        token: Option<&SessionToken>,
        request: &O,
    ) -> Result<O::Response, TransportError> {
        let caller = Caller {
            token: token.cloned(),
            peer: self.peer,
        };
        let body = request.to_cbor()?;
        let reply = self.server.handle(&caller, O::ID, &body);
        Ok(decode_reply::<O::Response>(&reply)??)
    }
}

struct Unparker(Thread);

impl Wake for Unparker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::from(Arc::new(Unparker(thread::current())));
    let mut context = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        thread::park();
    }
}

pub fn cancel() -> CancellationToken {
    CancellationToken::new()
}
