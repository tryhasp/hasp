pub mod http;
pub mod origin;
pub mod retry;

use std::future::Future;

use hasp_proto::ProtoError;
use hasp_proto::wire::{Operation, SessionToken, WireError};

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("server: {0}")]
    Server(#[from] WireError),
    #[error("codec: {0}")]
    Codec(#[from] ProtoError),
    #[error("unreachable")]
    Unreachable,
}

/// The request type fixes the response type and operation id. The token is the session bearer;
/// pre-auth operations pass `None`.
pub trait Transport {
    fn call<O: Operation + Sync>(
        &self,
        token: Option<&SessionToken>,
        request: &O,
    ) -> impl Future<Output = Result<O::Response, TransportError>> + Send;
}
