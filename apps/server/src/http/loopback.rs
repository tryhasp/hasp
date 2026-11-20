use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, header};
use hasp_proto::base64url;
use hasp_proto::wire::{OpId, SessionToken};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::app::Gateway;
use super::options::HttpOptions;
use super::routes::ROUTES;
use crate::Server;
use crate::Store;
use crate::fixture::Transport;

#[derive(Debug)]
pub(crate) struct Loopback {
    router: Router,
    runtime: tokio::runtime::Runtime,
}

impl Loopback {
    pub(crate) fn new<S: Store + 'static>(server: Arc<Server<S>>) -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let gateway = Gateway::new(server, HttpOptions::default());
        Self {
            router: gateway.router(),
            runtime,
        }
    }
}

pub(crate) fn route_of(op: OpId) -> (Method, String) {
    for spec in ROUTES {
        for (method, routed) in spec.methods {
            if *routed == op {
                let path = spec
                    .path
                    .split('/')
                    .map(|part| if part.starts_with('{') { "x" } else { part })
                    .collect::<Vec<_>>()
                    .join("/");
                return (method.clone(), path);
            }
        }
    }
    panic!("no route for {op:?}");
}

pub(crate) fn request(
    op: OpId,
    token: Option<&SessionToken>,
    body: &[u8],
    peer: [u8; 4],
) -> Request<Body> {
    let (method, path) = route_of(op);
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/cbor");
    if let Some(token) = token {
        builder = builder.header(
            header::AUTHORIZATION,
            format!("Bearer {}", base64url::encode(token.as_bytes())),
        );
    }
    let mut request = builder.body(Body::from(body.to_vec())).unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((peer, 4000))));
    request
}

impl Transport for Loopback {
    fn send(&self, token: Option<&SessionToken>, op: OpId, body: &[u8]) -> Vec<u8> {
        let request = request(op, token, body, [10, 0, 0, 1]);
        self.runtime.block_on(async {
            let response = self.router.clone().oneshot(request).await.unwrap();
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec()
        })
    }
}
