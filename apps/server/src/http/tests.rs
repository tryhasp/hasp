use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use futures_util::{SinkExt, StreamExt};
use hasp_proto::base64url;
use hasp_proto::wire::{
    AccountDelete, AccountGet, AccountLookup, Ack, AdminAccountDelete, AdminAccountList,
    AdminAccountUpdate, AdminTokenCreate, AttachmentComplete, AttachmentGet, AttachmentPut, Blob,
    ChangeCredentialFinish, ChangeCredentialStart, EnrolApprove, EnrolOpen, ErrorCode, Health,
    HealthResponse, InviteAccept, InviteCreate, InviteDecline, InviteGet, InviteList, Leave,
    LoginHandle, OpId, Operation, PROTOCOL_VERSION, Pull, ReauthFinish, ReauthStart, RecoverAbort,
    RecoverComplete, RecoverRegisterStart, RecoveryId, RepairPublish, SelfWrapEntry, SelfWrapPut,
    ServerKey, SessionList, SessionRevoke, SessionToken, TokenKind, VaultDissolve, WireError,
    decode_reply,
};
use hasp_proto::{
    AccountStatus, AttId, Dissolve, Epoch, Esid, Hash32, InviteId, LeaveRequest, Role, Rver,
    SigLabel, Signed, Uint53, VaultKind, Wire,
};
use http_body_util::BodyExt;
use tokio_tungstenite::tungstenite::Message;
use tower::ServiceExt;

use super::app::Gateway;
use super::identity::Cidr;
use super::loopback::{request, route_of};
use super::options::{Capacity, HttpOptions, SocketOptions};
use super::routes;
use crate::fixture::{Client, Harness, Person, VaultModel};
use crate::logging::{RedactingLayer, Sink};
use crate::{Limits, MemoryStore, WindowLimiter};

mod limits;
mod routing;
mod sockets;

struct Api {
    h: Harness,
    gateway: Gateway<MemoryStore>,
    rt: tokio::runtime::Runtime,
}

struct Answer<T> {
    status: StatusCode,
    headers: HeaderMap,
    result: Result<T, WireError>,
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

impl Api {
    fn new() -> Self {
        Self::with(HttpOptions::default(), Harness::new().direct())
    }

    fn with(options: HttpOptions, h: Harness) -> Self {
        let gateway = Gateway::new(Arc::clone(&h.server), options);
        Self {
            h,
            gateway,
            rt: runtime(),
        }
    }

    async fn raw_async(&self, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let response = self.gateway.router().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        (
            parts.status,
            parts.headers,
            body.collect().await.unwrap().to_bytes().to_vec(),
        )
    }

    fn raw(&self, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
        self.rt.block_on(self.raw_async(request))
    }

    async fn ok_async<O: Operation>(&self, token: &SessionToken, message: &O) -> O::Response {
        let request = request(
            O::ID,
            Some(token),
            &message.to_cbor().unwrap(),
            [10, 0, 0, 1],
        );
        let (status, _, body) = self.raw_async(request).await;
        assert_eq!(status, StatusCode::OK);
        decode_reply::<O::Response>(&body).unwrap().unwrap()
    }

    fn send_from<O: Operation>(
        &self,
        token: Option<&SessionToken>,
        peer: [u8; 4],
        message: &O,
    ) -> Answer<O::Response> {
        let (status, headers, body) =
            self.raw(request(O::ID, token, &message.to_cbor().unwrap(), peer));
        Answer {
            status,
            headers,
            result: decode_reply::<O::Response>(&body).unwrap(),
        }
    }

    fn send<O: Operation>(&self, token: Option<&SessionToken>, message: &O) -> Answer<O::Response> {
        self.send_from(token, [10, 0, 0, 1], message)
    }

    fn ok<O: Operation>(&self, token: &SessionToken, message: &O) -> O::Response {
        let answer = self.send(Some(token), message);
        assert_eq!(answer.status, StatusCode::OK);
        answer.result.unwrap()
    }
}

fn error_of<T: std::fmt::Debug>(answer: Answer<T>) -> (StatusCode, ErrorCode) {
    (answer.status, answer.result.unwrap_err().code)
}

fn shared_vault(h: &Harness, owner: &Client) -> VaultModel {
    let mut vault = VaultModel::new(VaultKind::Shared, &owner.person);
    let genesis = vault.genesis(&owner.person);
    let commit = vault.genesis_commit(&owner.person, genesis);
    h.call(Some(&owner.token), &commit).unwrap();
    vault
}

fn add_member(h: &Harness, owner: &Client, who: &Client, model: &mut VaultModel) {
    let created = h
        .call(
            Some(&owner.token),
            &InviteCreate {
                vault_id: model.id,
                role: Role::Editor,
            },
        )
        .unwrap();
    h.call(
        Some(&who.token),
        &InviteAccept {
            invite_id: created.invite_id,
            accept: vec![1].into(),
        },
    )
    .unwrap();
    let bundle = model.add_member(&owner.person, &who.person, Role::Editor);
    h.call(Some(&owner.token), &model.commit(bundle)).unwrap();
}

fn request_for_health() -> Request<Body> {
    Request::get("/healthz").body(Body::empty()).unwrap()
}
