use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use hasp_core::transport::{Transport, TransportError};
use hasp_proto::wire::{
    Commit, ErrorCode, OpId, Operation, PullResponse, SessionToken, WireError, decode_reply,
};
use hasp_proto::{Hash32, Manifest, VaultId, Wire};
use hasp_server::{Caller, MemoryStore, Server};

#[derive(Clone, Debug)]
pub(crate) struct Seen {
    pub(crate) op: OpId,
    pub(crate) token: Option<SessionToken>,
    pub(crate) request: Vec<u8>,
    pub(crate) response: Option<Vec<u8>>,
    pub(crate) error: Option<ErrorCode>,
    pub(crate) elapsed: Duration,
}

#[derive(Clone, Debug)]
pub(crate) struct Head {
    pub(crate) manifest: Manifest,
    pub(crate) hash: Hash32,
}

pub(crate) enum Verdict {
    Forward,
    Reply(Vec<u8>),
    Fail(ErrorCode),
}

type RequestHook = Box<dyn FnMut(&mut Vec<u8>) -> Verdict + Send>;
type ResponseHook = Box<dyn FnMut(&mut Vec<u8>) + Send>;

#[derive(Default)]
struct Script {
    log: Vec<Seen>,
    heads: BTreeMap<VaultId, Head>,
    requests: Vec<(OpId, RequestHook)>,
    responses: Vec<(OpId, ResponseHook)>,
}

impl Script {
    fn note(&mut self, vault: VaultId, signed: &hasp_proto::Signed<Manifest>) {
        let Ok(manifest) = signed.unverified() else {
            return;
        };
        let newer = self
            .heads
            .get(&vault)
            .is_none_or(|head| head.manifest.seq < manifest.seq);
        if newer {
            self.heads.insert(
                vault,
                Head {
                    manifest,
                    hash: signed.hash(),
                },
            );
        }
    }
}

#[derive(Clone)]
pub(crate) struct Mallory {
    server: Arc<Server<MemoryStore>>,
    script: Arc<Mutex<Script>>,
}

impl std::fmt::Debug for Mallory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mallory(..)")
    }
}

impl Mallory {
    pub(crate) fn new(server: &Arc<Server<MemoryStore>>) -> Self {
        Self {
            server: Arc::clone(server),
            script: Arc::new(Mutex::new(Script::default())),
        }
    }

    fn script(&self) -> MutexGuard<'_, Script> {
        self.script.lock().unwrap()
    }

    pub(crate) fn on_request(
        &self,
        op: OpId,
        hook: impl FnMut(&mut Vec<u8>) -> Verdict + Send + 'static,
    ) {
        self.script().requests.push((op, Box::new(hook)));
    }

    pub(crate) fn on_response(&self, op: OpId, hook: impl FnMut(&mut Vec<u8>) + Send + 'static) {
        self.script().responses.push((op, Box::new(hook)));
    }

    pub(crate) fn passthrough(&self) {
        let mut script = self.script();
        script.requests.clear();
        script.responses.clear();
    }

    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.script().log.clone()
    }

    pub(crate) fn seen_op(&self, op: OpId) -> Vec<Seen> {
        self.script()
            .log
            .iter()
            .filter(|seen| seen.op == op)
            .cloned()
            .collect()
    }

    pub(crate) fn ops(&self) -> Vec<OpId> {
        self.script().log.iter().map(|seen| seen.op).collect()
    }

    pub(crate) fn mark(&self) -> usize {
        self.script().log.len()
    }

    pub(crate) fn ops_since(&self, mark: usize) -> Vec<OpId> {
        self.script()
            .log
            .iter()
            .skip(mark)
            .map(|seen| seen.op)
            .collect()
    }

    pub(crate) fn stolen_token(&self) -> SessionToken {
        self.script()
            .log
            .iter()
            .rev()
            .find_map(|seen| seen.token.clone())
            .expect("the transport carried an authenticated call")
    }

    pub(crate) fn head(&self, vault: &VaultId) -> Option<Head> {
        self.script().heads.get(vault).cloned()
    }

    pub(crate) fn raw(&self, token: Option<&SessionToken>, op: OpId, body: &[u8]) -> Vec<u8> {
        let caller = Caller {
            token: token.cloned(),
            peer: None,
        };
        self.server.handle(&caller, op, body)
    }

    pub(crate) fn as_thief<O: Operation>(
        &self,
        token: &SessionToken,
        request: &O,
    ) -> Result<O::Response, WireError> {
        self.server
            .call(&Caller::with_token(token.clone()), request)
    }

    pub(crate) fn anonymous<O: Operation>(&self, request: &O) -> Result<O::Response, WireError> {
        self.server.call(&Caller::anonymous(), request)
    }

    fn rewrite_request(&self, op: OpId, body: &mut Vec<u8>) -> Verdict {
        let mut script = self.script();
        for (hooked, hook) in &mut script.requests {
            if *hooked == op {
                match hook(body) {
                    Verdict::Forward => {}
                    other => return other,
                }
            }
        }
        Verdict::Forward
    }

    fn rewrite_response(&self, op: OpId, body: &mut Vec<u8>) {
        let mut script = self.script();
        for (hooked, hook) in &mut script.responses {
            if *hooked == op {
                hook(body);
            }
        }
    }

    fn record(&self, seen: Seen) {
        let mut script = self.script();
        if seen.op == OpId::Commit
            && seen.error.is_none()
            && let Ok(commit) = Commit::from_cbor(&seen.request)
        {
            script.note(commit.vault_id, &commit.bundle.manifest);
        }
        if seen.op == OpId::Pull
            && let Some(bytes) = &seen.response
            && let Ok(page) = PullResponse::from_cbor(bytes)
        {
            for vault in &page.vaults {
                for bundle in &vault.commits {
                    script.note(vault.vault_id, &bundle.manifest);
                }
            }
        }
        script.log.push(seen);
    }
}

impl Transport for Mallory {
    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the in-process call completes at once; async is the trait signature"
    )]
    async fn call<O: Operation + Sync>(
        &self,
        token: Option<&SessionToken>,
        request: &O,
    ) -> Result<O::Response, TransportError> {
        let mut body = request.to_cbor()?;
        let original = body.clone();
        let verdict = self.rewrite_request(O::ID, &mut body);
        let mut seen = Seen {
            op: O::ID,
            token: token.cloned(),
            request: original,
            response: None,
            error: None,
            elapsed: Duration::ZERO,
        };
        match verdict {
            Verdict::Reply(bytes) => {
                seen.response = Some(bytes.clone());
                self.record(seen);
                return Ok(O::Response::from_cbor(&bytes)?);
            }
            Verdict::Fail(code) => {
                seen.error = Some(code);
                self.record(seen);
                return Err(WireError::new(code).into());
            }
            Verdict::Forward => {}
        }
        let started = Instant::now();
        let reply = self.raw(token, O::ID, &body);
        seen.elapsed = started.elapsed();
        match decode_reply::<O::Response>(&reply)? {
            Ok(response) => {
                let mut bytes = response.to_cbor()?;
                self.rewrite_response(O::ID, &mut bytes);
                seen.response = Some(bytes.clone());
                self.record(seen);
                Ok(O::Response::from_cbor(&bytes)?)
            }
            Err(error) => {
                seen.error = Some(error.code);
                self.record(seen);
                Err(error.into())
            }
        }
    }
}

pub(crate) fn edit<M: Wire>(bytes: &mut Vec<u8>, change: impl FnOnce(&mut M)) {
    let mut message = M::from_cbor(bytes).unwrap();
    change(&mut message);
    *bytes = message.to_cbor().unwrap();
}
