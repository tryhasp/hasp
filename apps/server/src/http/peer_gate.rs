use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub(super) struct PeerGate {
    max_requests: usize,
    max_bytes: usize,
    active: Mutex<BTreeMap<Vec<u8>, (usize, usize)>>,
}

#[derive(Debug)]
pub(super) struct PeerPermit(Option<Held>);

#[derive(Debug)]
struct Held {
    gate: Arc<PeerGate>,
    key: Vec<u8>,
    bytes: usize,
}

impl PeerGate {
    pub(super) fn new(max_requests: usize, max_bytes: usize) -> Self {
        Self {
            max_requests,
            max_bytes,
            active: Mutex::new(BTreeMap::new()),
        }
    }

    pub(super) fn enter(
        self: &Arc<Self>,
        peer: Option<IpAddr>,
        bytes: usize,
    ) -> Option<PeerPermit> {
        let Some(peer) = peer else {
            return Some(PeerPermit(None));
        };
        let key = crate::rate::peer_bucket(peer);
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = active.entry(key.clone()).or_insert((0, 0));
        let requests = entry.0.saturating_add(1);
        let total = entry.1.saturating_add(bytes);
        if requests > self.max_requests || total > self.max_bytes {
            if entry.0 == 0 {
                active.remove(&key);
            }
            return None;
        }
        *entry = (requests, total);
        drop(active);
        Some(PeerPermit(Some(Held {
            gate: Arc::clone(self),
            key,
            bytes,
        })))
    }
}

impl Drop for PeerPermit {
    fn drop(&mut self) {
        let Some(held) = self.0.take() else {
            return;
        };
        let mut active = held
            .gate
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = active.get_mut(&held.key) {
            *entry = (
                entry.0.saturating_sub(1),
                entry.1.saturating_sub(held.bytes),
            );
            if entry.0 == 0 {
                active.remove(&held.key);
            }
        }
    }
}
