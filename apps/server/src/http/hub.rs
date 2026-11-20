use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use hasp_proto::wire::SessionId;
use hasp_proto::{AccountId, Hash32, VaultId};
use tokio::sync::mpsc;

use crate::server::Server;
use crate::store::{AccountState, MemberStatus, SessionRow, Store};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Frame {
    Hint { vault: VaultId, seq: u64 },
    Notice,
    Revoked,
}

#[derive(Debug)]
struct Conn {
    session: SessionId,
    account: AccountId,
    last_notice: u64,
    tx: mpsc::Sender<Frame>,
}

#[derive(Debug, Default)]
struct Inner {
    next: u64,
    conns: BTreeMap<u64, Conn>,
}

#[derive(Debug, Default)]
pub(crate) struct Hub {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
pub(crate) struct Registration {
    pub(crate) id: u64,
    pub(crate) rx: mpsc::Receiver<Frame>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Subscriber {
    pub(crate) session: SessionId,
    pub(crate) account: AccountId,
    pub(crate) last_notice: u64,
}

pub(crate) fn live_session_by_hash<S: Store>(
    store: &mut S,
    hash: &Hash32,
    now: u64,
) -> Option<SessionRow> {
    let sid = store.session_tokens().get(hash).ok()??;
    live_session(store, &sid, now)
}

fn live_session<S: Store>(store: &mut S, sid: &SessionId, now: u64) -> Option<SessionRow> {
    let row = store.sessions().get(sid).ok()??;
    if now >= row.idle_expires || now >= row.abs_expires {
        return None;
    }
    let account = store.accounts().get(&row.account_id).ok()??;
    (account.state == AccountState::Active).then_some(row)
}

pub(crate) fn latest_notice<S: Store>(store: &mut S, account: &AccountId) -> u64 {
    store
        .notices()
        .last_in(&(*account, 0), &(*account, u64::MAX))
        .ok()
        .flatten()
        .map_or(0, |((_, id), _)| id)
}

impl Hub {
    pub(crate) fn register(
        &self,
        who: Subscriber,
        max_per_session: usize,
        queue: usize,
    ) -> Option<Registration> {
        let mut inner = self.inner.lock().ok()?;
        let open = inner
            .conns
            .values()
            .filter(|conn| conn.session == who.session)
            .count();
        if open >= max_per_session {
            return None;
        }
        let (tx, rx) = mpsc::channel(queue);
        inner.next = inner.next.wrapping_add(1);
        let id = inner.next;
        inner.conns.insert(
            id,
            Conn {
                session: who.session,
                account: who.account,
                last_notice: who.last_notice,
                tx,
            },
        );
        Some(Registration { id, rx })
    }

    pub(crate) fn unregister(&self, id: u64) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.conns.remove(&id);
        }
    }

    pub(crate) fn reconcile<S: Store>(&self, server: &Server<S>, vaults: &[VaultId]) {
        let snapshot: Vec<(u64, SessionId, AccountId, u64)> = match self.inner.lock() {
            Ok(inner) if !inner.conns.is_empty() => inner
                .conns
                .iter()
                .map(|(id, conn)| (*id, conn.session, conn.account, conn.last_notice))
                .collect(),
            Ok(_) | Err(_) => return,
        };
        let now = server.clock.now();
        let plan = server.with_store(|store| plan_frames(store, &snapshot, vaults, now));
        let Ok(plan) = plan else {
            return;
        };
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let mut dropped = Vec::new();
        for (id, frames, last_notice) in plan {
            let Some(conn) = inner.conns.get_mut(&id) else {
                continue;
            };
            conn.last_notice = last_notice;
            let revoked = frames.contains(&Frame::Revoked);
            let delivered = frames
                .into_iter()
                .all(|frame| conn.tx.try_send(frame).is_ok());
            if revoked || !delivered {
                dropped.push(id);
            }
        }
        for id in dropped {
            inner.conns.remove(&id);
        }
    }
}

fn plan_frames<S: Store>(
    store: &mut S,
    snapshot: &[(u64, SessionId, AccountId, u64)],
    vaults: &[VaultId],
    now: u64,
) -> Vec<(u64, Vec<Frame>, u64)> {
    let mut heads = Vec::new();
    let mut audience: BTreeMap<VaultId, BTreeSet<AccountId>> = BTreeMap::new();
    for vault in vaults {
        let Some(head) = store.vaults().get(vault).ok().flatten() else {
            continue;
        };
        heads.push((*vault, head.head_seq.get()));
        let low = (*vault, AccountId::from_bytes([0; 16]));
        let high = (*vault, AccountId::from_bytes([0xff; 16]));
        let members = store.members().range(&low, &high).unwrap_or_default();
        audience.insert(
            *vault,
            members
                .into_iter()
                .filter(|(_, row)| {
                    matches!(row.state, MemberStatus::Active | MemberStatus::Leaving)
                })
                .map(|((_, account), _)| account)
                .collect(),
        );
    }
    snapshot
        .iter()
        .map(|(id, session, account, last_notice)| {
            if live_session(store, session, now).is_none() {
                return (*id, vec![Frame::Revoked], *last_notice);
            }
            let mut frames = Vec::new();
            for (vault, seq) in &heads {
                if audience.get(vault).is_some_and(|set| set.contains(account)) {
                    frames.push(Frame::Hint {
                        vault: *vault,
                        seq: *seq,
                    });
                }
            }
            let notice = latest_notice(store, account);
            if notice > *last_notice {
                frames.push(Frame::Notice);
            }
            (*id, frames, notice.max(*last_notice))
        })
        .collect()
}
