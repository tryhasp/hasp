mod apply;
mod commit;
mod page;
mod pull;
mod rollback;
mod share;

use hasp_proto::wire::{ErrorCode, Operation};
use hasp_proto::{AccountId, ItemId, VaultId};

use crate::CoreError;
use crate::platform::Platform;
use crate::session::{Cancel, Session};
use crate::store::{Cache, Store};
use crate::transport::{Transport, TransportError};

pub use pull::{SyncReport, VaultSync, VaultSyncState};
pub use rollback::RollbackAccepted;

pub(crate) use apply::{persist_commits, proto_commit};
pub(crate) use commit::{
    CommitDraft, Edit, ensure_writable, flush_vault, queue_delete, queue_put, self_wrap_entry,
    submit_commit,
};
pub(crate) use page::{device_confirmed as device_confirmed_pub, refresh_pins};
pub(crate) use pull::{pull_vault_ids, record_events, sync_all};
pub(crate) use rollback::accept_older_server_state;

pub(crate) struct Ctx<'a, T: Transport, S: Store> {
    pub transport: &'a T,
    pub cache: &'a mut Cache<S>,
    pub session: &'a mut Session,
    pub platform: &'a Platform,
    pub cancel: &'a Cancel,
}

impl<T: Transport, S: Store> Ctx<'_, T, S> {
    pub(crate) async fn call<O: Operation + Sync>(
        &self,
        request: &O,
    ) -> Result<O::Response, CoreError> {
        self.cancel.check()?;
        let reply = self
            .transport
            .call(Some(&self.session.token), request)
            .await
            .map_err(CoreError::from);
        self.cancel.check()?;
        match reply {
            Err(error) if server_code(&error) == Some(ErrorCode::Auth) => {
                Err(CoreError::SessionExpired)
            }
            other => other,
        }
    }

    pub(crate) fn account_id(&self) -> AccountId {
        self.session.identity.account_id
    }
}

pub(crate) fn server_code(error: &CoreError) -> Option<ErrorCode> {
    match error {
        CoreError::Transport(TransportError::Server(wire)) => Some(wire.code),
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemRef {
    pub vault_id: VaultId,
    pub item_id: ItemId,
}
