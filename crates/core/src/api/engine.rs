use std::collections::VecDeque;
use std::sync::Mutex as StdMutex;

use tokio::sync::{Mutex, Notify};
use tokio_util::sync::CancellationToken;

use crate::CoreError;
use crate::api::{EngineEvent, EventKind};
use crate::client::{CancelHandle, Client, ClientConfig};
use crate::generator::memorable::Wordlist;
use crate::matcher::policy::Matcher;
use crate::model::template::Templates;
use crate::platform::Platform;
use crate::store::Store;
use crate::transport::Transport;
use crate::watchtower::Watchtower;

const EVENT_CAP: usize = 256;

#[derive(Debug, Default)]
pub(super) struct Events {
    queue: StdMutex<VecDeque<EngineEvent>>,
    notify: Notify,
}

impl Events {
    pub(super) fn push(&self, event: EngineEvent) {
        if let Ok(mut queue) = self.queue.lock() {
            if queue.len() >= EVENT_CAP {
                queue.pop_front();
            }
            queue.push_back(event);
        }
        self.notify.notify_one();
    }

    pub(super) async fn next(&self) -> EngineEvent {
        loop {
            let waiting = self.notify.notified();
            if let Ok(mut queue) = self.queue.lock()
                && let Some(event) = queue.pop_front()
            {
                return event;
            }
            waiting.await;
        }
    }
}

pub(super) fn event(kind: EventKind) -> EngineEvent {
    EngineEvent {
        kind,
        vault: None,
        item: None,
        detail: None,
        count: 0,
    }
}

#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub client: ClientConfig,
}

impl EngineConfig {
    pub fn new(platform_name: &str) -> Self {
        Self {
            client: ClientConfig::new(platform_name),
        }
    }
}

/// The coarse facade every host app talks to: one object, DTO in and out, secrets
/// only where a method says so. All state lives in `Client`; the engine adds ranking, step-up
/// policy, settings, the lock policy and the event queue.
pub struct Engine<T: Transport, S: Store> {
    pub(super) client: Mutex<Client<T, S>>,
    pub(super) cancel: CancelHandle,
    pub(super) matcher: Matcher,
    pub(super) templates: Templates,
    pub(super) wordlist: Wordlist,
    pub(super) events: Events,
    pub(super) watch: Mutex<Option<Watchtower>>,
}

impl<T: Transport, S: Store> std::fmt::Debug for Engine<T, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Engine(..)")
    }
}

impl<T: Transport, S: Store> Engine<T, S> {
    pub fn new(
        transport: T,
        store: S,
        platform: Platform,
        config: EngineConfig,
    ) -> Result<Self, CoreError> {
        let client = Client::new(transport, store, platform, config.client);
        Ok(Self {
            cancel: client.cancel_handle(),
            client: Mutex::new(client),
            matcher: Matcher::bundled()?,
            templates: Templates::bundled()?,
            wordlist: Wordlist::bundled()?,
            events: Events::default(),
            watch: Mutex::new(None),
        })
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub async fn next_event(&self) -> EngineEvent {
        self.events.next().await
    }

    pub(super) fn token() -> CancellationToken {
        CancellationToken::new()
    }

    pub(super) fn emit(&self, kind: EventKind) {
        self.events.push(event(kind));
    }
}
