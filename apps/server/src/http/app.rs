use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::any;
use hasp_proto::wire::ErrorCode;
use tokio::sync::{Semaphore, watch};

use super::hub::Hub;
use super::options::HttpOptions;
use super::peer_gate::PeerGate;
use super::request::{busy, failure, serve_operation};
use super::routes::{self, ROUTES};
use super::serve::{ConnLimits, serve_connections};
use super::ws;
use crate::server::Server;
use crate::store::Store;

pub(crate) struct App<S: Store + 'static> {
    pub(crate) server: Arc<Server<S>>,
    pub(crate) hub: Hub,
    pub(crate) options: HttpOptions,
    pub(super) transfers: Arc<Semaphore>,
    pub(super) inflight: Arc<Semaphore>,
    workers: Arc<Semaphore>,
    pub(super) peers: Arc<PeerGate>,
    stop: watch::Sender<bool>,
}

impl<S: Store + 'static> App<S> {
    pub(crate) fn stop_signal(&self) -> watch::Receiver<bool> {
        self.stop.subscribe()
    }

    pub(crate) async fn blocking<R: Send + 'static>(
        &self,
        within: Duration,
        work: impl FnOnce() -> R + Send + 'static,
    ) -> Result<R, Box<Response>> {
        let queued = tokio::time::timeout(
            self.options.capacity.queue_wait,
            Arc::clone(&self.workers).acquire_owned(),
        )
        .await;
        let Ok(Ok(permit)) = queued else {
            return Err(Box::new(busy()));
        };
        let started = Instant::now();
        let deadline = started.checked_add(within).unwrap_or(started);
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            (Instant::now() < deadline).then(work)
        });
        match tokio::time::timeout(within, task).await {
            Ok(Ok(Some(result))) => Ok(result),
            Ok(Ok(None)) | Err(_) => Err(Box::new(failure(
                StatusCode::REQUEST_TIMEOUT,
                ErrorCode::Internal,
            ))),
            Ok(Err(_)) => Err(Box::new(failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::Internal,
            ))),
        }
    }
}

impl<S: Store + 'static> std::fmt::Debug for App<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("App(..)")
    }
}

#[derive(Debug)]
pub struct Gateway<S: Store + 'static> {
    app: Arc<App<S>>,
}

impl<S: Store + 'static> Clone for Gateway<S> {
    fn clone(&self) -> Self {
        Self {
            app: Arc::clone(&self.app),
        }
    }
}

impl<S: Store + 'static> Gateway<S> {
    pub fn new(server: Arc<Server<S>>, options: HttpOptions) -> Self {
        let (stop, _) = watch::channel(false);
        Self {
            app: Arc::new(App {
                server,
                hub: Hub::default(),
                transfers: Arc::new(Semaphore::new(options.chunk_transfers)),
                inflight: Arc::new(Semaphore::new(options.capacity.inflight_bytes)),
                workers: Arc::new(Semaphore::new(options.capacity.workers)),
                peers: Arc::new(PeerGate::new(
                    options.capacity.peer_requests,
                    options.capacity.peer_inflight_bytes,
                )),
                options,
                stop,
            }),
        }
    }

    pub fn router(&self) -> Router {
        let mut router = Router::new();
        for spec in ROUTES {
            let app = Arc::clone(&self.app);
            router = router.route(
                spec.path,
                any(move |request: Request| {
                    let app = Arc::clone(&app);
                    async move { serve_operation(app, spec, request).await }
                }),
            );
        }
        let app = Arc::clone(&self.app);
        router
            .route(
                routes::WS_PATH,
                any(move |request: Request| {
                    let app = Arc::clone(&app);
                    async move { ws::upgrade(app, request).await }
                }),
            )
            .fallback(|| async { failure(StatusCode::NOT_FOUND, ErrorCode::NotFound) })
    }

    pub async fn maintain_once(&self) {
        let app = Arc::clone(&self.app);
        let swept = tokio::task::spawn_blocking(move || {
            app.server.limiter.prune(app.server.clock.now());
            let result = app.server.sweep();
            app.hub.reconcile(&app.server, &[]);
            result
        })
        .await;
        if !matches!(swept, Ok(Ok(()))) {
            tracing::warn!("maintenance sweep failed");
        }
    }

    pub fn stop(&self) {
        self.app.stop.send_replace(true);
    }

    pub async fn run(
        self,
        listener: tokio::net::TcpListener,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> std::io::Result<()> {
        let grace = self.app.options.shutdown_grace;
        let stopped = self.app.stop.subscribe();
        let trigger = self.clone();
        let signal = tokio::spawn(async move {
            shutdown.await;
            trigger.stop();
        });
        let maintenance = tokio::spawn(maintenance_loop(self.clone(), stopped.clone()));
        let limits = ConnLimits {
            max_connections: self.app.options.capacity.max_connections,
            header_timeout: self.app.options.header_timeout,
        };
        let serve = serve_connections(listener, self.router(), limits, stopped.clone());
        tokio::pin!(serve);
        let result = tokio::select! {
            result = &mut serve => result,
            () = async {
                wait_stopped(stopped).await;
                tokio::time::sleep(grace).await;
            } => Ok(()),
        };
        signal.abort();
        let _joined = maintenance.await;
        result
    }
}

pub(super) async fn wait_stopped(mut stopped: watch::Receiver<bool>) {
    let _seen = stopped.wait_for(|stop| *stop).await;
}

async fn maintenance_loop<S: Store + 'static>(gateway: Gateway<S>, stopped: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(gateway.app.options.maintenance_interval);
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = ticker.tick() => gateway.maintain_once().await,
            () = wait_stopped(stopped.clone()) => break,
        }
    }
}
