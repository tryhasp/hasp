use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tower::ServiceExt;

use super::app::wait_stopped;

#[derive(Clone, Copy, Debug)]
pub(super) struct ConnLimits {
    pub(super) max_connections: usize,
    pub(super) header_timeout: Duration,
}

const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

pub(super) async fn serve_connections(
    listener: TcpListener,
    router: Router,
    limits: ConnLimits,
    stopped: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let slots = std::sync::Arc::new(Semaphore::new(limits.max_connections));
    let mut tasks = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = wait_stopped(stopped.clone()) => break,
        };
        while tasks.try_join_next().is_some() {}
        let Ok((stream, peer)) = accepted else {
            tokio::time::sleep(ACCEPT_BACKOFF).await;
            continue;
        };
        let Ok(slot) = std::sync::Arc::clone(&slots).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let router = router.clone();
        let stopped = stopped.clone();
        tasks.spawn(async move {
            let _slot = slot;
            let _nodelay = stream.set_nodelay(true);
            let service = service_fn(move |mut request: hyper::Request<Incoming>| {
                request.extensions_mut().insert(ConnectInfo(peer));
                router.clone().oneshot(request)
            });
            let mut builder = http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(limits.header_timeout);
            let connection = builder
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades();
            tokio::pin!(connection);
            tokio::select! {
                _ = connection.as_mut() => {}
                () = wait_stopped(stopped) => {
                    connection.as_mut().graceful_shutdown();
                    let _done = connection.await;
                }
            }
        });
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}
