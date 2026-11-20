use std::net::SocketAddr;
use std::sync::Arc;

use hasp_core::client::{Client, SignIn, SignUp};
use hasp_core::store::MemoryStore as ClientStore;
use hasp_crypto::SecretKey;
use hasp_net::{HttpTransport, NetConfig, Origin};
use hasp_server::{
    Gateway, HttpOptions, MemoryStore, ReregisterToken, Server, ServerConfig, Unlimited,
    issue_reregister_tokens,
};
use hasp_testsupport::{TEST_ORIGIN, World};
use secrecy::SecretString;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub(crate) const PASSWORD: &str = "correct horse battery staple";

pub(crate) type HttpClient = Client<HttpTransport, ClientStore>;

pub(crate) struct Live {
    pub(crate) world: World,
    pub(crate) addr: SocketAddr,
    stop: oneshot::Sender<()>,
    task: JoinHandle<std::io::Result<()>>,
}

impl Live {
    pub(crate) async fn start() -> Self {
        let world = World::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, task) = serve(&world, listener);
        Self {
            world,
            addr,
            stop,
            task,
        }
    }

    pub(crate) async fn lose_server_secret(&mut self, master: [u8; 32]) -> Vec<ReregisterToken> {
        let (stop, task) = self.halt();
        let _sent = stop.send(());
        let _joined = task.await;
        let store = self.world.server.with_store(|store| store.clone()).unwrap();
        let server = Arc::new(
            Server::new(
                ServerConfig::new(TEST_ORIGIN, SecretKey::from_bytes(master)),
                store,
                Arc::new(self.world.clock.clone()),
                Arc::new(Unlimited),
            )
            .unwrap(),
        );
        let tokens = server
            .with_store(|store| issue_reregister_tokens(store, 1_000_000, 3600))
            .unwrap()
            .unwrap();
        self.world.server = server;
        let listener = TcpListener::bind(self.addr).await.unwrap();
        let (stop, task) = serve(&self.world, listener);
        self.stop = stop;
        self.task = task;
        tokens
    }

    fn halt(&mut self) -> (oneshot::Sender<()>, JoinHandle<std::io::Result<()>>) {
        let (stop, _) = oneshot::channel::<()>();
        let task = tokio::spawn(async { Ok(()) });
        (
            std::mem::replace(&mut self.stop, stop),
            std::mem::replace(&mut self.task, task),
        )
    }

    pub(crate) fn origin(&self) -> Origin {
        Origin::parse(&format!("http://{}", self.addr)).unwrap()
    }

    pub(crate) fn transport(&self) -> HttpTransport {
        HttpTransport::new(self.origin(), NetConfig::new("hasp-net-test")).unwrap()
    }

    pub(crate) fn client(&self) -> HttpClient {
        self.world.client_with(self.transport(), true).0
    }

    pub(crate) async fn signup(&mut self, login: &str) -> (HttpClient, String) {
        let token = self.world.token().await;
        let mut client = self.client();
        let kit = Box::pin(client.sign_up(
            &SignUp {
                origin: TEST_ORIGIN,
                token: &token,
                login,
                password: &SecretString::from(PASSWORD),
            },
            &CancellationToken::new(),
        ))
        .await
        .unwrap();
        (client, kit.secret_key().to_owned())
    }

    pub(crate) async fn sign_in(&self, login: &str, secret_key: &str) -> HttpClient {
        let mut client = self.client();
        client
            .sign_in(
                &SignIn {
                    origin: TEST_ORIGIN,
                    login,
                    secret_key,
                    password: &SecretString::from(PASSWORD),
                    kit_server_fp: None,
                },
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        client
    }

    pub(crate) async fn stop(self) {
        let _sent = self.stop.send(());
        let _joined = self.task.await;
    }
}

fn serve(
    world: &World,
    listener: TcpListener,
) -> (oneshot::Sender<()>, JoinHandle<std::io::Result<()>>) {
    let gateway: Gateway<MemoryStore> =
        Gateway::new(Arc::clone(&world.server), HttpOptions::default());
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(gateway.run(listener, async move {
        let _stopped = stopped.await;
    }));
    (stop, task)
}
