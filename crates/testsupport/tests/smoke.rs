#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions assert by unwrapping"
)]

use std::sync::Arc;

use hasp_core::transport::{Transport, TransportError};
use hasp_crypto::SecretKey;
use hasp_proto::wire::{
    AccountGet, Commit, ErrorCode, Health, LoginFinish, Pull, SessionToken, VaultCursor,
};
use hasp_proto::{
    OpenedItem, PinState, Seq, Uint53, VaultKind, Wire, open_item, verify_batch, verify_genesis,
};
use hasp_server::fixture::{ORIGIN, Person, VaultModel};
use hasp_server::{MemoryStore, Server, ServerConfig, SystemClock, Unlimited};
use hasp_testsupport::{InProcess, block_on};

fn transport() -> (Arc<Server<MemoryStore>>, InProcess<MemoryStore>) {
    let server = Arc::new(
        Server::new(
            ServerConfig::new(ORIGIN, SecretKey::from_bytes([3; 32])),
            MemoryStore::new(),
            Arc::new(SystemClock),
            Arc::new(Unlimited),
        )
        .unwrap(),
    );
    let transport = InProcess::new(Arc::clone(&server));
    (server, transport)
}

async fn register_and_login(
    transport: &InProcess<MemoryStore>,
    server: &Server<MemoryStore>,
    person: &Person,
    vault: &mut VaultModel,
) -> SessionToken {
    let token = server.issue_bootstrap_token().unwrap();
    let (start, state) = person.register_start(&token);
    let response = transport.call(None, &start).await.unwrap();
    let finish = person.register_finish(&token, state, &response, vault);
    transport.call(None, &finish).await.unwrap();

    let (start, state) = person.login_start();
    let response = transport.call(None, &start).await.unwrap();
    let (finish, key): (LoginFinish, _) = person
        .login_complete(ORIGIN, state, &response, "smoke")
        .unwrap();
    let done = transport.call(None, &finish).await.unwrap();
    key.token(&done.session_id)
}

#[test]
fn registers_an_account_and_commits_an_item_through_the_transport() {
    block_on(async {
        let (server, transport) = transport();
        let health = transport.call(None, &Health).await.unwrap();
        assert_eq!(health.max_protocol.get(), 1);

        let person = Person::new("alice");
        let mut vault = VaultModel::new(VaultKind::Private, &person);
        let token = register_and_login(&transport, &server, &person, &mut vault).await;

        let account = transport.call(Some(&token), &AccountGet).await.unwrap();
        assert_eq!(account.memberships.len(), 1);
        assert_eq!(account.records.len(), 1);
        assert_eq!(account.records[0], person.head);

        let bundle = vault.put_item(&person, 7, b"my overview");
        let commit: Commit = vault.commit(bundle);
        let committed = transport.call(Some(&token), &commit).await.unwrap();
        assert_eq!(committed.head_seq.get(), 2);

        let pulled = transport
            .call(
                Some(&token),
                &Pull {
                    vaults: vec![VaultCursor {
                        vault_id: vault.id,
                        seq: Seq::ZERO,
                    }],
                    notices_after: Uint53::ZERO,
                    limit: Uint53::ZERO,
                },
            )
            .await
            .unwrap();
        let page = &pulled.vaults[0];
        assert_eq!(page.commits.len(), 2);
        assert_eq!(page.head_seq.get(), 2);

        let own = person.own_keys();
        let pins = PinState::new();
        let genesis = VaultModel::proto_commit(&page.commits[0]);
        let state = verify_genesis(&genesis, &own, &pins).unwrap();
        let rest = [VaultModel::proto_commit(&page.commits[1])];
        let state = verify_batch(&state, &rest, &own, &pins).unwrap();
        assert_eq!(Some(state.hash), page.head_hash);

        let wire = page.commits[1].ops[0].clone();
        let opened = open_item(&wire, &wire.to_cbor().unwrap(), &state, vault.vk()).unwrap();
        match opened {
            OpenedItem::Live { overview, .. } => assert_eq!(overview.expose(), b"my overview"),
            OpenedItem::Tombstone { .. } => panic!("expected a live item"),
        }
    });
}

#[test]
fn server_errors_arrive_typed_and_codec_errors_are_distinct() {
    block_on(async {
        let (_, transport) = transport();
        let error = transport.call(None, &AccountGet).await.unwrap_err();
        match error {
            TransportError::Server(wire) => assert_eq!(wire.code, ErrorCode::Auth),
            TransportError::Codec(_) | TransportError::Unreachable => panic!("wrong error kind"),
        }
        let forged = SessionToken::from_bytes([1; 32]);
        assert!(matches!(
            transport.call(Some(&forged), &AccountGet).await,
            Err(TransportError::Server(_))
        ));
    });
}
