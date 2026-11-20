use hasp_core::CoreError;
use hasp_core::client::FingerprintCheck;
use hasp_core::sync::VaultSyncState;
use hasp_proto::wire::{
    Blob, Commit, CommitBundle, ErrorCode, InviteEntry, InviteListResponse, InviteView, OpId,
    PullResponse, SessionToken, SignupToken,
};
use hasp_proto::{
    Hash32, Manifest, PinState, ProtoError, Role, Seq, SigLabel, Signed, VaultId, VaultKind, Wire,
    fingerprint, format_fingerprint, verify_account_record,
};
use hasp_server::fixture::{Person, VaultModel};
use hasp_testsupport::World;

use super::lab::{ORIGIN, Phone, cancel, phone, run};
use super::mallory::{Head, Mallory, edit};

pub(crate) struct Rogue {
    pub(crate) person: Person,
    pub(crate) token: SessionToken,
}

pub(crate) async fn rogue(world: &mut World, login: &str) -> Rogue {
    let signup = SignupToken::parse(&world.token().await).unwrap();
    let person = Person::new(login);
    let mut model = VaultModel::new(VaultKind::Private, &person);
    let (start, state) = person.register_start(&signup);
    let response = world
        .server
        .call(&hasp_server::Caller::anonymous(), &start)
        .unwrap();
    let finish = person.register_finish(&signup, state, &response, &mut model);
    world
        .server
        .call(&hasp_server::Caller::anonymous(), &finish)
        .unwrap();
    let (start, state) = person.login_start();
    let reply = world
        .server
        .call(&hasp_server::Caller::anonymous(), &start)
        .unwrap();
    let (finish, key) = person
        .login_complete(ORIGIN, state, &reply, "rogue")
        .unwrap();
    let done = world
        .server
        .call(&hasp_server::Caller::anonymous(), &finish)
        .unwrap();
    let token = key.token(&done.session_id);
    Rogue { person, token }
}

pub(crate) fn fp_of(person: &Person) -> String {
    format_fingerprint(&fingerprint(&person.ik_pk(), &person.kem_pk()))
}

pub(crate) async fn admit(
    world: &World,
    owner: &mut Phone,
    vault: &VaultId,
    rogue: &Rogue,
    role: Role,
) {
    let offer = owner
        .client
        .invite_create(vault, role, &cancel())
        .await
        .unwrap();
    world
        .server
        .call(
            &hasp_server::Caller::with_token(rogue.token.clone()),
            &hasp_proto::wire::InviteAccept {
                invite_id: offer.invite_id,
                accept: Blob(rogue.person.account_id.to_cbor().unwrap()),
            },
        )
        .unwrap();
    owner
        .client
        .add_member(
            vault,
            &offer.invite_id,
            &FingerprintCheck::Compared(fp_of(&rogue.person)),
            &cancel(),
        )
        .await
        .unwrap();
}

pub(crate) struct Forge {
    pub(crate) seq: u64,
    pub(crate) prev: Option<Hash32>,
    pub(crate) epoch: hasp_proto::Epoch,
    pub(crate) rver: hasp_proto::Rver,
    pub(crate) roster_hash: Hash32,
    pub(crate) root: Hash32,
    pub(crate) repair: bool,
}

pub(crate) fn forge(rogue: &Person, vault: VaultId, f: &Forge) -> (CommitBundle, Hash32) {
    let manifest = Manifest {
        vault_id: vault,
        seq: Seq::new(f.seq).unwrap(),
        prev: f.prev,
        epoch: f.epoch,
        rver: f.rver,
        roster_hash: f.roster_hash,
        root: f.root,
        author: rogue.account_id,
        repair: f.repair,
    };
    let signed = Signed::sign(SigLabel::Manifest, &manifest, &rogue.signing).unwrap();
    let hash = signed.hash();
    (
        CommitBundle {
            manifest: signed,
            roster: None,
            shares: Vec::new(),
            ops: Vec::new(),
        },
        hash,
    )
}

pub(crate) fn inject(
    mallory: &Mallory,
    vault: VaultId,
    bundle: CommitBundle,
    advance: Option<Hash32>,
) {
    mallory.on_response(OpId::Pull, move |bytes| {
        edit::<PullResponse>(bytes, |page| {
            for entry in &mut page.vaults {
                if entry.vault_id == vault {
                    if let Some(hash) = advance {
                        entry.head_seq = bundle.manifest.unverified().unwrap().seq;
                        entry.head_hash = Some(hash);
                    }
                    entry.commits.push(bundle.clone());
                    entry.has_more = false;
                }
            }
        });
    });
}

fn same_root(head: &Head, seq: u64) -> Forge {
    Forge {
        seq,
        prev: Some(head.hash),
        epoch: head.manifest.epoch,
        rver: head.manifest.rver,
        roster_hash: head.manifest.roster_hash,
        root: head.manifest.root,
        repair: false,
    }
}

async fn editor_scene() -> (World, Mallory, Phone, Rogue, VaultId) {
    let mut world = World::new();
    let mallory = Mallory::new(&world.server);
    let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
    let rogue = rogue(&mut world, "mallory@example.com").await;
    let vault = alice
        .client
        .create_vault("Shared", &cancel())
        .await
        .unwrap();
    admit(&world, &mut alice, &vault, &rogue, Role::Editor).await;
    alice.add_login(&vault, "Wifi", "w");
    alice.client.sync(&cancel()).await.unwrap();
    (world, mallory, alice, rogue, vault)
}

fn quarantine_of(alice: &Phone, vault: &VaultId) -> hasp_core::store::QuarantineInfo {
    alice.store.cache().quarantine(vault).unwrap().unwrap()
}

#[test]
fn e22_a_bad_root_from_an_editor_is_refused_by_the_server_and_quarantined_by_clients() {
    run(async {
        let (_world, mallory, mut alice, rogue, vault) = Box::pin(editor_scene()).await;
        let head = mallory.head(&vault).unwrap();
        let mut f = same_root(&head, head.manifest.seq.get() + 1);
        f.root = Hash32::from_bytes([0xab; 32]);
        let (bundle, hash) = forge(&rogue.person, vault, &f);

        let refused = mallory.as_thief(
            &rogue.token,
            &Commit {
                vault_id: vault,
                base_seq: head.manifest.seq,
                bundle: bundle.clone(),
                self_wraps: Vec::new(),
            },
        );
        assert_eq!(refused.err().unwrap().code, ErrorCode::Root);

        inject(&mallory, vault, bundle, Some(hash));
        let report = alice.client.sync(&cancel()).await.unwrap();
        let state = report
            .vaults
            .iter()
            .find(|v| v.vault_id == vault)
            .unwrap()
            .state
            .clone();
        assert_eq!(state, VaultSyncState::Quarantined("Root".to_owned()));
        let info = quarantine_of(&alice, &vault);
        assert_eq!(info.author, Some(rogue.person.account_id));
        assert!(matches!(
            alice
                .client
                .create_item(&vault, &super::lab::login_item("x", "x")),
            Err(CoreError::Quarantined { .. })
        ));

        mallory.passthrough();
        let repair = alice.client.repair_prepare(&vault).unwrap();
        assert!(matches!(
            alice.client.repair_apply(&vault, &repair, false),
            Err(CoreError::Refused(_))
        ));
        assert!(alice.store.cache().quarantine(&vault).unwrap().is_some());
        alice.client.repair_apply(&vault, &repair, true).unwrap();
        assert!(alice.store.cache().quarantine(&vault).unwrap().is_none());
    });
}

#[test]
fn e21_a_removed_writer_cannot_extend_the_head_or_replay_below_it() {
    run(async {
        let (_world, mallory, mut alice, rogue, vault) = Box::pin(editor_scene()).await;
        let before = mallory.head(&vault).unwrap();
        alice
            .client
            .remove_member(&vault, &rogue.person.account_id, &cancel())
            .await
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let after = mallory.head(&vault).unwrap();
        assert!(after.manifest.epoch > before.manifest.epoch);

        let extend = Forge {
            seq: after.manifest.seq.get() + 1,
            prev: Some(after.hash),
            epoch: after.manifest.epoch,
            rver: before.manifest.rver,
            roster_hash: before.manifest.roster_hash,
            root: after.manifest.root,
            repair: false,
        };
        let (bundle, hash) = forge(&rogue.person, vault, &extend);
        inject(&mallory, vault, bundle, Some(hash));
        let report = alice.client.sync(&cancel()).await.unwrap();
        let state = report
            .vaults
            .iter()
            .find(|v| v.vault_id == vault)
            .unwrap()
            .state
            .clone();
        assert_eq!(state, VaultSyncState::Quarantined("Roster".to_owned()));
        alice.client.quarantine_retry(&vault, &cancel()).await.ok();

        mallory.passthrough();
        let replay = Forge {
            seq: after.manifest.seq.get(),
            prev: Some(before.hash),
            epoch: before.manifest.epoch,
            rver: before.manifest.rver,
            roster_hash: before.manifest.roster_hash,
            root: before.manifest.root,
            repair: false,
        };
        let (bundle, _) = forge(&rogue.person, vault, &replay);
        let mut fresh = alice;
        fresh.client.quarantine_retry(&vault, &cancel()).await.ok();
        inject(&mallory, vault, bundle, None);
        let outcome = fresh.client.sync(&cancel()).await;
        let flagged = match outcome {
            Ok(report) => format!(
                "{:?}",
                report
                    .vaults
                    .iter()
                    .find(|v| v.vault_id == vault)
                    .unwrap()
                    .state
            ),
            Err(error) => format!("{error:?}"),
        };
        assert!(
            flagged.contains("Rollback") || flagged.contains("Fork"),
            "{flagged}"
        );
    });
}

#[test]
fn e1_h3_an_invite_whose_inviter_record_is_swapped_is_refused_by_the_invitee() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
        let link = Mallory::new(&world.server);
        let (mut bob_client, _) =
            world.client_on(link.clone(), super::lab::SharedStore::default(), true);
        let token = world.token().await;
        bob_client
            .sign_up(
                &hasp_core::client::SignUp {
                    origin: ORIGIN,
                    token: &token,
                    login: "bob@example.com",
                    password: &super::lab::secret(super::lab::PASSWORD),
                },
                &cancel(),
            )
            .await
            .unwrap();
        let rogue = rogue(&mut world, "mallory@example.com").await;
        let vault = alice
            .client
            .create_vault("Family", &cancel())
            .await
            .unwrap();
        let offer = alice
            .client
            .invite_create(&vault, Role::Editor, &cancel())
            .await
            .unwrap();
        let substitute = rogue.person.head.clone();
        assert!(verify_account_record(&substitute, None, &PinState::new()).is_ok());
        link.on_response(OpId::InviteGet, move |bytes| {
            edit::<InviteView>(bytes, |view| view.inviter = substitute.clone());
        });
        let outcome = bob_client.invite_accept(&offer.code, &cancel()).await;
        assert!(
            matches!(outcome, Err(CoreError::Proto(ProtoError::Invite))),
            "{outcome:?}"
        );
        assert!(link.seen_op(OpId::InviteAccept).is_empty());
    });
}

#[test]
fn e1_a_swapped_invitee_record_fails_the_fingerprint_and_the_server_and_an_unchecked_honest_add_stays_tofu()
 {
    run(async {
        let mut world = World::new();
        let owner_link = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &owner_link, "alice@example.com", true).await;
        let bob_link = Mallory::new(&world.server);
        let mut bob = phone(&mut world, &bob_link, "bob@example.com", true).await;
        let rogue = rogue(&mut world, "mallory@example.com").await;
        let vault = alice
            .client
            .create_vault("Family", &cancel())
            .await
            .unwrap();
        let offer = alice
            .client
            .invite_create(&vault, Role::Viewer, &cancel())
            .await
            .unwrap();
        let accepted = bob
            .client
            .invite_accept(&offer.code, &cancel())
            .await
            .unwrap();
        let substitute = rogue.person.head.clone();
        owner_link.on_response(OpId::InviteList, move |bytes| {
            edit::<InviteListResponse>(bytes, |list| {
                for entry in &mut list.invites {
                    let InviteEntry { invitee, .. } = entry;
                    *invitee = Some(substitute.clone());
                }
            });
        });
        let compared = alice
            .client
            .add_member(
                &vault,
                &offer.invite_id,
                &FingerprintCheck::Compared(accepted.my_fingerprint),
                &cancel(),
            )
            .await;
        assert!(
            matches!(compared, Err(CoreError::Proto(ProtoError::Pin))),
            "{compared:?}"
        );
        let unchecked = alice
            .client
            .add_member(
                &vault,
                &offer.invite_id,
                &FingerprintCheck::NotCompared,
                &cancel(),
            )
            .await;
        assert!(
            matches!(
                unchecked,
                Err(CoreError::Transport(hasp_core::transport::TransportError::Server(w))) if w.code == ErrorCode::Invite
            ),
            "{unchecked:?}"
        );
        owner_link.passthrough();
        alice
            .client
            .add_member(
                &vault,
                &offer.invite_id,
                &FingerprintCheck::NotCompared,
                &cancel(),
            )
            .await
            .unwrap();
        let (_, verified) = alice
            .client
            .trusted_key(&bob.client.account_id().unwrap())
            .unwrap()
            .unwrap();
        assert!(!verified);
    });
}

#[test]
fn repair_abuse_by_a_non_owner_is_refused_by_the_server_and_never_applied_by_members() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
        let mut carol = phone(&mut world, &mallory, "carol@example.com", true).await;
        let rogue = rogue(&mut world, "mallory@example.com").await;
        let vault = alice
            .client
            .create_vault("Shared", &cancel())
            .await
            .unwrap();
        admit(&world, &mut alice, &vault, &rogue, Role::Editor).await;
        let offer = alice
            .client
            .invite_create(&vault, Role::Editor, &cancel())
            .await
            .unwrap();
        let accepted = carol
            .client
            .invite_accept(&offer.code, &cancel())
            .await
            .unwrap();
        alice
            .client
            .add_member(
                &vault,
                &offer.invite_id,
                &FingerprintCheck::Compared(accepted.my_fingerprint),
                &cancel(),
            )
            .await
            .unwrap();
        alice.add_login(&vault, "Wifi", "w");
        alice.client.sync(&cancel()).await.unwrap();
        carol.client.sync(&cancel()).await.unwrap();
        let head = mallory.head(&vault).unwrap();

        let mut f = same_root(&head, head.manifest.seq.get());
        f.prev = head.manifest.prev;
        f.repair = true;
        let (bundle, _) = forge(&rogue.person, vault, &f);
        let refused = mallory.as_thief(
            &rogue.token,
            &hasp_proto::wire::RepairPublish {
                vault_id: vault,
                bundle: bundle.clone(),
            },
        );
        assert!(refused.is_err());

        let mut next = same_root(&head, head.manifest.seq.get() + 1);
        next.repair = true;
        let (parked, hash) = forge(&rogue.person, vault, &next);
        inject(&mallory, vault, parked, Some(hash));
        let report = carol.client.sync(&cancel()).await.unwrap();
        let state = report
            .vaults
            .iter()
            .find(|v| v.vault_id == vault)
            .unwrap()
            .state
            .clone();
        assert_eq!(state, VaultSyncState::RepairPending);
        assert!(matches!(
            carol
                .client
                .create_item(&vault, &super::lab::login_item("x", "x")),
            Err(CoreError::RepairPending { .. })
        ));
        assert!(carol.client.repair_confirm(&vault, false).is_err());
        let applied = carol.client.repair_confirm(&vault, true);
        assert!(applied.is_err(), "{applied:?}");
        assert_eq!(carol.client.items(&vault).unwrap().len(), 1);
        assert!(carol.heads_of(&vault).seq <= head.manifest.seq.get());
    });
}
