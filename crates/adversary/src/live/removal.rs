use hasp_core::CoreError;
use hasp_core::store::LocalVaultStatus;
use hasp_core::sync::VaultSyncState;
use hasp_crypto::hpke_open;
use hasp_proto::wire::{
    AccountLookupResponse, Commit, ErrorCode, InviteListResponse, InviteView, OpId,
};
use hasp_proto::{PinState, Role, Wire};
use hasp_server::Caller;
use hasp_server::fixture::{Person, VaultModel};
use hasp_testsupport::World;

use super::lab::{cancel, invite, login_item, phone, run};
use super::lair::Lair;
use super::mallory::{Mallory, edit};
use super::rogue::{inject, rogue};
use crate::double::{Check, DState, Verifier, kem_hash, share_context};

#[test]
fn e31_a_removal_without_an_epoch_bump_is_refused_by_the_server_and_quarantined_by_a_member() {
    run(async {
        let mut lair = Box::pin(Lair::new()).await;
        let carol = rogue(&mut lair.world, "carol@example.com").await;
        lair.admit_bob(Role::Editor).await;
        lair.admit(&carol, Role::Editor);
        lair.bob.client.sync(&cancel()).await.unwrap();
        let vault = lair.vault();
        let before = lair.bob.state_of(&vault);
        assert!(before.roster.member(&carol.person.account_id).is_some());

        let forged = lair.removal_without_bump(&carol.person.account_id);
        let refused = lair
            .world
            .server
            .call(
                &Caller::with_token(lair.owner.token.clone()),
                &lair.model.commit(forged.clone()),
            )
            .unwrap_err();
        assert_eq!(refused.code, ErrorCode::Epoch);

        inject(
            &lair.link,
            vault,
            forged.clone(),
            Some(forged.manifest.hash()),
        );
        let outcome = lair.bob.sync_state(&vault).await.unwrap();
        assert_eq!(outcome, VaultSyncState::Quarantined("Epoch".to_owned()));
        let info = lair.bob.store.cache().quarantine(&vault).unwrap().unwrap();
        assert_eq!(info.author, Some(lair.owner.person.account_id));
        assert_eq!(info.last_good_seq, before.seq.get());
        assert!(matches!(
            lair.bob.client.create_item(&vault, &login_item("x", "x")),
            Err(CoreError::Quarantined { .. })
        ));
        assert!(
            lair.bob
                .state_of(&vault)
                .roster
                .member(&carol.person.account_id)
                .is_some()
        );

        let commit = [VaultModel::proto_commit(&forged)];
        let own = lair.bob.own_keys();
        let pins = PinState::new();
        let start = DState::from_real(&before);
        assert!(
            Verifier::without(&[Check::RemovalBump])
                .batch(&start, &commit, &own, &pins)
                .is_ok()
        );
        assert!(
            Verifier::full()
                .batch(&start, &commit, &own, &pins)
                .is_err()
        );
    });
}

#[test]
fn e4_a_removal_wraps_the_new_key_to_roster_keys_whatever_the_server_directory_says() {
    run(async {
        let mut world = World::new();
        let owner_link = Mallory::new(&world.server);
        let other = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &owner_link, "alice@example.com", true).await;
        let mut bob = phone(&mut world, &other, "bob@example.com", true).await;
        let mut carol = phone(&mut world, &other, "carol@example.com", true).await;
        let attacker = rogue(&mut world, "mallory@example.com").await;
        let vault = alice
            .client
            .create_vault("Family", &cancel())
            .await
            .unwrap();
        invite(&mut alice, &mut bob, &vault, Role::Editor).await;
        invite(&mut alice, &mut carol, &vault, Role::Editor).await;
        alice.add_login(&vault, "Wifi", "w");
        alice.client.sync(&cancel()).await.unwrap();

        let planted = attacker.person.head.clone();
        let for_lookup = planted.clone();
        owner_link.on_response(OpId::AccountLookup, move |bytes| {
            edit::<AccountLookupResponse>(bytes, |reply| reply.account = Some(for_lookup.clone()));
        });
        let for_list = planted.clone();
        owner_link.on_response(OpId::InviteList, move |bytes| {
            edit::<InviteListResponse>(bytes, |list| {
                for entry in &mut list.invites {
                    entry.invitee = Some(for_list.clone());
                }
            });
        });
        owner_link.on_response(OpId::InviteGet, move |bytes| {
            edit::<InviteView>(bytes, |view| view.inviter = planted.clone());
        });

        let carol_id = carol.client.account_id().unwrap();
        let bob_id = bob.client.account_id().unwrap();
        alice
            .client
            .remove_member(&vault, &bob_id, &cancel())
            .await
            .unwrap();

        let sent = owner_link.seen_op(OpId::Commit).pop().unwrap();
        let commit = Commit::from_cbor(&sent.request).unwrap();
        let state = alice.state_of(&vault);
        let carol_key = state.roster.member(&carol_id).unwrap().clone();
        let owner_key = state.roster.owner().unwrap().ik_pk;
        assert_eq!(commit.bundle.shares.len(), 1);
        let share = commit.bundle.shares[0].unverified().unwrap();
        assert_eq!(share.to, carol_id);
        assert_eq!(share.kem_pk_hash, kem_hash(&carol_key.kem_pk));
        let (info, aad) =
            share_context(&share, &owner_key, &carol_key.ik_pk, &state.roster_hash).unwrap();
        let Person { kem, .. } = &attacker.person;
        assert!(hpke_open(kem, &share.enc, &info, &aad, &share.ct).is_err());

        carol.client.sync(&cancel()).await.unwrap();
        let summary = carol
            .client
            .vaults()
            .unwrap()
            .into_iter()
            .find(|v| v.vault_id == vault)
            .unwrap();
        assert_eq!(summary.epoch, state.epoch.get());
        let items = carol.client.items(&vault).unwrap();
        assert_eq!(items.len(), 1);
        carol.client.item(&vault, &items[0].item_id).unwrap();

        bob.client.sync(&cancel()).await.unwrap();
        let gone = bob
            .client
            .vaults()
            .unwrap()
            .into_iter()
            .find(|v| v.vault_id == vault)
            .unwrap();
        assert_eq!(gone.status, LocalVaultStatus::Removed);
    });
}
