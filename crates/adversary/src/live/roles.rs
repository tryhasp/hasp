use hasp_core::CoreError;
use hasp_core::client::{Admission, FingerprintCheck};
use hasp_proto::wire::{InviteListResponse, InviteView, OpId};
use hasp_proto::{Role, Wire};
use hasp_testsupport::World;

use super::lab::{cancel, login_item, phone, run};
use super::mallory::{Mallory, edit};

fn escalate(link: &Mallory) {
    link.on_response(OpId::InviteList, |bytes| {
        edit::<InviteListResponse>(bytes, |list| {
            for entry in &mut list.invites {
                entry.role = Role::Editor;
            }
        });
    });
}

#[test]
fn h2_the_role_the_owner_chose_survives_a_server_that_raises_it_in_the_invite_row() {
    run(async {
        let mut world = World::new();
        let owner_link = Mallory::new(&world.server);
        let member_link = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &owner_link, "alice@example.com", true).await;
        let mut bob = phone(&mut world, &member_link, "bob@example.com", true).await;
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
        member_link.on_response(OpId::InviteGet, |bytes| {
            edit::<InviteView>(bytes, |view| view.role = Role::Editor);
        });
        let accepted = bob
            .client
            .invite_accept(&offer.code, &cancel())
            .await
            .unwrap();
        escalate(&owner_link);

        let pending = alice
            .client
            .pending_invitees(&vault, &cancel())
            .await
            .unwrap();
        assert_eq!(pending[0].role, Role::Viewer);
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
        bob.client.sync(&cancel()).await.unwrap();

        let listed = owner_link.seen_op(OpId::InviteList).pop().unwrap();
        let row = InviteListResponse::from_cbor(&listed.response.unwrap()).unwrap();
        assert_eq!(row.invites[0].role, Role::Editor);

        let roster = alice.state_of(&vault).roster;
        let bob_id = bob.client.account_id().unwrap();
        assert_eq!(roster.member(&bob_id).unwrap().role, Role::Viewer);
        let summary = bob
            .client
            .vaults()
            .unwrap()
            .into_iter()
            .find(|v| v.vault_id == vault)
            .unwrap();
        assert_eq!(summary.role, Role::Viewer);
        let write = bob.client.create_item(&vault, &login_item("x", "x"));
        assert!(write.is_err(), "{write:?}");
    });
}

#[test]
fn h2_an_explicit_admission_uses_the_owner_role_and_never_a_vault_owner_role_or_the_invite_row() {
    run(async {
        let mut world = World::new();
        let owner_link = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &owner_link, "alice@example.com", true).await;
        let member_link = Mallory::new(&world.server);
        let mut bob = phone(&mut world, &member_link, "bob@example.com", true).await;
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
        escalate(&owner_link);
        let check = FingerprintCheck::Compared(accepted.my_fingerprint);

        let owner_role = alice
            .client
            .add_member_as(
                &vault,
                &Admission {
                    invite: &offer.invite_id,
                    role: Role::Owner,
                    check: &check,
                },
                &cancel(),
            )
            .await;
        assert!(
            matches!(owner_role, Err(CoreError::Refused(_))),
            "{owner_role:?}"
        );

        alice
            .client
            .add_member_as(
                &vault,
                &Admission {
                    invite: &offer.invite_id,
                    role: Role::Viewer,
                    check: &check,
                },
                &cancel(),
            )
            .await
            .unwrap();
        let bob_id = bob.client.account_id().unwrap();
        assert_eq!(
            alice.state_of(&vault).roster.member(&bob_id).unwrap().role,
            Role::Viewer
        );
    });
}
