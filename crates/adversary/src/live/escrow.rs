use hasp_proto::wire::{AccountGet, OpId, Pull, RcSet, VaultCursor};
use hasp_proto::{AccountId, Role, SigLabel, Uint53, Wire};
use hasp_testsupport::World;

use super::lab::{PASSWORD, cancel, password_of, phone, run, secret};
use super::mallory::Mallory;

#[test]
fn e3_recovery_and_family_recovery_create_no_escrow_wrap_and_only_member_made_sharing() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
        let mut organizer = phone(&mut world, &mallory, "organizer@example.com", true).await;
        let mark = mallory.mark();
        let code = alice
            .client
            .create_recovery_code(&secret(PASSWORD), &cancel())
            .await
            .unwrap();
        let ops = mallory.ops_since(mark);
        assert_eq!(
            ops,
            vec![OpId::ReauthStart, OpId::ReauthFinish, OpId::RcSet]
        );
        let token = mallory.stolen_token();
        let record = mallory
            .as_thief(&token, &AccountGet {})
            .unwrap()
            .records
            .pop()
            .unwrap()
            .unverified()
            .unwrap();
        let set = RcSet::from_cbor(&mallory.seen_op(OpId::RcSet).pop().unwrap().request).unwrap();
        assert!(set.rc.verify(SigLabel::Recovery, &record.ik_pk).is_ok());

        let (vault, item) = alice
            .client
            .family_recovery_setup(code.expose(), &cancel())
            .await
            .unwrap();
        let offer = alice
            .client
            .invite_create(&vault, Role::Viewer, &cancel())
            .await
            .unwrap();
        let accepted = organizer
            .client
            .invite_accept(&offer.code, &cancel())
            .await
            .unwrap();
        alice
            .client
            .add_member(
                &vault,
                &offer.invite_id,
                &hasp_core::client::FingerprintCheck::Compared(accepted.my_fingerprint),
                &cancel(),
            )
            .await
            .unwrap();
        organizer.client.sync(&cancel()).await.unwrap();
        assert_eq!(
            password_of(&organizer.client.item(&vault, &item).unwrap()),
            code.expose()
        );

        let page = mallory
            .as_thief(
                &token,
                &Pull {
                    vaults: [vault, alice.private()]
                        .into_iter()
                        .map(|vault_id| VaultCursor {
                            vault_id,
                            seq: hasp_proto::Seq::new(0).unwrap(),
                        })
                        .collect(),
                    notices_after: Uint53::ZERO,
                    limit: Uint53::ZERO,
                },
            )
            .unwrap();
        let allowed: Vec<AccountId> = vec![
            alice.client.account_id().unwrap(),
            organizer.client.account_id().unwrap(),
        ];
        let mut shares = 0;
        for entry in &page.vaults {
            for bundle in &entry.commits {
                if let Some(roster) = &bundle.roster {
                    let roster = roster.unverified().unwrap();
                    assert!(
                        roster
                            .members
                            .iter()
                            .all(|m| allowed.contains(&m.account_id))
                    );
                }
                shares += bundle.shares.len();
            }
            shares += entry.shares.len();
        }
        assert_eq!(shares, 1);

        assert_not_on_the_wire(&mallory, code.expose().as_bytes());
    });
}

fn assert_not_on_the_wire(mallory: &Mallory, needle: &[u8]) {
    for seen in mallory.seen() {
        for bytes in [Some(&seen.request), seen.response.as_ref()]
            .into_iter()
            .flatten()
        {
            assert!(!bytes.windows(needle.len()).any(|w| w == needle));
        }
    }
}
