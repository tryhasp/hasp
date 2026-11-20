use hasp_core::CoreError;
use hasp_core::model::wire::encode_item;
use hasp_proto::wire::{OpId, PullResponse};
use hasp_proto::{ItemParams, Role, Version, Wire, item_wire_hash, seal_item};
use hasp_server::fixture::VaultModel;

use super::lab::{login_item, run};
use super::lair::Lair;
use super::mallory::edit;

fn overview_of(title: &str) -> Vec<u8> {
    encode_item(&login_item(title, "x")).unwrap().0.to_vec()
}

#[test]
fn a_vault_key_holder_cannot_plant_an_old_version_into_the_restorable_history() {
    run(async {
        let mut lair = Box::pin(Lair::new()).await;
        lair.put(1, &overview_of("Bank"));
        lair.put(1, &overview_of("Bank (new)"));
        lair.put(2, &overview_of("Mail"));
        lair.admit_bob(Role::Viewer).await;
        let vault = lair.vault();
        let item = VaultModel::item_id(1);

        let planted = seal_item(
            lair.model.vk(),
            &ItemParams {
                vault_id: vault,
                item_id: item,
                ver: Version::new(1).unwrap(),
                epoch: hasp_proto::Epoch::ZERO,
                overview: &overview_of("Bank (planted)"),
                details: b"details",
                att_ids: Vec::new(),
                prev_h: None,
            },
        )
        .unwrap();
        let forged = planted.clone();
        lair.link.on_response(OpId::Pull, move |bytes| {
            edit::<PullResponse>(bytes, |page| {
                for op in page
                    .vaults
                    .iter_mut()
                    .flat_map(|v| v.commits.iter_mut())
                    .flat_map(|c| c.ops.iter_mut())
                    .filter(|op| op.item_id == forged.item_id && op.ver == forged.ver)
                {
                    *op = forged.clone();
                }
            });
        });
        lair.bob.client.sync(&super::lab::cancel()).await.unwrap();

        let held = lair.bob.store.cache().item_versions(&vault, &item).unwrap();
        let stored: Vec<_> = held.iter().map(|(ver, _, _)| ver.get()).collect();
        assert_eq!(stored, vec![1, 2]);
        let planted_bytes = planted.to_cbor().unwrap();
        assert!(
            held.iter()
                .any(|(_, _, bytes)| item_wire_hash(bytes) == item_wire_hash(&planted_bytes))
        );

        let history = lair.bob.client.history(&vault, &item).unwrap();
        let titles: Vec<_> = history.iter().map(|entry| entry.title.as_str()).collect();
        assert_eq!(titles, vec!["Bank (new)"]);
        let restored = lair.bob.client.restore_version(&vault, &item, 1);
        assert!(
            matches!(restored, Err(CoreError::NotFound(_))),
            "{restored:?}"
        );
    });
}
