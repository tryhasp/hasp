use std::sync::{Arc, Mutex};

use hasp_core::CoreError;
use hasp_core::sync::VaultSyncState;
use hasp_proto::wire::{OpId, PullResponse, VaultPull};
use hasp_proto::{Commit, ItemWire, PinState, ProtoError, VaultId, VaultState};
use hasp_server::fixture::VaultModel;
use hasp_testsupport::World;

use super::lab::{PASSWORD, Phone, cancel, kit_device, login_item, phone, run};
use super::mallory::{Mallory, edit};
use crate::double::{Check, DState, Verifier, root_of};
use crate::harness::err_name;

const CHAIN_ONLY: &[Check] = &[Check::Root, Check::OpVersion];

struct Duel {
    victim: Phone,
    link: Mallory,
    vault: VaultId,
    before: VaultState,
    items: usize,
    served: Arc<Mutex<Vec<Commit>>>,
    _world: World,
}

async fn duel() -> Duel {
    let mut world = World::new();
    let writer_link = Mallory::new(&world.server);
    let mut writer = phone(&mut world, &writer_link, "alice@example.com", true).await;
    let vault = writer.private();
    writer.add_login(&vault, "Seed", "s");
    writer.client.sync(&cancel()).await.unwrap();
    let link = Mallory::new(&world.server);
    let victim = kit_device(&world, &link, writer.kit(), "alice@example.com", PASSWORD)
        .await
        .unwrap();
    let wifi = writer.add_login(&vault, "Wifi", "one");
    writer.client.sync(&cancel()).await.unwrap();
    writer.add_login(&vault, "Mail", "two");
    writer.client.sync(&cancel()).await.unwrap();
    writer
        .client
        .edit_item(&vault, &wifi, &login_item("Wifi", "three"))
        .unwrap();
    writer.client.sync(&cancel()).await.unwrap();
    Duel {
        before: victim.state_of(&vault),
        items: victim.client.items(&vault).unwrap().len(),
        victim,
        link,
        vault,
        served: Arc::default(),
        _world: world,
    }
}

impl Duel {
    fn serve(&self, mut change: impl FnMut(usize, &mut VaultPull) + Send + 'static) {
        let vault = self.vault;
        let sink = Arc::clone(&self.served);
        let mut call = 0;
        self.link.on_response(OpId::Pull, move |bytes| {
            edit::<PullResponse>(bytes, |page| {
                for entry in page.vaults.iter_mut().filter(|v| v.vault_id == vault) {
                    change(call, entry);
                    sink.lock()
                        .unwrap()
                        .extend(entry.commits.iter().map(VaultModel::proto_commit));
                }
            });
            call += 1;
        });
    }

    fn served(&self) -> Vec<Commit> {
        self.served.lock().unwrap().clone()
    }

    fn verify(
        &self,
        verifier: &Verifier,
        from: &DState,
        commits: &[Commit],
    ) -> Result<DState, ProtoError> {
        verifier.batch(from, commits, &self.victim.own_keys(), &PinState::new())
    }

    fn start(&self) -> DState {
        DState::from_real(&self.before)
    }

    fn naive_pages(&self, pages: &[(&[Commit], bool)]) -> Result<DState, ProtoError> {
        pages
            .iter()
            .try_fold(self.start(), |state, (commits, has_more)| {
                let verifier = if *has_more {
                    Verifier::without(CHAIN_ONLY)
                } else {
                    Verifier::full()
                };
                self.verify(&verifier, &state, commits)
            })
    }

    fn naive_fallback(&self, commits: &[Commit]) -> Result<DState, ProtoError> {
        self.verify(&Verifier::full(), &self.start(), commits)
            .or_else(|_| {
                let weak = self.verify(&Verifier::without(CHAIN_ONLY), &self.start(), commits)?;
                let head = commits.last().unwrap().manifest.unverified()?.root;
                if root_of(&weak.leaves) == head {
                    Ok(weak)
                } else {
                    Err(ProtoError::Root)
                }
            })
    }

    fn assert_untouched(&self) {
        assert_eq!(self.victim.heads_of(&self.vault).seq, self.before.seq.get());
        assert_eq!(
            self.victim.client.items(&self.vault).unwrap().len(),
            self.items
        );
    }
}

#[test]
fn c1_a_dropped_op_behind_a_has_more_flag_is_quarantined_while_a_naive_loop_accepts_it() {
    run(async {
        let mut duel = Box::pin(duel()).await;
        duel.serve(|_, entry| {
            entry.commits[1].ops.clear();
            entry.has_more = true;
        });
        let outcome = duel.victim.sync_state(&duel.vault).await;
        assert!(
            matches!(&outcome, Ok(VaultSyncState::Quarantined(check)) if check == "Root"),
            "{outcome:?}"
        );
        duel.assert_untouched();

        let commits = duel.served();
        let polluted = duel.naive_pages(&[(&commits, true), (&[], false)]).unwrap();
        let head = commits.last().unwrap().manifest.unverified().unwrap().root;
        assert_ne!(root_of(&polluted.leaves), head);
        assert_eq!(
            err_name(duel.verify(&Verifier::full(), &duel.start(), &commits)),
            "Root"
        );
    });
}

#[test]
fn c1_a_truncated_first_page_followed_by_empty_pages_never_completes() {
    run(async {
        let mut duel = Box::pin(duel()).await;
        duel.serve(|call, entry| {
            if call == 0 {
                entry.commits.truncate(1);
                entry.commits[0].ops.clear();
                entry.has_more = true;
            } else {
                entry.commits.clear();
                entry.has_more = false;
            }
        });
        let outcome = duel.victim.sync_state(&duel.vault).await;
        assert!(
            matches!(outcome, Err(CoreError::Proto(ProtoError::Format))),
            "{outcome:?}"
        );
        duel.assert_untouched();
        assert!(duel.link.seen_op(OpId::Pull).len() <= 5000);
    });
}

#[test]
fn c1_has_more_with_no_commits_is_refused_at_once() {
    run(async {
        let mut duel = Box::pin(duel()).await;
        duel.serve(|_, entry| {
            entry.commits.clear();
            entry.has_more = true;
        });
        let outcome = duel.victim.sync_state(&duel.vault).await;
        assert!(
            matches!(outcome, Err(CoreError::Proto(ProtoError::Format))),
            "{outcome:?}"
        );
        duel.assert_untouched();
        assert!(duel.link.seen_op(OpId::Pull).len() < 10);
    });
}

#[test]
fn c1_an_older_item_wire_swapped_into_a_later_page_is_quarantined() {
    run(async {
        let mut duel = Box::pin(duel()).await;
        let first: Arc<Mutex<Option<ItemWire>>> = Arc::default();
        let stash = Arc::clone(&first);
        duel.serve(move |call, entry| {
            if call == 0 {
                *stash.lock().unwrap() = entry.commits[0].ops.first().cloned();
                entry.commits.truncate(1);
                entry.has_more = true;
            } else {
                let old = stash.lock().unwrap().clone().unwrap();
                entry.commits.last_mut().unwrap().ops[0] = old;
            }
        });
        let outcome = duel.victim.sync_state(&duel.vault).await;
        assert!(
            matches!(outcome, Ok(VaultSyncState::Quarantined(_))),
            "{outcome:?}"
        );
        duel.assert_untouched();

        let commits = duel.served();
        assert_eq!(commits.len(), 3);
        assert!(
            duel.verify(&Verifier::full(), &duel.start(), &commits)
                .is_err()
        );
        duel.verify(&Verifier::without(CHAIN_ONLY), &duel.start(), &commits)
            .unwrap();
    });
}

#[test]
fn h1_ops_moved_between_commits_are_quarantined_and_a_weaker_fallback_would_accept_them() {
    run(async {
        let mut duel = Box::pin(duel()).await;
        duel.serve(|_, entry| {
            let moved = std::mem::take(&mut entry.commits[0].ops);
            entry.commits[1].ops.splice(0..0, moved);
        });
        let outcome = duel.victim.sync_state(&duel.vault).await;
        assert_eq!(
            outcome.unwrap(),
            VaultSyncState::Quarantined("Root".to_owned())
        );
        let info = duel
            .victim
            .store
            .cache()
            .quarantine(&duel.vault)
            .unwrap()
            .unwrap();
        assert_eq!(info.last_good_seq, duel.before.seq.get());
        duel.assert_untouched();

        let commits = duel.served();
        assert_eq!(
            err_name(duel.verify(&Verifier::full(), &duel.start(), &commits)),
            "Root"
        );
        assert!(duel.naive_fallback(&commits).is_ok());
    });
}
