use hasp_proto::wire::{CommitBundle, ErrorCode, RepairPublish, ServerKey};
use hasp_proto::{Epoch, Manifest, Rver, SigLabel, Signed, leafset_root};

use super::vault::{code, pull_one, shared_vault};
use super::Harness;
use crate::fixture::{Client, VaultModel};

fn repair_bundle(
    alice: &Client,
    good: &VaultModel,
    seq: u64,
    prev: Option<hasp_proto::Hash32>,
) -> CommitBundle {
    let (_, roster_hash) = good.roster.clone().unwrap();
    let manifest = Manifest {
        vault_id: good.id,
        seq: hasp_proto::Seq::new(seq).unwrap(),
        prev,
        epoch: Epoch::new(good.epoch).unwrap(),
        rver: Rver::new(good.rver).unwrap(),
        roster_hash,
        root: leafset_root(&good.leaves).unwrap(),
        author: alice.person.account_id,
        repair: true,
    };
    CommitBundle {
        manifest: Signed::sign(SigLabel::Manifest, &manifest, &alice.person.signing).unwrap(),
        roster: None,
        shares: Vec::new(),
        ops: Vec::new(),
    }
}

fn wedged() -> (Harness, Client, VaultModel, VaultModel) {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let mut vault = shared_vault(&h, &alice);
    let bundle = vault.put_item(&alice.person, 1, b"good");
    h.call(Some(&alice.token), &vault.commit(bundle)).unwrap();
    let good = vault.clone();
    let bundle = vault.put_item(&alice.person, 2, b"bad");
    h.call(Some(&alice.token), &vault.commit(bundle)).unwrap();
    (h, alice, good, vault)
}

#[test]
fn server_key_is_public_and_matches_the_server() {
    let mut h = Harness::new();
    let _ = h.signup("alice");
    let reply = h.call(None, &ServerKey {}).unwrap();
    assert_eq!(reply.public_key.0.len(), 32);
    assert_eq!(reply.public_key.0, h.server.server_public_key().to_vec());
    assert_eq!(reply.origin, h.server.origin());
}

#[test]
fn an_owner_repair_replaces_the_suffix_and_becomes_the_head() {
    let (h, alice, mut good, bad) = wedged();
    let repair = repair_bundle(&alice, &good, bad.seq, good.head);
    let hash = repair.manifest.hash();
    let reply = h
        .call(
            Some(&alice.token),
            &RepairPublish {
                vault_id: good.id,
                bundle: repair,
            },
        )
        .unwrap();
    assert_eq!(reply.head_seq.get(), bad.seq);
    assert_eq!(reply.head_hash, hash);
    let pulled = pull_one(&h, &alice, &good, good.seq);
    assert_eq!(pulled.head_hash, Some(hash));
    assert_eq!(pulled.commits.len(), 1);
    assert!(pulled.commits[0].manifest.unverified().unwrap().repair);
    assert!(pulled.commits[0].ops.is_empty());
    let all = pull_one(&h, &alice, &good, 0);
    assert_eq!(all.commits.len(), 3);
    assert_eq!(all.commits.iter().map(|c| c.ops.len()).sum::<usize>(), 2);

    good.head = Some(hash);
    good.seq = bad.seq;
    let next = good.put_item(&alice.person, 3, b"after");
    let reply = h.call(Some(&alice.token), &good.commit(next)).unwrap();
    assert_eq!(reply.head_seq.get(), bad.seq + 1);
}

#[test]
fn a_repeated_repair_is_idempotent() {
    let (h, alice, good, bad) = wedged();
    let repair = repair_bundle(&alice, &good, bad.seq, good.head);
    let request = RepairPublish {
        vault_id: good.id,
        bundle: repair,
    };
    let first = h.call(Some(&alice.token), &request).unwrap();
    let second = h.call(Some(&alice.token), &request).unwrap();
    assert_eq!(first.head_hash, second.head_hash);
}

#[test]
fn a_replayed_repair_with_a_broken_signature_is_refused() {
    let (h, alice, good, bad) = wedged();
    let repair = repair_bundle(&alice, &good, bad.seq, good.head);
    let request = RepairPublish {
        vault_id: good.id,
        bundle: repair,
    };
    h.call(Some(&alice.token), &request).unwrap();
    let mut altered = request.clone();
    let mut sig = *altered.bundle.manifest.sig.as_bytes();
    sig[0] ^= 1;
    altered.bundle.manifest.sig = hasp_crypto::Signature::from_bytes(sig);
    assert_eq!(code(h.call(Some(&alice.token), &altered)), ErrorCode::Sig);
    h.call(Some(&alice.token), &request).unwrap();
}

#[test]
fn a_repair_must_fork_at_a_known_seq_from_the_last_good_hash() {
    let (h, alice, good, bad) = wedged();
    let ahead = repair_bundle(&alice, &good, bad.seq + 1, good.head);
    assert_eq!(
        code(h.call(
            Some(&alice.token),
            &RepairPublish {
                vault_id: good.id,
                bundle: ahead
            }
        )),
        ErrorCode::Conflict
    );
    let wrong_prev = repair_bundle(&alice, &good, bad.seq, bad.head);
    assert_eq!(
        code(h.call(
            Some(&alice.token),
            &RepairPublish {
                vault_id: good.id,
                bundle: wrong_prev
            }
        )),
        ErrorCode::Fork
    );
    let pulled = pull_one(&h, &alice, &good, good.seq);
    assert_eq!(pulled.head_hash, bad.head);
}

#[test]
fn a_manifest_without_the_repair_flag_or_from_a_stranger_is_refused() {
    let (mut h, alice, good, bad) = wedged();
    let mut plain = repair_bundle(&alice, &good, bad.seq, good.head);
    let mut body = plain.manifest.unverified().unwrap();
    body.repair = false;
    plain.manifest = Signed::sign(SigLabel::Manifest, &body, &alice.person.signing).unwrap();
    assert_eq!(
        code(h.call(
            Some(&alice.token),
            &RepairPublish {
                vault_id: good.id,
                bundle: plain
            }
        )),
        ErrorCode::Format
    );
    let mallory = h.signup("mallory");
    let repair = repair_bundle(&alice, &good, bad.seq, good.head);
    assert_eq!(
        code(h.call(
            Some(&mallory.token),
            &RepairPublish {
                vault_id: good.id,
                bundle: repair
            }
        )),
        ErrorCode::NotMember
    );
}
