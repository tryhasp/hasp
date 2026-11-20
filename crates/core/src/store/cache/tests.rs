use hasp_crypto::{SecretKey, SigningKey};
use hasp_proto::{
    AccountId, Epoch, Hash32, Manifest, Member, Role, Roster, Rver, Seq, SigLabel, Signed, VaultId,
    VaultKind,
};

use super::*;
use crate::store::MemoryStore;

fn vault_at(seq: u64) -> VaultLocal {
    let signer = SigningKey::from_seed(&SecretKey::from_bytes([1; 32]));
    let vault_id = VaultId::from_bytes([3; 16]);
    let account = AccountId::from_bytes([4; 16]);
    let roster = Roster {
        vault_id,
        rver: Rver::new(1).unwrap(),
        epoch: Epoch::new(0).unwrap(),
        prev: None,
        kind: VaultKind::Shared,
        members: vec![Member {
            account_id: account,
            ik_pk: signer.verifying_key(),
            kem_pk: hasp_crypto::KemSecretKey::from_seed(&SecretKey::from_bytes([2; 32]))
                .unwrap()
                .public_key(),
            role: Role::Owner,
            added_rver: Rver::new(1).unwrap(),
        }],
        vk_commit: Hash32::from_bytes([9; 32]),
    };
    let roster = Signed::sign(SigLabel::Roster, &roster, &signer).unwrap();
    let manifest = Manifest {
        vault_id,
        seq: Seq::new(seq).unwrap(),
        prev: None,
        epoch: Epoch::new(0).unwrap(),
        rver: Rver::new(1).unwrap(),
        roster_hash: roster.hash(),
        root: Hash32::from_bytes([0; 32]),
        author: account,
        repair: false,
    };
    let manifest = Signed::sign(SigLabel::Manifest, &manifest, &signer).unwrap();
    let mut vault = VaultLocal::new(vault_id, VaultKind::Shared, Role::Owner);
    vault.head = Some(Head {
        seq: Seq::new(seq).unwrap(),
        hash: manifest.hash(),
        manifest,
        roster,
        leaves: Vec::new(),
    });
    vault
}

fn write(cache: &mut Cache<MemoryStore>, vault: &VaultLocal) -> Result<(), StoreError> {
    let mut batch = Batch::new();
    Records::put_vault(&mut batch, vault)?;
    cache.commit(&batch)
}

#[test]
fn a_head_whose_leaves_do_not_hash_to_the_manifest_root_does_not_open() {
    let head = vault_at(5).head.unwrap();
    assert!(matches!(head.state(), Err(StoreError::Corrupt(_))));
}

#[test]
fn refuses_a_write_that_lowers_a_stored_head() {
    let mut cache = Cache::new(MemoryStore::default());
    write(&mut cache, &vault_at(5)).unwrap();
    assert!(matches!(
        write(&mut cache, &vault_at(3)),
        Err(StoreError::Stale)
    ));
    let held = cache.vault(&VaultId::from_bytes([3; 16])).unwrap().unwrap();
    assert_eq!(held.head.unwrap().seq.get(), 5);
    write(&mut cache, &vault_at(5)).unwrap();
    write(&mut cache, &vault_at(6)).unwrap();
}
