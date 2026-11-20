use hasp_proto::wire::{AttachmentComplete, AttachmentGet, AttachmentPut, ErrorCode};
use hasp_proto::{AttId, Role, Uint53};

use super::vault::{code, shared_vault};
use super::Harness;
use crate::fixture::{Client, VaultModel};

fn put(vault: &VaultModel, att: AttId, index: u64, data: &[u8]) -> AttachmentPut {
    AttachmentPut {
        vault_id: vault.id,
        att_id: att,
        index: Uint53::new(index).unwrap(),
        data: data.to_vec().into(),
    }
}

fn complete(vault: &VaultModel, att: AttId, chunks: u64) -> AttachmentComplete {
    AttachmentComplete {
        vault_id: vault.id,
        att_id: att,
        chunks: Uint53::new(chunks).unwrap(),
    }
}

fn upload(h: &Harness, who: &Client, vault: &VaultModel, att: AttId, chunks: &[&[u8]]) {
    for (index, data) in chunks.iter().enumerate() {
        h.call(
            Some(&who.token),
            &put(vault, att, u64::try_from(index).unwrap(), data),
        )
        .unwrap();
    }
    h.call(
        Some(&who.token),
        &complete(vault, att, u64::try_from(chunks.len()).unwrap()),
    )
    .unwrap();
}

fn attachment_count(h: &Harness) -> (usize, usize) {
    h.server
        .with_store(|store| {
            use crate::store::Store;
            (
                store.attachments().len().unwrap(),
                store.attachment_chunks().len().unwrap(),
            )
        })
        .unwrap()
}

#[test]
fn chunks_upload_resume_complete_and_download_in_order() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let att = AttId::from_bytes([1; 16]);
    let vault = &alice.vault;
    h.call(Some(&alice.token), &put(vault, att, 0, b"first"))
        .unwrap();
    h.call(Some(&alice.token), &put(vault, att, 0, b"first"))
        .unwrap();
    assert_eq!(
        code(h.call(Some(&alice.token), &put(vault, att, 0, b"changed"))),
        ErrorCode::Conflict
    );
    assert_eq!(
        code(h.call(Some(&alice.token), &put(vault, att, 2, b"gap"))),
        ErrorCode::Conflict
    );
    h.call(Some(&alice.token), &put(vault, att, 1, b"second"))
        .unwrap();
    assert_eq!(
        code(h.call(Some(&alice.token), &complete(vault, att, 3))),
        ErrorCode::Conflict
    );
    let get = |index| AttachmentGet {
        vault_id: vault.id,
        att_id: att,
        index: Uint53::new(index).unwrap(),
    };
    assert_eq!(
        code(h.call(Some(&alice.token), &get(0))),
        ErrorCode::NotFound
    );
    h.call(Some(&alice.token), &complete(vault, att, 2))
        .unwrap();
    let first = h.call(Some(&alice.token), &get(0)).unwrap();
    assert_eq!(
        (first.data.0.as_slice(), first.last),
        (&b"first"[..], false)
    );
    let second = h.call(Some(&alice.token), &get(1)).unwrap();
    assert_eq!(
        (second.data.0.as_slice(), second.last),
        (&b"second"[..], true)
    );
    assert_eq!(
        code(h.call(Some(&alice.token), &get(2))),
        ErrorCode::NotFound
    );
    assert_eq!(
        code(h.call(Some(&alice.token), &put(vault, att, 2, b"late"))),
        ErrorCode::Conflict
    );
}

#[test]
fn an_empty_attachment_cannot_be_completed() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let att = AttId::from_bytes([2; 16]);
    assert_eq!(
        code(h.call(Some(&alice.token), &complete(&alice.vault, att, 0))),
        ErrorCode::NotFound
    );
    h.call(Some(&alice.token), &put(&alice.vault, att, 0, b"x"))
        .unwrap();
    assert_eq!(
        code(h.call(Some(&alice.token), &complete(&alice.vault, att, 0))),
        ErrorCode::Conflict
    );
}

#[test]
fn chunk_and_total_sizes_are_bounded() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let att = AttId::from_bytes([3; 16]);
    let too_big = vec![0; (1 << 20) + 17];
    assert_eq!(
        code(h.call(Some(&alice.token), &put(&alice.vault, att, 0, &too_big))),
        ErrorCode::TooLarge
    );
    let full = vec![0; (1 << 20) + 16];
    let mut sent = 0_u64;
    let result = loop {
        match h.call(Some(&alice.token), &put(&alice.vault, att, sent, &full)) {
            Ok(_) => sent += 1,
            Err(error) => break error.code,
        }
        assert!(sent < 200);
    };
    assert_eq!(result, ErrorCode::TooLarge);
    assert_eq!(sent, 99);
}

#[test]
fn membership_and_write_role_gate_attachments() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let carol = h.signup("carol");
    let mut model = shared_vault(&h, &alice);
    for (who, role) in [(&bob, Role::Viewer), (&carol, Role::Editor)] {
        super::members::invite_raw(&h, &alice, &who.token, &model, role);
        let bundle = model.add_member(&alice.person, &who.person, role);
        h.call(Some(&alice.token), &model.commit(bundle)).unwrap();
    }
    let att = AttId::from_bytes([4; 16]);
    assert_eq!(
        code(h.call(Some(&bob.token), &put(&model, att, 0, b"x"))),
        ErrorCode::ReadOnly
    );
    upload(&h, &carol, &model, att, &[b"data"]);
    let get = AttachmentGet {
        vault_id: model.id,
        att_id: att,
        index: Uint53::ZERO,
    };
    assert!(h.call(Some(&bob.token), &get).is_ok());
    let outsider = h.signup("dave");
    assert_eq!(
        code(h.call(Some(&outsider.token), &get)),
        ErrorCode::NotMember
    );
    assert_eq!(
        code(h.call(Some(&outsider.token), &put(&model, att, 1, b"y"))),
        ErrorCode::NotMember
    );
    let elsewhere = AttachmentGet {
        vault_id: alice.vault.id,
        ..get
    };
    assert_eq!(
        code(h.call(Some(&alice.token), &elsewhere)),
        ErrorCode::NotFound
    );
    assert_eq!(
        code(h.call(Some(&alice.token), &put(&alice.vault, att, 1, b"z"))),
        ErrorCode::Conflict
    );
}

#[test]
fn committing_a_reference_needs_a_complete_attachment_of_the_same_vault() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let att = AttId::from_bytes([5; 16]);
    let missing = alice
        .vault
        .clone()
        .put_item_with_attachments(&alice.person, 1, vec![att]);
    assert_eq!(
        code(h.call(Some(&alice.token), &alice.vault.commit(missing))),
        ErrorCode::NotFound
    );
    h.call(Some(&alice.token), &put(&alice.vault, att, 0, b"x"))
        .unwrap();
    let uploading = alice
        .vault
        .clone()
        .put_item_with_attachments(&alice.person, 1, vec![att]);
    assert_eq!(
        code(h.call(Some(&alice.token), &alice.vault.commit(uploading))),
        ErrorCode::NotFound
    );
    h.call(Some(&alice.token), &complete(&alice.vault, att, 1))
        .unwrap();
    let bundle = alice
        .vault
        .put_item_with_attachments(&alice.person, 1, vec![att]);
    h.call(Some(&alice.token), &alice.vault.commit(bundle))
        .unwrap();

    let other = shared_vault(&h, &alice);
    let mut other = other;
    let cross = other.put_item_with_attachments(&alice.person, 1, vec![att]);
    assert_eq!(
        code(h.call(Some(&alice.token), &other.commit(cross))),
        ErrorCode::NotFound
    );
}

#[test]
fn an_attachment_lives_until_no_retained_version_references_it() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let att = AttId::from_bytes([6; 16]);
    upload(&h, &alice, &alice.vault, att, &[b"one", b"two"]);
    let bundle = alice
        .vault
        .put_item_with_attachments(&alice.person, 1, vec![att]);
    h.call(Some(&alice.token), &alice.vault.commit(bundle))
        .unwrap();
    assert_eq!(attachment_count(&h), (1, 2));

    let bundle = alice
        .vault
        .put_item_with_attachments(&alice.person, 1, Vec::new());
    h.call(Some(&alice.token), &alice.vault.commit(bundle))
        .unwrap();
    assert_eq!(attachment_count(&h), (1, 2));
    for n in 0..8_u8 {
        let bundle = alice.vault.put_item(&alice.person, 1, &[n]);
        h.call(Some(&alice.token), &alice.vault.commit(bundle))
            .unwrap();
    }
    assert_eq!(attachment_count(&h), (1, 2));
    let bundle = alice
        .vault
        .put_item(&alice.person, 1, b"push the first version out");
    h.call(Some(&alice.token), &alice.vault.commit(bundle))
        .unwrap();
    assert_eq!(attachment_count(&h), (0, 0));
}

#[test]
fn two_items_share_a_reference_count() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let att = AttId::from_bytes([7; 16]);
    upload(&h, &alice, &alice.vault, att, &[b"shared"]);
    for n in [1, 2] {
        let bundle = alice
            .vault
            .put_item_with_attachments(&alice.person, n, vec![att]);
        h.call(Some(&alice.token), &alice.vault.commit(bundle))
            .unwrap();
    }
    for n in 0..10_u8 {
        let bundle = alice.vault.put_item(&alice.person, 1, &[n]);
        h.call(Some(&alice.token), &alice.vault.commit(bundle))
            .unwrap();
    }
    assert_eq!(attachment_count(&h), (1, 1));
    for n in 0..10_u8 {
        let bundle = alice.vault.put_item(&alice.person, 2, &[n]);
        h.call(Some(&alice.token), &alice.vault.commit(bundle))
            .unwrap();
    }
    assert_eq!(attachment_count(&h), (0, 0));
}

#[test]
fn unreferenced_uploads_are_collected_after_a_day() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let abandoned = AttId::from_bytes([8; 16]);
    let finished = AttId::from_bytes([9; 16]);
    h.call(
        Some(&alice.token),
        &put(&alice.vault, abandoned, 0, b"half"),
    )
    .unwrap();
    upload(&h, &alice, &alice.vault, finished, &[b"done but unused"]);
    h.clock.advance(23 * 3600);
    h.server.sweep().unwrap();
    assert_eq!(attachment_count(&h), (2, 2));
    h.clock.advance(2 * 3600);
    h.server.sweep().unwrap();
    assert_eq!(attachment_count(&h), (0, 0));
}

#[test]
fn a_referenced_attachment_survives_the_sweep() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let att = AttId::from_bytes([10; 16]);
    upload(&h, &alice, &alice.vault, att, &[b"keep"]);
    let bundle = alice
        .vault
        .put_item_with_attachments(&alice.person, 1, vec![att]);
    h.call(Some(&alice.token), &alice.vault.commit(bundle))
        .unwrap();
    h.clock.advance(3 * 24 * 3600);
    h.server.sweep().unwrap();
    assert_eq!(attachment_count(&h), (1, 1));
}
