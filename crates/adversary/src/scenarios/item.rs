use hasp_crypto::SecretKey;
use hasp_proto::{
    Aad, ItemBody, ItemWire, Rtype, SealedPadded, VaultState, Version, Wire, open_item, tombstone,
};

use crate::double::{Check, DState, Opened, Verifier};
use crate::harness::{OWNER, Session, clone_key, err_name};

struct Fixture {
    session: Session,
    state: VaultState,
    a: ItemWire,
    b: ItemWire,
    vk: SecretKey,
}

fn fixture() -> Fixture {
    let mut session = Session::owner();
    let first = session.chain.put(OWNER, 1, b"overview of a");
    let second = session.chain.put(OWNER, 2, b"overview of b");
    session.advance(&[first, second]);
    let a = session.chain.items.values().next().unwrap().clone();
    let b = session.chain.items.values().nth(1).unwrap().clone();
    let vk = clone_key(session.chain.vk());
    let state = session.state.clone();
    Fixture {
        session,
        state,
        a,
        b,
        vk,
    }
}

fn judge(f: &Fixture, item: &ItemWire, expected: &str) {
    let bytes = item.to_cbor().unwrap();
    assert_eq!(
        err_name(open_item(item, &bytes, &f.state, &f.vk)),
        expected,
        "real verifier"
    );
    let state = DState::from_real(&f.state);
    assert_eq!(
        err_name(Verifier::full().open_item(item, &bytes, &state, &f.vk)),
        expected,
        "reference parity"
    );
}

fn double_open(
    f: &Fixture,
    item: &ItemWire,
    skip: &[Check],
) -> Result<Opened, hasp_proto::ProtoError> {
    let bytes = item.to_cbor()?;
    Verifier::without(skip).open_item(item, &bytes, &DState::from_real(&f.state), &f.vk)
}

fn live_parts(item: &ItemWire) -> (hasp_proto::SealedRaw, SealedPadded, SealedPadded) {
    match &item.body {
        ItemBody::Live { wrap, ov, det } => (wrap.clone(), ov.clone(), det.clone()),
        ItemBody::Tombstone => panic!("live item expected"),
    }
}

#[test]
fn honest_items_open_in_both_verifiers() {
    let f = fixture();
    for item in [&f.a, &f.b] {
        let bytes = item.to_cbor().unwrap();
        let real = open_item(item, &bytes, &f.state, &f.vk).unwrap();
        let double = Verifier::full()
            .open_item(item, &bytes, &DState::from_real(&f.state), &f.vk)
            .unwrap();
        match (real, double) {
            (
                hasp_proto::OpenedItem::Live { overview, .. },
                Opened::Live { overview: mine, .. },
            ) => {
                assert_eq!(overview.expose(), mine.as_slice());
            }
            _ => panic!("expected live items"),
        }
    }
}

#[test]
fn e5_overview_swapped_between_items_is_rejected_by_the_leaf_and_by_the_aead() {
    let f = fixture();
    let (wrap, _, det) = live_parts(&f.b);
    let (_, ov_a, _) = live_parts(&f.a);
    let swapped = ItemWire {
        body: ItemBody::Live {
            wrap,
            ov: ov_a,
            det,
        },
        ..f.b.clone()
    };
    judge(&f, &swapped, "Root");
    assert_eq!(
        err_name(double_open(&f, &swapped, &[Check::ItemLeaf])),
        "Aead"
    );
}

#[test]
fn e5_without_per_item_binding_the_swap_succeeds() {
    let vk = SecretKey::from_bytes([9; 32]);
    let weak = Aad::new(Rtype::ItemPayload);
    let ov_a = SealedPadded::seal(&vk, b"overview of a", &weak).unwrap();
    let _ov_b = SealedPadded::seal(&vk, b"overview of b", &weak).unwrap();
    let shown_for_b = ov_a.open(&vk, &weak).unwrap();
    assert_eq!(shown_for_b.expose(), b"overview of a");
}

#[test]
fn e5_whole_body_moved_to_another_item_id_is_rejected() {
    let f = fixture();
    let moved = ItemWire {
        item_id: f.b.item_id,
        ..f.a.clone()
    };
    assert_eq!(
        {
            judge(&f, &moved, "Root");
            err_name(double_open(&f, &moved, &[Check::ItemLeaf]))
        },
        "Aead"
    );
}

#[test]
fn e6_version_bumped_on_the_wire_is_rejected() {
    let f = fixture();
    let bumped = ItemWire {
        ver: Version::new(2).unwrap(),
        ..f.a.clone()
    };
    assert_eq!(
        {
            judge(&f, &bumped, "Root");
            err_name(double_open(&f, &bumped, &[Check::ItemLeaf]))
        },
        "Aead"
    );
}

#[test]
fn e6_epoch_changed_on_the_wire_is_rejected() {
    let f = fixture();
    let moved = ItemWire {
        epoch: hasp_proto::Epoch::new(1).unwrap(),
        ..f.a.clone()
    };
    assert_eq!(
        {
            judge(&f, &moved, "Root");
            err_name(double_open(&f, &moved, &[Check::ItemLeaf]))
        },
        "Aead"
    );
}

#[test]
fn e6_live_item_served_as_a_tombstone_is_rejected() {
    let f = fixture();
    let deleted = tombstone(f.a.vault_id, f.a.item_id, f.a.ver, f.a.epoch, None);
    judge(&f, &deleted, "Root");
    let opened = double_open(&f, &deleted, &[Check::ItemLeaf]).unwrap();
    assert_eq!(opened, Opened::Tombstone);
}

fn overview_of(opened: Opened) -> Vec<u8> {
    match opened {
        Opened::Live { overview, .. } => overview,
        Opened::Tombstone => Vec::new(),
    }
}

#[test]
fn e7_deleted_item_resurrected_from_history_is_rejected() {
    let mut f = fixture();
    let delete = f.session.chain.delete(OWNER, 1);
    f.session.advance(&[delete]);
    f.state = f.session.state.clone();
    judge(&f, &f.a, "Root");
    let shown = double_open(&f, &f.a, &[Check::ItemLeaf]).unwrap();
    assert_eq!(overview_of(shown), b"overview of a");
}

#[test]
fn e7_older_version_served_in_place_of_the_current_one_is_rejected() {
    let mut f = fixture();
    let edit = f.session.chain.put(OWNER, 1, b"edited a");
    f.session.advance(&[edit]);
    f.state = f.session.state.clone();
    judge(&f, &f.a, "Root");
    let shown = double_open(&f, &f.a, &[Check::ItemLeaf]).unwrap();
    assert_eq!(overview_of(shown), b"overview of a");
}

#[test]
fn e11_wire_bytes_that_differ_from_the_canonical_encoding_are_rejected() {
    let f = fixture();
    let mut bytes = f.a.to_cbor().unwrap();
    bytes.push(0);
    assert_eq!(err_name(open_item(&f.a, &bytes, &f.state, &f.vk)), "Format");
}
