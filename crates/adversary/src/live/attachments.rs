use hasp_core::CoreError;
use hasp_core::client::NewAttachment;
use hasp_crypto::{SecretKey, open, seal_with_nonce};
use hasp_proto::wire::{AttachmentGet, AttachmentGetResponse, AttachmentPut, ErrorCode, OpId};
use hasp_proto::{Aad, AttId, CtxValue, ItemId, Kdf, Uint53, VaultId, Wire, derive};
use hasp_testsupport::World;
use tokio_util::sync::CancellationToken;

use super::lab::{Phone, cancel, phone, run};
use super::mallory::{Mallory, Verdict, edit};

const CHUNK: usize = 1 << 20;

fn file(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).unwrap().wrapping_add(seed))
        .collect()
}

struct Scene {
    mallory: Mallory,
    alice: Phone,
    vault: VaultId,
    item: ItemId,
    att: AttId,
    data: Vec<u8>,
    other: AttId,
}

async fn scene() -> Scene {
    let mut world = World::new();
    let mallory = Mallory::new(&world.server);
    let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
    let vault = alice.private();
    let item = alice.add_login(&vault, "Scans", "pw");
    let data = file(2 * CHUNK + 100, 1);
    let info = alice
        .client
        .attach_file(
            &vault,
            &item,
            &NewAttachment {
                name: "passport.pdf",
                mime: "application/pdf",
                data: &data,
            },
            &cancel(),
        )
        .await
        .unwrap();
    let decoy = alice
        .client
        .attach_file(
            &vault,
            &item,
            &NewAttachment {
                name: "decoy.bin",
                mime: "application/octet-stream",
                data: &file(2 * CHUNK + 100, 9),
            },
            &cancel(),
        )
        .await
        .unwrap();
    alice.client.flush(&vault, &cancel()).await.unwrap();
    Scene {
        mallory,
        alice,
        vault,
        item,
        att: info.att_id,
        data,
        other: decoy.att_id,
    }
}

async fn download(s: &mut Scene) -> Result<Vec<u8>, CoreError> {
    let call: CancellationToken = cancel();
    s.alice
        .client
        .download_attachment(&s.vault, &s.item, &s.att, &call)
        .await
        .map(|bytes| bytes.to_vec())
}

fn nonce(prefix: &[u8; 15], index: u64, last: bool) -> [u8; 24] {
    let mut out = [0_u8; 24];
    out[..15].copy_from_slice(prefix);
    out[15..23].copy_from_slice(&index.to_be_bytes());
    out[23..].fill(u8::from(last));
    out
}

fn chunk_key(key: &SecretKey, vault: &VaultId, item: &ItemId, att: &AttId) -> (SecretKey, Vec<u8>) {
    let derived = derive(
        key,
        Kdf::AttChunk,
        &[
            CtxValue::Id16(*vault.as_bytes()),
            CtxValue::Id16(*item.as_bytes()),
            CtxValue::Id16(*att.as_bytes()),
        ],
    )
    .unwrap();
    let aad = Aad::attachment_chunk(*vault, *item, *att, Uint53::new(CHUNK as u64).unwrap())
        .to_bytes()
        .unwrap();
    (derived, aad)
}

#[test]
fn e18_an_honest_download_returns_the_file_and_each_attack_fails_closed() {
    run(async {
        let mut s = scene().await;
        assert_eq!(download(&mut s).await.unwrap(), s.data);
        let before = s.alice.store.dump();

        s.mallory.on_response(OpId::AttachmentGet, {
            let mut calls = 0;
            move |bytes| {
                if calls == 1 {
                    edit::<AttachmentGetResponse>(bytes, |r| r.last = true);
                }
                calls += 1;
            }
        });
        let truncated = download(&mut s).await;
        assert!(
            matches!(truncated, Err(CoreError::Credentials)),
            "{truncated:?}"
        );

        s.mallory.passthrough();
        s.mallory.on_request(OpId::AttachmentGet, |bytes| {
            edit::<AttachmentGet>(bytes, |r| {
                r.index = Uint53::new(1 - r.index.get().min(1)).unwrap();
            });
            Verdict::Forward
        });
        let reordered = download(&mut s).await;
        assert!(
            matches!(reordered, Err(CoreError::Credentials)),
            "{reordered:?}"
        );

        s.mallory.passthrough();
        let other = s.other;
        s.mallory.on_request(OpId::AttachmentGet, move |bytes| {
            edit::<AttachmentGet>(bytes, |r| r.att_id = other);
            Verdict::Forward
        });
        let spliced = download(&mut s).await;
        assert!(
            matches!(spliced, Err(CoreError::Credentials)),
            "{spliced:?}"
        );

        s.mallory.passthrough();
        s.mallory.on_request(OpId::AttachmentGet, |bytes| {
            let request = AttachmentGet::from_cbor(bytes).unwrap();
            if request.index.get() == 2 {
                Verdict::Fail(ErrorCode::NotFound)
            } else {
                Verdict::Forward
            }
        });
        assert!(download(&mut s).await.is_err());

        s.mallory.passthrough();
        assert_eq!(s.alice.store.dump(), before);
        assert_eq!(download(&mut s).await.unwrap(), s.data);
    });
}

#[test]
fn e18_a_reader_that_ignores_the_last_flag_accepts_a_truncated_file() {
    run(async {
        let mut s = scene().await;
        download(&mut s).await.unwrap();
        let chunks: Vec<Vec<u8>> = s
            .mallory
            .seen_op(OpId::AttachmentGet)
            .into_iter()
            .rev()
            .take(3)
            .rev()
            .map(|seen| {
                AttachmentGetResponse::from_cbor(&seen.response.unwrap())
                    .unwrap()
                    .data
                    .0
            })
            .collect();
        let item = s.alice.client.item(&s.vault, &s.item).unwrap();
        let desc = item
            .details()
            .attachments
            .iter()
            .find(|a| a.att_id.as_bytes() == s.att.as_bytes())
            .unwrap();
        let (key, aad) = chunk_key(&desc.file_key, &s.vault, &s.item, &s.att);
        let mut naive = Vec::new();
        for (index, chunk) in chunks.iter().take(2).enumerate() {
            let opened = open(
                &key,
                &nonce(&desc.nonce_prefix, index as u64, false),
                chunk,
                &aad,
            )
            .unwrap();
            naive.extend_from_slice(opened.expose());
        }
        assert_eq!(naive.len(), 2 * CHUNK);
        assert!(s.data.starts_with(&naive));
        assert!(open(&key, &nonce(&desc.nonce_prefix, 1, true), &chunks[1], &aad).is_err());
    });
}

#[test]
fn e25_a_changed_source_gets_a_fresh_id_key_and_nonce_and_a_resume_replays_staged_bytes() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
        let vault = alice.private();
        let item = alice.add_login(&vault, "Scans", "pw");
        let original = file(CHUNK + 500, 3);
        let mut failed_once = false;
        mallory.on_request(OpId::AttachmentPut, move |bytes| {
            let put = AttachmentPut::from_cbor(bytes).unwrap();
            if put.index.get() == 1 && !failed_once {
                failed_once = true;
                Verdict::Fail(ErrorCode::Internal)
            } else {
                Verdict::Forward
            }
        });
        let attempt = alice
            .client
            .attach_file(
                &vault,
                &item,
                &NewAttachment {
                    name: "a.bin",
                    mime: "application/octet-stream",
                    data: &original,
                },
                &cancel(),
            )
            .await;
        assert!(attempt.is_err());
        let first_puts: Vec<AttachmentPut> = mallory
            .seen_op(OpId::AttachmentPut)
            .iter()
            .map(|s| AttachmentPut::from_cbor(&s.request).unwrap())
            .collect();
        let interrupted = first_puts[0].att_id;
        alice
            .client
            .resume_upload(&interrupted, &cancel())
            .await
            .unwrap();
        let resumed: Vec<AttachmentPut> = mallory
            .seen_op(OpId::AttachmentPut)
            .iter()
            .map(|s| AttachmentPut::from_cbor(&s.request).unwrap())
            .filter(|p| p.att_id == interrupted && p.index.get() == 0)
            .collect();
        assert_eq!(resumed.len(), 2);
        assert_eq!(resumed[0].data, resumed[1].data);

        let mut modified = original.clone();
        modified[10] ^= 0xff;
        let mut infos = Vec::new();
        for data in [&modified, &modified] {
            infos.push(
                alice
                    .client
                    .attach_file(
                        &vault,
                        &item,
                        &NewAttachment {
                            name: "a.bin",
                            mime: "application/octet-stream",
                            data,
                        },
                        &cancel(),
                    )
                    .await
                    .unwrap(),
            );
        }
        assert_ne!(infos[0].att_id, infos[1].att_id);
        assert!(infos.iter().all(|i| i.att_id != interrupted));
        let details = alice.client.item(&vault, &item).unwrap();
        let descs = &details.details().attachments;
        assert_eq!(descs.len(), 2);
        assert_ne!(descs[0].file_key.expose(), descs[1].file_key.expose());
        assert_ne!(descs[0].nonce_prefix, descs[1].nonce_prefix);
        let puts: Vec<AttachmentPut> = mallory
            .seen_op(OpId::AttachmentPut)
            .iter()
            .map(|s| AttachmentPut::from_cbor(&s.request).unwrap())
            .filter(|p| p.index.get() == 0 && p.att_id != interrupted)
            .collect();
        assert_ne!(puts[0].data, puts[1].data);
    });
}

#[test]
fn e25_reusing_key_and_nonce_for_a_changed_file_leaks_the_xor_of_the_plaintexts() {
    let key = SecretKey::from_bytes([4; 32]);
    let n = nonce(&[8; 15], 0, false);
    let (first, second) = (file(4096, 1), file(4096, 77));
    let c1 = seal_with_nonce(&key, &n, &first, b"aad").unwrap();
    let c2 = seal_with_nonce(&key, &n, &second, b"aad").unwrap();
    let leaked: Vec<u8> = c1.iter().zip(&c2).take(4096).map(|(a, b)| a ^ b).collect();
    let expected: Vec<u8> = first.iter().zip(&second).map(|(a, b)| a ^ b).collect();
    assert_eq!(leaked, expected);
}
