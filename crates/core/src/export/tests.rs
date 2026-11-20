use hasp_proto::{Kdf, Writer, derive};
use secrecy::SecretSlice;
use zeroize::Zeroizing;

use super::header::*;
use super::reader::*;
use super::writer::*;
use super::*;
use crate::stream::PAD_BLOCK;

fn params() -> Argon2idParams {
    Argon2idParams::local(8, 1, 1).unwrap()
}

fn passphrase() -> SecretString {
    SecretString::from("correct horse")
}

#[test]
fn the_key_check_value_comes_from_its_own_derived_key_and_not_from_the_stream_key() {
    let key = SecretKey::from_bytes([7; 32]);
    let own = derive(&key, Kdf::ExportKcv, &[]).unwrap();
    assert_eq!(key_check(&key).as_slice(), &own.expose()[..KCV_LEN]);
    let reused = hasp_crypto::hmac_sha256(&key, b"hasp/v1/export-kcv");
    assert_ne!(key_check(&key).as_slice(), &reused[..KCV_LEN]);
}

fn file_of(
    body: impl FnOnce(&mut StreamWriter<'_, Vec<u8>>) -> Result<(), ExportError>,
) -> Vec<u8> {
    let passphrase = passphrase();
    let mut out = Vec::new();
    let protection = Protection::Passphrase {
        passphrase: &passphrase,
        params: params(),
    };
    write_stream(&mut out, &protection, 7, body).unwrap();
    out
}

fn open_file(bytes: &[u8]) -> Result<ExportContent, ExportError> {
    read(bytes, &Unlock::Passphrase(&passphrase()))
}

fn vault(n: u8) -> Vec<u8> {
    vault_record(&ExportVault {
        id: Id::from_bytes([n; 16]),
        name: format!("vault {n}"),
        kind: VaultKind::Shared,
    })
    .unwrap()
}

#[test]
fn stream_round_trips_around_chunk_boundaries() {
    for size in [
        0,
        1,
        4095,
        4096,
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
        2 * CHUNK_SIZE,
    ] {
        let key = SecretKey::from_bytes([9; 32]);
        let prefix = [3_u8; NONCE_PREFIX_LEN];
        let aad = b"aad".to_vec();
        let mut out = Vec::new();
        let data: Vec<u8> = (0..size).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let mut stream = StreamWriter {
            out: &mut out,
            key: SecretKey::from_bytes([9; 32]),
            aad: aad.clone(),
            prefix,
            buffer: Zeroizing::new(Vec::new()),
            index: 0,
        };
        stream.push(&data).unwrap();
        stream.finish().unwrap();
        let plaintext = decrypt_stream(&out, &key, &prefix, &aad).unwrap();
        assert_eq!(plaintext.as_slice(), data.as_slice(), "{size}");
        let expected_chunks = size / CHUNK_SIZE + 1;
        let last_padded = ((size % CHUNK_SIZE) + 1).div_ceil(PAD_BLOCK) * PAD_BLOCK;
        let expected = (expected_chunks - 1) * (CHUNK_SIZE + TAG_LEN) + last_padded + TAG_LEN;
        assert_eq!(out.len(), expected, "{size}");
    }
}

#[test]
fn a_dropped_last_chunk_is_corruption_not_a_short_file() {
    let key = SecretKey::from_bytes([9; 32]);
    let prefix = [3_u8; NONCE_PREFIX_LEN];
    let mut out = Vec::new();
    let mut stream = StreamWriter {
        out: &mut out,
        key: SecretKey::from_bytes([9; 32]),
        aad: Vec::new(),
        prefix,
        buffer: Zeroizing::new(Vec::new()),
        index: 0,
    };
    stream.push(&vec![1; CHUNK_SIZE + 10]).unwrap();
    stream.finish().unwrap();
    let first = CHUNK_SIZE + TAG_LEN;
    assert!(matches!(
        decrypt_stream(&out[..first], &key, &prefix, &[]),
        Err(ExportError::Corrupt("truncated"))
    ));
}

#[test]
fn requires_an_end_record_and_matching_counts() {
    let missing = file_of(|s| s.record(&vault(1)));
    assert!(matches!(
        open_file(&missing),
        Err(ExportError::Corrupt("missing end record"))
    ));
    let wrong = file_of(|s| {
        s.record(&vault(1))?;
        s.record(&end_record(Counts {
            vaults: 2,
            items: 0,
            attachments: 0,
        })?)
    });
    assert!(matches!(
        open_file(&wrong),
        Err(ExportError::Corrupt("record counts"))
    ));
    let after = file_of(|s| {
        s.record(&end_record(Counts {
            vaults: 0,
            items: 0,
            attachments: 0,
        })?)?;
        s.record(&vault(1))
    });
    assert!(matches!(
        open_file(&after),
        Err(ExportError::Corrupt("data after end"))
    ));
    let good = file_of(|s| {
        s.record(&vault(1))?;
        s.record(&end_record(Counts {
            vaults: 1,
            items: 0,
            attachments: 0,
        })?)
    });
    let content = open_file(&good).unwrap();
    assert_eq!(content.vaults[0].name, "vault 1");
    assert_eq!(content.vaults[0].kind, VaultKind::Shared);
}

#[test]
fn rejects_unknown_record_types_and_orphan_attachments() {
    let mut w = Writer::new();
    w.map(1).unwrap();
    w.key(0).unwrap();
    w.uint(5).unwrap();
    let unknown = file_of(|s| s.record(&w.into_bytes()));
    assert!(matches!(
        open_file(&unknown),
        Err(ExportError::Format("record type"))
    ));
    let file = AttachedFile {
        id: Id::from_bytes([1; 16]),
        name: "a".into(),
        mime: "text/plain".into(),
        data: SecretSlice::from(vec![1, 2, 3]),
    };
    let orphan = file_of(|s| {
        for piece in attachment_records(Id::from_bytes([2; 16]), &file)? {
            s.record(&piece)?;
        }
        Ok(())
    });
    assert!(matches!(
        open_file(&orphan),
        Err(ExportError::Corrupt("attachment owner"))
    ));
}

#[test]
fn header_limits_and_canonical_form_are_enforced() {
    let good = file_of(|s| {
        s.record(&end_record(Counts {
            vaults: 0,
            items: 0,
            attachments: 0,
        })?)
    });
    let info = peek(&good).unwrap();
    assert_eq!(
        info,
        HeaderInfo {
            created: 7,
            key_mode: KeyMode::Passphrase
        }
    );
    let mut bad_magic = good.clone();
    bad_magic[0] = b'X';
    assert!(matches!(
        peek(&bad_magic),
        Err(ExportError::Format("magic"))
    ));
    let mut version = good.clone();
    version[6] = 2;
    assert!(matches!(peek(&version), Err(ExportError::Version)));
    let huge = Header {
        created: 0,
        mode: MODE_PASSPHRASE,
        params: Argon2idParams::local(MAX_KDF_M_KIB + 8, 1, 1).unwrap(),
        salt: [0; SALT_LEN],
        nonce_prefix: [0; NONCE_PREFIX_LEN],
        chunk_size: chunk_size_u64().unwrap(),
        bk_nonce: None,
        kcv: [0; KCV_LEN],
    };
    let mut bytes = MAGIC.to_vec();
    bytes.extend(encode_header(&huge, Some(&[0; KCV_LEN])).unwrap());
    assert!(matches!(peek(&bytes), Err(ExportError::KdfParams)));
    let mut loose = MAGIC.to_vec();
    loose.extend([0xb8, 0x06]);
    assert!(matches!(peek(&loose), Err(ExportError::Format(_))));
}

#[test]
fn header_kdf_parameters_are_bounded_by_the_suite_ceiling() {
    let header = |m, t, p| Header {
        created: 0,
        mode: MODE_PASSPHRASE,
        params: Argon2idParams::local(m, t, p).unwrap(),
        salt: [0; SALT_LEN],
        nonce_prefix: [0; NONCE_PREFIX_LEN],
        chunk_size: chunk_size_u64().unwrap(),
        bk_nonce: None,
        kcv: [0; KCV_LEN],
    };
    let peeked = |h: &Header| {
        let mut bytes = MAGIC.to_vec();
        bytes.extend(encode_header(h, Some(&[0; KCV_LEN])).unwrap());
        peek(&bytes)
    };
    assert!(peeked(&header(MAX_KDF_M_KIB, MAX_KDF_T, MAX_KDF_P)).is_ok());
    for (m, t, p) in [
        (MAX_KDF_M_KIB + 1, 1, 1),
        (8, MAX_KDF_T + 1, 1),
        (64, 1, MAX_KDF_P + 1),
    ] {
        assert!(matches!(
            peeked(&header(m, t, p)),
            Err(ExportError::KdfParams)
        ));
    }
    let passphrase = passphrase();
    let mut out = Vec::new();
    let protection = Protection::Passphrase {
        passphrase: &passphrase,
        params: Argon2idParams::local(MAX_KDF_M_KIB + 1, 1, 1).unwrap(),
    };
    assert!(matches!(
        write_stream(&mut out, &protection, 0, |_| Ok(())),
        Err(ExportError::KdfParams)
    ));
}

#[test]
fn padding_must_be_exact() {
    assert!(unpad_last(&[]).is_err());
    assert!(unpad_last(&[0; PAD_BLOCK]).is_err());
    let mut block = vec![0; PAD_BLOCK];
    block[10] = 0x81;
    assert!(unpad_last(&block).is_err());
    block[10] = 0x80;
    assert_eq!(unpad_last(&block).unwrap().len(), 10);
    assert!(unpad_last(&block[..100]).is_err());
}
