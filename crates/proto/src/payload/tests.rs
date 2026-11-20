use super::*;

fn secret(text: &str) -> SecretBytes {
    SecretBytes::from_vec(text.as_bytes().to_vec())
}

fn overview() -> Overview {
    Overview {
        kind: "login".into(),
        title: "Example".into(),
        subtitle: "me".into(),
        tags: vec!["a/b".into()],
        favourite: Some(2),
        state: ItemState::Trashed { at: 9 },
        client_modified: 5,
        created: 4,
        expires_at: None,
    }
}

fn details() -> Details {
    Details {
        sections: vec![Section {
            id: [1; 16],
            title: "main".into(),
            fields: vec![
                Field {
                    id: [2; 16],
                    label: "password".into(),
                    value: Value::Concealed(secret("hunter2")),
                    purpose: Some(Purpose::Password),
                    concealed: true,
                    expires_alert: false,
                },
                Field {
                    id: [3; 16],
                    label: "otp".into(),
                    value: Value::Otp(Otp {
                        secret: secret("12345678901234567890"),
                        algorithm: OtpAlgorithm::Sha256,
                        digits: 8,
                        mode: OtpMode::Hotp { counter: 7 },
                        issuer: Some("iss".into()),
                        account: None,
                        steam: false,
                    }),
                    purpose: None,
                    concealed: false,
                    expires_alert: true,
                },
            ],
        }],
        notes: Some("n".repeat(MAX_NOTES)),
        urls: vec![UrlEntry {
            id: [4; 16],
            url: "https://example.com".into(),
            mode: MatchMode::Host,
            confirmed_hosts: vec!["example.com".into()],
            kind: UrlKind::SignIn,
        }],
        apps: vec![AppAssociation {
            platform: AppPlatform::Ios,
            id: "com.example".into(),
            cert_sha256: Some([7; 32]),
            source: AssocSource::Dataset,
        }],
        passkeys: vec![Passkey {
            credential_id: vec![1, 2],
            rp_id: "example.com".into(),
            user_handle: vec![3],
            user_name: "u".into(),
            display_name: "U".into(),
            algorithm: -7,
            private_key: secret("pkcs8"),
            created: 1,
            last_used: Some(2),
            backup_eligible: true,
            backed_up: false,
        }],
        attachments: vec![AttachmentDescriptor {
            att_id: AttId::from_bytes([5; 16]),
            file_key: SecretKey::from_bytes([6; 32]),
            nonce_prefix: [8; NONCE_PREFIX_LEN],
            size: 10,
            chunk_size: 1 << 20,
            name: "a.txt".into(),
            mime: "text/plain".into(),
        }],
        history: vec![PasswordHistoryEntry {
            value: secret("old"),
            replaced_at: 3,
            field: [2; 16],
        }],
    }
}

#[test]
fn overview_and_details_round_trip_canonically() {
    let encoded = encode_overview(&overview()).unwrap();
    assert_eq!(decode_overview(&encoded).unwrap(), overview());
    let encoded = encode_details(&details()).unwrap();
    let decoded = decode_details(&encoded).unwrap();
    assert_eq!(
        encode_details(&decoded).unwrap().as_slice(),
        encoded.as_slice()
    );
    assert_eq!(decoded.passkeys.first().map(|p| p.algorithm), Some(-7));
    assert_eq!(decoded.attachments.len(), 1);
}

#[test]
fn notes_over_the_limit_and_unknown_versions_are_refused() {
    let mut long = details();
    long.notes = Some("n".repeat(MAX_NOTES + 1));
    assert!(matches!(encode_details(&long), Err(ProtoError::Format)));
    let mut bytes = encode_overview(&overview()).unwrap().to_vec();
    let version = bytes.iter().position(|b| *b == 0x01).unwrap();
    bytes[version] = 0x02;
    assert!(matches!(decode_overview(&bytes), Err(ProtoError::Version)));
    let mut trailing = encode_overview(&overview()).unwrap().to_vec();
    trailing.push(0);
    assert!(decode_overview(&trailing).is_err());
}

#[test]
fn zigzag_covers_the_cose_algorithm_range() {
    for value in [0, 1, -1, -7, -257, 1_000_000, i32::MIN, i32::MAX] {
        assert_eq!(unzigzag(zigzag(value).unwrap()).unwrap(), value);
    }
}

#[test]
fn hidden_records_round_trip() {
    let hidden = [
        Hidden::Settings(VaultMeta {
            name: "Family".into(),
            icon: "home".into(),
            description: String::new(),
        }),
        Hidden::Pin(PinRecord {
            account_id: AccountId::from_bytes([1; 16]),
            ik_pk: [2; 32],
            kem_pk_hash: Hash32::from_bytes([3; 32]),
            level: PinLevelWire::Verified,
            first_seen: 5,
        }),
        Hidden::Device(DeviceRecord {
            label: "laptop".into(),
            platform: "macos".into(),
            first_seen: 6,
            status: DeviceStatus::Revoked,
        }),
    ];
    for item in hidden {
        let bytes = encode_hidden(&item).unwrap();
        assert_eq!(decode_hidden(&bytes).unwrap(), item);
    }
}

#[test]
fn debug_output_hides_secrets() {
    let text = format!("{:?}", details());
    assert!(!text.contains("hunter2"));
}
