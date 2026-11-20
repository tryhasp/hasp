use hasp_proto::wire::{
    AccountDelete, AccountGet, ChangeCredentialStart, Commit, ErrorCode, OpId, Pull, RcSet,
    VaultCursor, VaultDissolve,
};
use hasp_proto::{AccountStatus, Dissolve, ItemBody, Role, SigLabel, Signed, Uint53, Wire};
use hasp_server::fixture::Person;
use hasp_testsupport::World;

use super::lab::{PASSWORD, cancel, kit_device, login_item, phone, run, secret, share};
use super::mallory::{Mallory, Verdict};

type Tamper = (&'static str, fn(&mut Commit), ErrorCode);

fn code<T>(result: Result<T, hasp_proto::wire::WireError>) -> ErrorCode {
    result.err().expect("the server refused").code
}

#[test]
fn e13_a_stolen_token_reads_only_ciphertext() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
        let private = alice.private();
        alice
            .client
            .create_item(&private, &login_item("SecretTitleXYZ", "hunter2-plaintext"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let token = mallory.stolen_token();
        let page = mallory
            .as_thief(
                &token,
                &Pull {
                    vaults: vec![VaultCursor {
                        vault_id: private,
                        seq: hasp_proto::Seq::new(0).unwrap(),
                    }],
                    notices_after: Uint53::ZERO,
                    limit: Uint53::ZERO,
                },
            )
            .unwrap();
        let bytes = page.to_cbor().unwrap();
        assert!(page.vaults[0].commits.len() >= 2);
        for needle in [&b"SecretTitleXYZ"[..], b"hunter2-plaintext", b"alice"] {
            assert!(!bytes.windows(needle.len()).any(|w| w == needle));
        }
    });
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    let needle = needle.as_bytes();
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn e13_a_rogue_ca_that_records_every_session_learns_no_secret_and_replays_change_nothing() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let bob_link = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
        let mut bob = phone(&mut world, &bob_link, "bob@example.com", true).await;
        let vault = share(&mut alice, &mut bob, "VaultNameMarker", Role::Editor).await;
        alice.add_login(&vault, "TitleMarker", "PasswordMarker");
        alice.add_login(
            &alice.private(),
            "PrivateTitleMarker",
            "PrivatePasswordMarker",
        );
        alice.client.sync(&cancel()).await.unwrap();
        let recovery = alice
            .client
            .create_recovery_code(&secret(PASSWORD), &cancel())
            .await
            .unwrap();
        bob.client.sync(&cancel()).await.unwrap();
        alice.client.sync(&cancel()).await.unwrap();

        let mut transcript = Vec::new();
        for seen in mallory.seen().into_iter().chain(bob_link.seen()) {
            transcript.extend_from_slice(&seen.request);
            transcript.extend_from_slice(&seen.response.unwrap_or_default());
        }
        let secret_key = alice.kit().secret_key().to_owned();
        let secret_key_plain: String = secret_key.chars().filter(|c| *c != '-').collect();
        for needle in [
            PASSWORD,
            "VaultNameMarker",
            "TitleMarker",
            "PasswordMarker",
            "PrivateTitleMarker",
            "PrivatePasswordMarker",
            &secret_key,
            &secret_key_plain,
            recovery.expose(),
        ] {
            assert!(!contains(&transcript, needle), "{needle} crossed the wire");
        }

        let token = mallory.stolen_token();
        let heads = |vault: hasp_proto::VaultId| {
            mallory
                .as_thief(
                    &token,
                    &Pull {
                        vaults: vec![VaultCursor {
                            vault_id: vault,
                            seq: hasp_proto::Seq::new(0).unwrap(),
                        }],
                        notices_after: Uint53::ZERO,
                        limit: Uint53::ZERO,
                    },
                )
                .unwrap()
                .vaults[0]
                .head_hash
        };
        let before = (heads(vault), heads(alice.private()));
        for seen in mallory.seen_op(OpId::Commit) {
            let _ = mallory.raw(Some(&token), OpId::Commit, &seen.request);
        }
        assert_eq!((heads(vault), heads(alice.private())), before);
        alice.client.sync(&cancel()).await.unwrap();
        bob.client.sync(&cancel()).await.unwrap();
    });
}

#[test]
fn e13_forged_and_altered_writes_with_a_stolen_token_are_refused() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
        let private = alice.private();
        alice.add_login(&private, "Mail", "pw");
        alice.client.sync(&cancel()).await.unwrap();
        let token = mallory.stolen_token();
        let last = mallory
            .seen_op(OpId::Commit)
            .into_iter()
            .rev()
            .find(|seen| seen.error.is_none())
            .unwrap();
        let original = Commit::from_cbor(&last.request).unwrap();
        let head = mallory.head(&private).unwrap();

        let mut next = original.clone();
        next.base_seq = head.manifest.seq;
        assert!(mallory.as_thief(&token, &next).is_err());

        let thief = Person::new("thief");
        let mut foreign = original.clone();
        let mut manifest = foreign.bundle.manifest.unverified().unwrap();
        manifest.author = thief.account_id;
        foreign.bundle.manifest =
            Signed::sign(SigLabel::Manifest, &manifest, &thief.signing).unwrap();
        assert!(mallory.as_thief(&token, &foreign).is_err());

        let tampers: [Tamper; 2] = [
            (
                "signature",
                |c| {
                    let mut sig = *c.bundle.manifest.sig.as_bytes();
                    sig[0] ^= 1;
                    c.bundle.manifest.sig = hasp_crypto::Signature::from_bytes(sig);
                },
                ErrorCode::Sig,
            ),
            (
                "op body",
                |c| c.bundle.ops[0].body = ItemBody::Tombstone,
                ErrorCode::Root,
            ),
        ];
        for (name, tamper, expected) in tampers {
            mallory.on_request(OpId::Commit, move |bytes| {
                super::mallory::edit::<Commit>(bytes, tamper);
                Verdict::Forward
            });
            alice.add_login(&private, name, "pw");
            let error = alice.client.flush(&private, &cancel()).await.unwrap_err();
            let hasp_core::CoreError::Transport(hasp_core::transport::TransportError::Server(wire)) =
                error
            else {
                panic!("{name}: {error:?}");
            };
            assert_eq!(wire.code, expected, "{name}");
            mallory.passthrough();
        }

        let replay = mallory.as_thief(&token, &original);
        assert!(replay.is_ok() || code(replay) != ErrorCode::Internal);
        alice.client.sync(&cancel()).await.unwrap();
    });
}

#[test]
fn e13_a_lax_server_that_stores_a_forged_commit_is_still_refused_by_the_client() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
        let private = alice.private();
        alice.add_login(&private, "Mail", "pw");
        alice.client.sync(&cancel()).await.unwrap();
        mallory.on_response(OpId::Pull, |bytes| {
            super::mallory::edit::<hasp_proto::wire::PullResponse>(bytes, |page| {
                for vault in &mut page.vaults {
                    for commit in &mut vault.commits {
                        let mut sig = *commit.manifest.sig.as_bytes();
                        sig[1] ^= 1;
                        commit.manifest.sig = hasp_crypto::Signature::from_bytes(sig);
                    }
                }
            });
        });
        let laptop = kit_device(&world, &mallory, alice.kit(), "alice@example.com", PASSWORD).await;
        let laptop = laptop.unwrap();
        let info = laptop
            .store
            .cache()
            .quarantine(&alice.private())
            .unwrap()
            .unwrap();
        assert_eq!(info.check, "Sig");
    });
}

#[test]
fn e16_a_revoked_session_can_neither_read_nor_write() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
        let thief_link = Mallory::new(&world.server);
        let mut laptop = kit_device(
            &world,
            &thief_link,
            alice.kit(),
            "alice@example.com",
            PASSWORD,
        )
        .await
        .unwrap();
        let token = thief_link.stolen_token();
        let listed = alice.client.devices(&cancel()).await.unwrap();
        let victim = listed.iter().find(|d| !d.current).unwrap();
        alice
            .client
            .revoke_device(&victim.session_id, &victim.device_id, &cancel())
            .await
            .unwrap();
        let pull = Pull {
            vaults: Vec::new(),
            notices_after: Uint53::ZERO,
            limit: Uint53::ZERO,
        };
        assert_eq!(code(mallory.as_thief(&token, &pull)), ErrorCode::Auth);
        let commit = mallory
            .seen_op(OpId::Commit)
            .pop()
            .map(|seen| Commit::from_cbor(&seen.request).unwrap())
            .unwrap();
        assert_eq!(code(mallory.as_thief(&token, &commit)), ErrorCode::Auth);
        let error = laptop.client.sync(&cancel()).await.unwrap_err();
        assert!(
            matches!(error, hasp_core::CoreError::SessionExpired),
            "{error:?}"
        );
    });
}

#[test]
fn e29_a_session_without_reauth_is_refused_every_reauth_only_action() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
        let private = alice.private();
        let token = mallory.stolen_token();
        let thief = Person::new("thief");
        let mut thief_rc = Person::new("thief");
        let (_, rc_set): (_, RcSet) = thief_rc.recovery_material();
        let record = mallory
            .as_thief(&token, &AccountGet {})
            .unwrap()
            .records
            .pop()
            .unwrap();
        let head = mallory.head(&private).unwrap();
        let dissolve = Dissolve {
            vault_id: private,
            rver: head.manifest.rver,
            epoch: head.manifest.epoch,
            seq: head.manifest.seq,
            head: head.hash,
        };
        let forged_delete = thief.next_record(0, AccountStatus::Deleted);
        let attempts = [
            code(mallory.as_thief(
                &token,
                &ChangeCredentialStart {
                    request: vec![1].into(),
                },
            )),
            code(mallory.as_thief(&token, &rc_set)),
            code(mallory.as_thief(&token, &AccountDelete { account: record })),
            code(mallory.as_thief(
                &token,
                &VaultDissolve {
                    record: Signed::sign(SigLabel::Dissolve, &dissolve, &thief.signing).unwrap(),
                },
            )),
        ];
        assert!(attempts.iter().all(|c| *c == ErrorCode::ReauthRequired));

        alice
            .client
            .create_recovery_code(&secret(PASSWORD), &cancel())
            .await
            .unwrap();
        let inside = mallory.as_thief(
            &token,
            &AccountDelete {
                account: forged_delete.clone(),
            },
        );
        assert_ne!(code(inside), ErrorCode::ReauthRequired);
        world.clock.advance(301);
        assert_eq!(
            code(mallory.as_thief(
                &token,
                &AccountDelete {
                    account: forged_delete
                }
            )),
            ErrorCode::ReauthRequired
        );
    });
}

#[test]
fn e13_sessions_expire_idle_and_the_password_logs_in_again() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
        let private = alice.private();
        let token = mallory.stolen_token();
        world.clock.advance(31 * 24 * 3600);
        let pull = Pull {
            vaults: Vec::new(),
            notices_after: Uint53::ZERO,
            limit: Uint53::ZERO,
        };
        assert_eq!(code(mallory.as_thief(&token, &pull)), ErrorCode::Auth);
        let error = alice.client.sync(&cancel()).await.unwrap_err();
        assert!(
            matches!(error, hasp_core::CoreError::SessionExpired),
            "{error:?}"
        );
        alice.client.lock();
        alice
            .client
            .unlock_password(&secret(PASSWORD), &cancel())
            .await
            .unwrap();
        alice.add_login(&private, "After", "pw");
        alice.client.sync(&cancel()).await.unwrap();
        assert_ne!(mallory.stolen_token(), token);
    });
}

#[test]
#[ignore = "bug: D2-3"]
fn e13_a_replayed_commit_with_a_broken_signature_is_refused_not_acknowledged() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
        let private = alice.private();
        alice.add_login(&private, "Mail", "pw");
        alice.client.sync(&cancel()).await.unwrap();
        let token = mallory.stolen_token();
        let last = mallory
            .seen_op(OpId::Commit)
            .into_iter()
            .rev()
            .find(|seen| seen.error.is_none())
            .unwrap();
        let mut replay = Commit::from_cbor(&last.request).unwrap();
        let mut sig = *replay.bundle.manifest.sig.as_bytes();
        sig[0] ^= 1;
        replay.bundle.manifest.sig = hasp_crypto::Signature::from_bytes(sig);
        assert_eq!(code(mallory.as_thief(&token, &replay)), ErrorCode::Sig);
    });
}
