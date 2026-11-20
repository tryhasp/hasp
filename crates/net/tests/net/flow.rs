use hasp_core::CoreError;
use hasp_core::client::{FingerprintCheck, NewAttachment};
use hasp_core::testing::{login_item, password_of};
use hasp_proto::Role;
use tokio_util::sync::CancellationToken;

use crate::gateway::Live;

fn cancel() -> CancellationToken {
    CancellationToken::new()
}

fn first_item(
    client: &crate::gateway::HttpClient,
    vault: &hasp_proto::VaultId,
) -> hasp_proto::ItemId {
    client.items(vault).unwrap().remove(0).item_id
}

#[tokio::test]
async fn sign_up_commit_and_pull_run_over_http() {
    let mut live = Live::start().await;
    let (mut alice, secret_key) = live.signup("alice@example.com").await;
    let private = alice.private_vault().unwrap();
    alice
        .create_item(&private, &login_item("Bank", "hunter2"))
        .unwrap();
    alice.sync(&cancel()).await.unwrap();
    assert!(alice.items(&private).unwrap().iter().all(|i| !i.pending));

    let mut phone = live.sign_in("alice@example.com", &secret_key).await;
    phone.sync(&cancel()).await.unwrap();
    let id = first_item(&phone, &private);
    assert_eq!(password_of(&phone.item(&private, &id).unwrap()), "hunter2");

    phone
        .edit_item(&private, &id, &login_item("Bank", "rotated"))
        .unwrap();
    phone.sync(&cancel()).await.unwrap();
    alice.sync(&cancel()).await.unwrap();
    assert_eq!(password_of(&alice.item(&private, &id).unwrap()), "rotated");
    live.stop().await;
}

#[tokio::test]
async fn a_revoked_session_is_reported_as_an_expired_session() {
    let mut live = Live::start().await;
    let (mut alice, secret_key) = live.signup("alice@example.com").await;
    let mut phone = live.sign_in("alice@example.com", &secret_key).await;
    phone.sync(&cancel()).await.unwrap();
    let listed = alice.devices(&cancel()).await.unwrap();
    let victim = listed.iter().find(|device| !device.current).unwrap();
    alice
        .revoke_device(&victim.session_id, &victim.device_id, &cancel())
        .await
        .unwrap();
    let error = phone.sync(&cancel()).await.unwrap_err();
    assert!(
        matches!(error, CoreError::SessionExpired | CoreError::DeviceRevoked),
        "{error:?}"
    );
    live.stop().await;
}

#[tokio::test]
async fn an_attachment_uploads_and_downloads_in_chunks_over_http() {
    let mut live = Live::start().await;
    let (mut alice, secret_key) = live.signup("alice@example.com").await;
    let private = alice.private_vault().unwrap();
    let doc = alice
        .create_item(&private, &login_item("Doc", "x"))
        .unwrap();
    alice.sync(&cancel()).await.unwrap();
    let data = vec![7_u8; 2 * 1024 * 1024 + 123];
    let info = alice
        .attach_file(
            &private,
            &doc,
            &NewAttachment {
                name: "big.bin",
                mime: "application/octet-stream",
                data: &data,
            },
            &cancel(),
        )
        .await
        .unwrap();
    alice.sync(&cancel()).await.unwrap();

    let mut phone = live.sign_in("alice@example.com", &secret_key).await;
    phone.sync(&cancel()).await.unwrap();
    let got = phone
        .download_attachment(&private, &doc, &info.att_id, &cancel())
        .await
        .unwrap();
    assert_eq!(got.len(), data.len());
    assert!(got.iter().all(|byte| *byte == 7));
    live.stop().await;
}

#[tokio::test]
async fn a_shared_vault_is_created_invited_and_joined_over_http() {
    let mut live = Live::start().await;
    let (mut alice, _) = live.signup("alice@example.com").await;
    let (mut bob, _) = live.signup("bob@example.com").await;
    let vault = alice.create_vault("Family", &cancel()).await.unwrap();
    let offer = alice
        .invite_create(&vault, Role::Editor, &cancel())
        .await
        .unwrap();
    let accepted = bob.invite_accept(&offer.code, &cancel()).await.unwrap();
    alice
        .add_member(
            &vault,
            &offer.invite_id,
            &FingerprintCheck::Compared(accepted.my_fingerprint),
            &cancel(),
        )
        .await
        .unwrap();
    bob.sync(&cancel()).await.unwrap();
    alice
        .create_item(&vault, &login_item("Wifi", "pw"))
        .unwrap();
    alice.sync(&cancel()).await.unwrap();
    bob.sync(&cancel()).await.unwrap();
    assert_eq!(bob.items(&vault).unwrap().len(), 1);
    live.stop().await;
}
