use std::future::Future;
use std::sync::{Arc, Mutex};

use hasp_core::CoreError;
use hasp_core::client::{Channel, ChannelError, Client, ClientConfig, ClientState};
use hasp_core::platform::{ManualClock, Platform, ScriptedBiometric};
use hasp_proto::wire::OpId;
use hasp_testsupport::{World, block_on};

use super::lab::{PASSWORD, Phone, SharedStore, cancel, phone, run, secret};
use super::mallory::Mallory;

struct Pipe {
    tx: Mutex<std::sync::mpsc::Sender<Vec<u8>>>,
    rx: Mutex<std::sync::mpsc::Receiver<Vec<u8>>>,
}

impl Channel for Pipe {
    fn send(&self, message: Vec<u8>) -> impl Future<Output = Result<(), ChannelError>> + Send {
        std::future::ready(
            self.tx
                .lock()
                .unwrap()
                .send(message)
                .map_err(|_| ChannelError::Closed),
        )
    }

    fn recv(&self) -> impl Future<Output = Result<Vec<u8>, ChannelError>> + Send {
        std::future::ready(
            self.rx
                .lock()
                .unwrap()
                .recv()
                .map_err(|_| ChannelError::Closed),
        )
    }
}

struct Spoofed;

impl Channel for Spoofed {
    fn send(&self, _: Vec<u8>) -> impl Future<Output = Result<(), ChannelError>> + Send {
        std::future::ready(Err(ChannelError::Peer))
    }

    fn recv(&self) -> impl Future<Output = Result<Vec<u8>, ChannelError>> + Send {
        std::future::ready(Err(ChannelError::Peer))
    }
}

fn pipes() -> (Pipe, Pipe) {
    let (to_ext, from_desktop) = std::sync::mpsc::channel();
    let (to_desktop, from_ext) = std::sync::mpsc::channel();
    (
        Pipe {
            tx: Mutex::new(to_ext),
            rx: Mutex::new(from_ext),
        },
        Pipe {
            tx: Mutex::new(to_desktop),
            rx: Mutex::new(from_desktop),
        },
    )
}

struct Paired {
    desktop: Phone,
    extension: Client<Mallory, SharedStore>,
    k_ext: hasp_crypto::SecretKey,
    mallory: Mallory,
}

fn pair(world: &mut World) -> Paired {
    let mallory = Mallory::new(&world.server);
    let mut desk = block_on(Box::pin(phone(world, &mallory, "alice@example.com", true)));
    let (mut extension, _) = world.client_on(mallory.clone(), SharedStore::default(), false);
    let (desktop_side, ext_side) = pipes();
    let k_ext = std::thread::scope(|scope| {
        let served = scope.spawn(|| {
            block_on(Box::pin(
                desk.client
                    .serve_extension_pairing(&desktop_side, &cancel()),
            ))
            .unwrap();
        });
        let paired = scope
            .spawn(|| {
                block_on(Box::pin(extension.pair_with_desktop(
                    &ext_side,
                    "chrome",
                    &cancel(),
                )))
                .unwrap()
            })
            .join()
            .unwrap();
        served.join().unwrap();
        paired
    });
    Paired {
        desktop: desk,
        extension,
        k_ext,
        mallory,
    }
}

#[test]
fn e33_a_channel_that_fails_peer_verification_mints_no_session_and_releases_nothing() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let mut desk = phone(&mut world, &mallory, "alice@example.com", true).await;
        let served = desk
            .client
            .serve_extension_pairing(&Spoofed, &cancel())
            .await;
        assert!(matches!(served, Err(CoreError::Refused(_))), "{served:?}");
        assert!(mallory.seen_op(OpId::EnrolApprove).is_empty());
        let (mut extension, _) = world.client_on(mallory.clone(), SharedStore::default(), false);
        let paired = extension
            .pair_with_desktop(&Spoofed, "chrome", &cancel())
            .await;
        assert!(paired.is_err());
        assert_eq!(desk.client.devices(&cancel()).await.unwrap().len(), 1);
    });
}

#[test]
fn e33_pairing_needs_user_presence_on_the_desktop() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let clock = Arc::new(ManualClock::new(1_000_000));
        let bio = Arc::new(ScriptedBiometric::new(true, true));
        let mut platform = Platform::for_tests(Arc::clone(&clock));
        platform.biometric = bio.clone();
        let mut desk = Client::new(
            mallory.clone(),
            SharedStore::default(),
            platform,
            ClientConfig::new("macos"),
        );
        let token = world.token().await;
        desk.sign_up(
            &hasp_core::client::SignUp {
                origin: super::lab::ORIGIN,
                token: &token,
                login: "alice@example.com",
                password: &secret(PASSWORD),
            },
            &cancel(),
        )
        .await
        .unwrap();
        bio.set_approve(false);
        let (desktop_side, ext_side) = pipes();
        let (_extension, _) = world.client_on(mallory.clone(), SharedStore::default(), false);
        ext_side
            .tx
            .lock()
            .unwrap()
            .send({
                let mut w = hasp_proto::Writer::new();
                w.map(4).unwrap();
                w.key(0).unwrap();
                w.text("enrol_request").unwrap();
                w.key(1).unwrap();
                hasp_proto::Wire::encode(&hasp_proto::DeviceId::from_bytes([5; 16]), &mut w)
                    .unwrap();
                w.key(2).unwrap();
                w.text("extension").unwrap();
                w.key(3).unwrap();
                w.text("chrome").unwrap();
                w.into_bytes()
            })
            .unwrap();
        let served = desk.serve_extension_pairing(&desktop_side, &cancel()).await;
        assert!(served.is_err(), "{served:?}");
        assert!(mallory.seen_op(OpId::EnrolApprove).is_empty());
    });
}

#[test]
fn e33_only_the_released_k_ext_unlocks_and_a_revoked_extension_reaches_no_ciphertext() {
    let mut world = World::new();
    let mut p = pair(&mut world);
    run(async {
        p.extension.lock();
        let wrong = hasp_crypto::SecretKey::from_bytes([1; 32]);
        assert!(
            p.extension
                .unlock_extension(&wrong, &cancel())
                .await
                .is_err()
        );
        assert!(!p.extension.is_unlocked());
        assert!(
            p.extension
                .unlock_password(&secret(PASSWORD), &cancel())
                .await
                .is_err()
        );
        p.extension
            .unlock_extension(&p.k_ext, &cancel())
            .await
            .unwrap();
        p.extension.lock();

        let listed = p.desktop.client.devices(&cancel()).await.unwrap();
        let victim = listed.iter().find(|d| !d.current).unwrap();
        p.desktop
            .client
            .revoke_device(&victim.session_id, &victim.device_id, &cancel())
            .await
            .unwrap();
        let mark = p.mallory.mark();
        let error = p
            .extension
            .unlock_extension(&p.k_ext, &cancel())
            .await
            .unwrap_err();
        assert!(matches!(error, CoreError::DeviceRevoked), "{error:?}");
        assert!(!p.extension.is_unlocked());
        assert_eq!(p.extension.state().unwrap(), ClientState::Empty);
        let refused = p.mallory.seen_op(OpId::SessionList);
        assert!(
            refused
                .last()
                .is_some_and(|s| s.error == Some(hasp_proto::wire::ErrorCode::Auth))
        );
        assert!(p.mallory.seen().len() > mark);
    });
}
