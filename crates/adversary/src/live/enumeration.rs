use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use hasp_core::client::{Client, ClientConfig, SignUp};
use hasp_core::platform::{ManualClock, Platform};
use hasp_crypto::{OpaqueClientLogin, SecretKey};
use hasp_proto::wire::{
    DeviceInfo, ErrorCode, LoginFinish, LoginStart, LoginStartResponse, OpId, Prelogin,
    PreloginResponse, RecoverPrelogin, RecoverPreloginResponse, WireError, encode_reply,
};
use hasp_proto::{AccountId, DeviceId, KdfWire, Wire};
use hasp_testsupport::World;

use super::lab::{ORIGIN, PASSWORD, SharedStore, cancel, phone, run, secret};
use super::mallory::Mallory;

const FLOOR: KdfWire = KdfWire {
    m: 65_536,
    t: 3,
    p: 4,
};

struct Population {
    mallory: Mallory,
    known: BTreeSet<String>,
}

async fn population() -> Population {
    let mut world = World::new();
    let mallory = Mallory::new(&world.server);
    let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
    alice
        .client
        .change_password(
            &secret(PASSWORD),
            &secret("a second long password"),
            false,
            &cancel(),
        )
        .await
        .unwrap();
    let mut config = ClientConfig::new("macos");
    config.account_kdf = KdfWire {
        m: 65_536,
        t: 4,
        p: 4,
    };
    let clock = std::sync::Arc::new(ManualClock::new(1_000_000));
    let mut bob = Client::new(
        mallory.clone(),
        SharedStore::default(),
        Platform::for_tests(clock),
        config,
    );
    let token = world.token().await;
    bob.sign_up(
        &SignUp {
            origin: ORIGIN,
            token: &token,
            login: "bob@example.com",
            password: &secret(PASSWORD),
        },
        &cancel(),
    )
    .await
    .unwrap();
    let mut carol = phone(&mut world, &mallory, "carol@example.com", true).await;
    carol
        .client
        .create_recovery_code(&secret(PASSWORD), &cancel())
        .await
        .unwrap();
    Population {
        mallory,
        known: [
            "alice@example.com",
            "bob@example.com",
            "carol@example.com",
            "admin",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    }
}

fn prelogin(mallory: &Mallory, login: &str) -> (PreloginResponse, usize) {
    let body = Prelogin {
        login: login.to_owned(),
    }
    .to_cbor()
    .unwrap();
    let reply = mallory.raw(None, OpId::Prelogin, &body);
    let decoded = hasp_proto::wire::decode_reply::<PreloginResponse>(&reply)
        .unwrap()
        .unwrap();
    (decoded, reply.len())
}

fn ghosts() -> Vec<String> {
    (0..60).map(|i| format!("ghost{i}@example.com")).collect()
}

fn suspicious(response: &PreloginResponse) -> bool {
    response.kdf != FLOOR || response.cred_gen.get() > 1
}

fn naive_prelogin(
    known: &BTreeSet<String>,
    login: &str,
    honest: &PreloginResponse,
) -> PreloginResponse {
    if known.contains(login) {
        honest.clone()
    } else {
        PreloginResponse {
            account_id: AccountId::from_bytes([0; 16]),
            kdf: FLOOR,
            cred_gen: hasp_proto::Uint53::new(1).unwrap(),
            v: honest.v,
        }
    }
}

#[test]
fn e14_unknown_logins_get_records_from_the_real_distribution_with_one_shape() {
    run(async {
        let p = Box::pin(population()).await;
        let mut real = BTreeSet::new();
        let mut lengths = BTreeSet::new();
        for login in &p.known {
            let (response, len) = prelogin(&p.mallory, login);
            real.insert((
                response.kdf.m,
                response.kdf.t,
                response.kdf.p,
                response.cred_gen.get(),
            ));
            lengths.insert(len);
        }
        assert!(real.iter().any(|r| r.1 == 4) && real.iter().any(|r| r.3 > 1));
        let mut false_positives = 0;
        let mut ids = BTreeSet::new();
        for login in ghosts() {
            let (first, len) = prelogin(&p.mallory, &login);
            let (second, _) = prelogin(&p.mallory, &login);
            assert_eq!(first, second);
            lengths.insert(len);
            assert_eq!(first.kdf, FLOOR);
            assert!((1..=3).contains(&first.cred_gen.get()));
            ids.insert(*first.account_id.as_bytes());
            false_positives += usize::from(suspicious(&first));
        }
        assert_eq!(lengths.len(), 1);
        assert_eq!(ids.len(), 60);
        assert!(false_positives > 0);
    });
}

#[test]
fn e14_a_naive_server_that_floors_unknown_logins_is_a_perfect_oracle() {
    run(async {
        let p = Box::pin(population()).await;
        let mut false_positives = 0;
        let mut detected = 0;
        for login in p.known.iter().cloned().chain(ghosts()) {
            let (honest, _) = prelogin(&p.mallory, &login);
            let shown = naive_prelogin(&p.known, &login, &honest);
            let flagged = suspicious(&shown);
            if p.known.contains(&login) {
                detected += usize::from(flagged);
            } else {
                false_positives += usize::from(flagged);
            }
        }
        assert_eq!(false_positives, 0);
        assert!(detected >= 2);
    });
}

#[test]
fn e14_recovery_prelogin_follows_the_same_rule() {
    run(async {
        let p = Box::pin(population()).await;
        let mut lengths = BTreeSet::new();
        let mut rgens = BTreeSet::new();
        for login in p.known.iter().cloned().chain(ghosts()) {
            let body = RecoverPrelogin {
                login: login.clone(),
            }
            .to_cbor()
            .unwrap();
            let reply = p.mallory.raw(None, OpId::RecoverPrelogin, &body);
            lengths.insert(reply.len());
            let decoded = hasp_proto::wire::decode_reply::<RecoverPreloginResponse>(&reply)
                .unwrap()
                .unwrap();
            if !p.known.contains(&login) {
                rgens.insert(decoded.rgen.get());
            }
        }
        assert_eq!(lengths.len(), 1);
        assert!(rgens.is_subset(&BTreeSet::from([0, 1])));
    });
}

fn start(mallory: &Mallory, account: AccountId) -> (Vec<u8>, LoginStartResponse) {
    let (_, ke1) = OpaqueClientLogin::start(&SecretKey::from_bytes([5; 32])).unwrap();
    let body = LoginStart {
        account_id: account,
        ke1: ke1.into(),
    }
    .to_cbor()
    .unwrap();
    let reply = mallory.raw(None, OpId::LoginStart, &body);
    let decoded = hasp_proto::wire::decode_reply::<LoginStartResponse>(&reply)
        .unwrap()
        .unwrap();
    (reply, decoded)
}

fn finish(mallory: &Mallory, response: &LoginStartResponse) -> Vec<u8> {
    let body = LoginFinish {
        handle: response.handle,
        ke3: vec![9; 64].into(),
        device: DeviceInfo {
            device_id: DeviceId::from_bytes([1; 16]),
            platform: "linux".to_owned(),
            label: None,
        },
    }
    .to_cbor()
    .unwrap();
    mallory.raw(None, OpId::LoginFinish, &body)
}

#[test]
fn e14_login_for_known_and_unknown_accounts_has_one_shape() {
    run(async {
        let p = Box::pin(population()).await;
        let known_id = prelogin(&p.mallory, "alice@example.com").0.account_id;
        let unknown_id = AccountId::from_bytes([0x77; 16]);
        let (known_reply, known_start) = start(&p.mallory, known_id);
        let (unknown_reply, unknown_start) = start(&p.mallory, unknown_id);
        assert_eq!(known_reply.len(), unknown_reply.len());
        assert_eq!(known_start.ke2.0.len(), unknown_start.ke2.0.len());
        assert_eq!(
            finish(&p.mallory, &known_start),
            finish(&p.mallory, &unknown_start)
        );
    });
}

fn sample(mallory: &Mallory, account: AccountId) -> Duration {
    let (_, ke1) = OpaqueClientLogin::start(&SecretKey::from_bytes([5; 32])).unwrap();
    let body = LoginStart {
        account_id: account,
        ke1: ke1.into(),
    }
    .to_cbor()
    .unwrap();
    let began = Instant::now();
    std::hint::black_box(mallory.raw(None, OpId::LoginStart, &body));
    began.elapsed()
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    values.get(values.len() / 2).copied().unwrap_or(f64::NAN)
}

fn real(count: usize) -> f64 {
    f64::from(u32::try_from(count).unwrap())
}

struct Separation {
    class: &'static str,
    ratio: f64,
    sign_z: f64,
}

fn paired(known: &[Duration], ghost: &[Duration], class: &'static str) -> Separation {
    let mut ratios: Vec<f64> = known
        .iter()
        .zip(ghost)
        .map(|(k, g)| k.as_secs_f64() / g.as_secs_f64())
        .collect();
    let slower = real(ratios.iter().filter(|ratio| **ratio > 1.0).count());
    let pairs = real(ratios.len());
    Separation {
        class,
        ratio: median(&mut ratios),
        sign_z: (slower - pairs / 2.0) / (pairs.sqrt() / 2.0),
    }
}

fn measure(p: &Population, rounds: usize) -> (Vec<Separation>, Duration) {
    let class = |login: &str| prelogin(&p.mallory, login).0.account_id;
    let known = [
        (
            "floor with a changed credential",
            class("alice@example.com"),
        ),
        ("non-floor kdf", class("bob@example.com")),
        ("recovery code set", class("carol@example.com")),
    ];
    let mut accounts: Vec<AccountId> = known.iter().map(|(_, id)| *id).collect();
    accounts.push(AccountId::from_bytes([0x77; 16]));
    for account in accounts.iter().cycle().take(accounts.len() * 10) {
        sample(&p.mallory, *account);
    }
    let mut timings: Vec<Vec<Duration>> = vec![Vec::new(); accounts.len()];
    for round in 0..rounds {
        for step in 0..accounts.len() {
            let slot = (step + round) % accounts.len();
            timings[slot].push(sample(&p.mallory, accounts[slot]));
        }
    }
    let ghost = timings.pop().unwrap_or_default();
    let ghost_floor = ghost.iter().min().copied().unwrap_or_default();
    let separations = known
        .iter()
        .zip(&timings)
        .map(|((class, _), samples)| paired(samples, &ghost, class))
        .collect();
    (separations, ghost_floor)
}

#[test]
fn e14_login_start_cost_stays_within_a_factor_of_two_across_account_classes() {
    run(async {
        let p = Box::pin(population()).await;
        let (separations, ghost_floor) = measure(&p, 100);
        for Separation { class, ratio, .. } in separations {
            assert!((0.5..2.0).contains(&ratio), "{class}: paired ratio {ratio}");
        }
        let began = Instant::now();
        for _ in 0..40 {
            std::hint::black_box(
                encode_reply::<LoginStartResponse>(&Err(WireError::new(ErrorCode::Auth))).unwrap(),
            );
        }
        let naive = began.elapsed() / 40;
        assert!(
            naive * 3 < ghost_floor,
            "naive {naive:?} real {ghost_floor:?}"
        );
    });
}

#[test]
fn e14_login_start_cost_is_statistically_indistinguishable_for_known_and_unknown_accounts() {
    run(async {
        let p = Box::pin(population()).await;
        let (separations, _) = measure(&p, 200);
        for Separation {
            class,
            ratio,
            sign_z,
        } in separations
        {
            assert!(
                (0.9..1.1).contains(&ratio),
                "{class}: median paired ratio {ratio}"
            );
            assert!(sign_z.abs() < 4.0, "{class}: sign-test z {sign_z}");
        }
    });
}
