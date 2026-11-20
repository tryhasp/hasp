use hasp_crypto::{
    KemPublicKey, KemSecretKey, OpaqueClientLogin, OpaqueClientRegistration, OpaqueIdentities,
    SecretBytes, SecretKey, SigningKey, VerifyingKey,
};
use hasp_proto::wire::{
    DeviceInfo, LoginFinish, LoginStart, LoginStartResponse, OpaquePurpose, OpaqueResponse,
    RcAuthKey, RcSet, RegisterFinish, RegisterStart, SessionId, SessionToken, SignupToken,
    credential_id, opaque_context, session_token,
};
use hasp_proto::{
    Aad, AccountId, AccountRecord, AccountStatus, DeviceId, Epoch, Hash32, Keyset, KeysetKeys,
    Member, OwnKeys, RecoveryEnrolment, Role, Rver, Sealed, SealedRaw, Seq, SigLabel, Signed,
    Uint53, Wire,
};

use super::vault_model::VaultModel;
use super::{FLOOR_KDF, ORIGIN, copy, rnd, uint};

#[derive(Debug)]
pub struct Person {
    pub account_id: AccountId,
    pub login: String,
    pub ik_seed: SecretKey,
    pub kem_seed: SecretKey,
    pub signing: SigningKey,
    pub kem: KemSecretKey,
    pub ak: SecretKey,
    pub auk: SecretKey,
    pub k_keyset: SecretKey,
    pub k_self: SecretKey,
    pub opk: SecretKey,
    pub device: DeviceId,
    pub head: Signed<AccountRecord>,
    pub rc_gen: u64,
    pub k_rc: Option<SecretKey>,
}

impl Person {
    pub fn new(login: &str) -> Self {
        let ik_seed = rnd();
        let kem_seed = rnd();
        let signing = SigningKey::from_seed(&ik_seed);
        let kem = KemSecretKey::from_seed(&kem_seed).expect("kem seed");
        let account_id = AccountId::random().expect("os randomness");
        let record = AccountRecord {
            account_id,
            seq: Seq::new(1).expect("seq"),
            prev: None,
            ik_pk: signing.verifying_key(),
            kem_pk: kem.public_key(),
            kdf: FLOOR_KDF,
            status: AccountStatus::Active,
            rc_gen: Uint53::ZERO,
            min_v: uint(1),
            created: uint(1),
        };
        let head = Signed::sign(SigLabel::Account, &record, &signing).expect("sign");
        Self {
            account_id,
            login: login.to_owned(),
            ik_seed,
            kem_seed,
            signing,
            kem,
            ak: rnd(),
            auk: rnd(),
            k_keyset: rnd(),
            k_self: rnd(),
            opk: rnd(),
            device: DeviceId::random().expect("os randomness"),
            head,
            rc_gen: 0,
            k_rc: None,
        }
    }

    pub fn ik_pk(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn kem_pk(&self) -> KemPublicKey {
        self.kem.public_key()
    }

    pub fn own_keys(&self) -> OwnKeys {
        OwnKeys {
            account_id: self.account_id,
            ik_pk: self.ik_pk(),
            kem_pk: self.kem_pk(),
            retired_kem_pk_hashes: Vec::new(),
        }
    }

    pub fn member(&self, role: Role, added_rver: u64) -> Member {
        Member {
            account_id: self.account_id,
            ik_pk: self.ik_pk(),
            kem_pk: self.kem_pk(),
            role,
            added_rver: Rver::new(added_rver).expect("rver"),
        }
    }

    pub fn record(&self) -> AccountRecord {
        self.head.unverified().expect("own record")
    }

    pub fn next_record(&self, rc_gen: u64, status: AccountStatus) -> Signed<AccountRecord> {
        let latest = self.record();
        let record = AccountRecord {
            seq: latest.seq.checked_next().expect("seq"),
            prev: Some(self.head.hash()),
            rc_gen: uint(rc_gen),
            status,
            ..latest
        };
        Signed::sign(SigLabel::Account, &record, &self.signing).expect("sign")
    }

    pub fn device_info(&self, platform: &str) -> DeviceInfo {
        DeviceInfo {
            device_id: self.device,
            platform: platform.to_owned(),
            label: None,
        }
    }

    pub fn keyset(&self) -> Keyset {
        let generation = uint(1);
        Keyset {
            account_id: self.account_id,
            generation,
            ak_wrap: SealedRaw::seal(
                &self.auk,
                self.ak.expose(),
                &Aad::ak_wrap(self.account_id, &FLOOR_KDF, generation),
            )
            .expect("seal"),
            keys: Sealed::seal(
                &self.k_keyset,
                &KeysetKeys {
                    ik_seed: copy(&self.ik_seed),
                    kem_seed: copy(&self.kem_seed),
                    sk_ascii: SecretBytes::from_vec(b"fixture-secret-key".to_vec()),
                    retired: Vec::new(),
                },
                &Aad::keyset_keys(self.account_id, generation),
            )
            .expect("seal"),
        }
    }

    pub fn self_wrap(&self, vault: &VaultModel, epoch: u64) -> SealedRaw {
        let epoch = Epoch::new(epoch).expect("epoch");
        SealedRaw::seal(
            &self.k_self,
            vault.vk_at(epoch).expose(),
            &Aad::self_wrap(self.account_id, vault.id, epoch),
        )
        .expect("seal")
    }

    pub fn register_start(&self, token: &SignupToken) -> (RegisterStart, OpaqueClientRegistration) {
        let (state, request) = OpaqueClientRegistration::start(&self.opk).expect("opaque start");
        (
            RegisterStart {
                token: token.clone(),
                login: self.login.clone(),
                account_id: self.account_id,
                request: request.into(),
            },
            state,
        )
    }

    pub fn register_finish(
        &self,
        token: &SignupToken,
        state: OpaqueClientRegistration,
        response: &OpaqueResponse,
        vault: &mut VaultModel,
    ) -> RegisterFinish {
        let record = state
            .finish(
                response.response.as_slice(),
                &OpaqueIdentities {
                    client: self.account_id.as_bytes(),
                    server: ORIGIN.as_bytes(),
                },
            )
            .expect("opaque finish");
        let genesis = vault.genesis(self);
        RegisterFinish {
            token: token.clone(),
            login: self.login.clone(),
            account_id: self.account_id,
            record: record.into(),
            account: self.head.clone(),
            keyset: self.keyset(),
            vault: genesis,
            self_wrap: self.self_wrap(vault, 0),
        }
    }

    pub fn login_start(&self) -> (LoginStart, OpaqueClientLogin) {
        let (state, ke1) = OpaqueClientLogin::start(&self.opk).expect("opaque start");
        (
            LoginStart {
                account_id: self.account_id,
                ke1: ke1.into(),
            },
            state,
        )
    }

    pub fn login_finish(
        &self,
        origin: &str,
        purpose: OpaquePurpose,
        state: OpaqueClientLogin,
        response: &LoginStartResponse,
    ) -> Result<(hasp_proto::wire::LoginHandle, Vec<u8>, SecretBytesKey), hasp_proto::ProtoError>
    {
        let context = opaque_context(purpose, &self.account_id, &self.record().kdf)?;
        let (ke3, key) = state.finish(
            response.ke2.as_slice(),
            &context,
            &OpaqueIdentities {
                client: self.account_id.as_bytes(),
                server: origin.as_bytes(),
            },
        )?;
        Ok((
            response.handle,
            ke3,
            SecretBytesKey(SecretBytes::from_vec(key.expose().to_vec())),
        ))
    }

    pub fn login_complete(
        &self,
        origin: &str,
        state: OpaqueClientLogin,
        response: &LoginStartResponse,
        platform: &str,
    ) -> Result<(LoginFinish, SecretBytesKey), hasp_proto::ProtoError> {
        let (handle, ke3, key) =
            self.login_finish(origin, OpaquePurpose::Login, state, response)?;
        Ok((
            LoginFinish {
                handle,
                ke3: ke3.into(),
                device: self.device_info(platform),
            },
            key,
        ))
    }

    pub fn recovery_material(&mut self) -> (RcAuthKey, RcSet) {
        let rgen = self.rc_gen.checked_add(1).expect("rgen");
        let k_rc = rnd();
        let k_rc_auth = RcAuthKey::random().expect("os randomness");
        let rc_wrap = SealedRaw::seal(
            &k_rc,
            self.ak.expose(),
            &Aad::recovery_wrap(self.account_id, uint(rgen)),
        )
        .expect("seal");
        let body = RecoveryEnrolment {
            account_id: self.account_id,
            rgen: uint(rgen),
            h_wrap: Hash32::digest(&[&rc_wrap.to_cbor().expect("wrap")]),
        };
        let rc = Signed::sign(SigLabel::Recovery, &body, &self.signing).expect("sign");
        let account = self.next_record(rgen, AccountStatus::Active);
        self.k_rc = Some(k_rc);
        (
            k_rc_auth.clone(),
            RcSet {
                rc,
                rc_wrap,
                h_auth: k_rc_auth.hash(),
                account,
            },
        )
    }

    pub fn adopt_record(&mut self, record: Signed<AccountRecord>) {
        self.rc_gen = record.unverified().expect("record").rc_gen.get();
        self.head = record;
    }
}

#[derive(Debug)]
pub struct SecretBytesKey(SecretBytes);

impl SecretBytesKey {
    pub fn token(&self, sid: &SessionId) -> SessionToken {
        session_token(self.0.expose(), sid).expect("token")
    }
}

pub fn credential(account: &AccountId) -> Vec<u8> {
    credential_id(account).expect("credential id")
}
