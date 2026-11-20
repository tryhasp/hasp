#![expect(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    clippy::too_many_arguments,
    reason = "a test relying party aborts on a malformed attestation"
)]

use hasp_crypto::{sha256, verify_es256};
use hasp_proto::base64url;
use serde_json::Value as Json;

#[derive(Debug, Clone, PartialEq)]
enum Cbor {
    Uint(u64),
    Nint(i64),
    Bytes(Vec<u8>),
    Text(String),
    Map(Vec<(Cbor, Cbor)>),
    Array(Vec<Cbor>),
}

fn argument(input: &mut &[u8], info: u8) -> u64 {
    let width = match info {
        0..=23 => return u64::from(info),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        other => panic!("unsupported additional info {other}"),
    };
    let (head, rest) = input.split_at(width);
    *input = rest;
    head.iter()
        .fold(0, |acc, byte| (acc << 8) | u64::from(*byte))
}

fn parse(input: &mut &[u8]) -> Cbor {
    let (first, rest) = input.split_first().expect("truncated cbor");
    *input = rest;
    let (major, info) = (first >> 5, first & 0x1f);
    let value = argument(input, info);
    match major {
        0 => Cbor::Uint(value),
        1 => Cbor::Nint(-1 - i64::try_from(value).unwrap()),
        2 | 3 => {
            let (head, rest) = input.split_at(usize::try_from(value).unwrap());
            *input = rest;
            if major == 2 {
                Cbor::Bytes(head.to_vec())
            } else {
                Cbor::Text(String::from_utf8(head.to_vec()).unwrap())
            }
        }
        4 => Cbor::Array((0..value).map(|_| parse(input)).collect()),
        5 => Cbor::Map((0..value).map(|_| (parse(input), parse(input))).collect()),
        other => panic!("unsupported major type {other}"),
    }
}

fn parse_all(bytes: &[u8]) -> Cbor {
    let mut rest = bytes;
    let value = parse(&mut rest);
    assert!(rest.is_empty(), "trailing cbor");
    value
}

fn lookup<'a>(map: &'a Cbor, key: &Cbor) -> &'a Cbor {
    let Cbor::Map(entries) = map else {
        panic!("not a map")
    };
    &entries
        .iter()
        .find(|(k, _)| k == key)
        .expect("missing key")
        .1
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Rejected {
    ClientData(&'static str),
    AuthData(&'static str),
    Signature,
}

#[derive(Debug)]
pub(crate) struct Registered {
    pub(crate) credential_id: Vec<u8>,
    pub(crate) public_sec1: Vec<u8>,
    pub(crate) flags: u8,
    pub(crate) counter: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Authenticated {
    pub(crate) flags: u8,
    pub(crate) counter: u32,
}

#[derive(Debug)]
pub(crate) struct RelyingParty {
    pub(crate) rp_id: String,
    pub(crate) origin: String,
}

impl RelyingParty {
    pub(crate) fn new(rp_id: &str, origin: &str) -> Self {
        Self {
            rp_id: rp_id.to_owned(),
            origin: origin.to_owned(),
        }
    }

    fn client_data(&self, raw: &[u8], kind: &str, challenge: &str) -> Result<(), Rejected> {
        let json: Json =
            serde_json::from_slice(raw).map_err(|_| Rejected::ClientData("not json"))?;
        let text = |key: &str| json.get(key).and_then(Json::as_str);
        if text("type") != Some(kind) {
            return Err(Rejected::ClientData("type"));
        }
        if text("challenge") != Some(challenge) {
            return Err(Rejected::ClientData("challenge"));
        }
        if text("origin") != Some(self.origin.as_str()) {
            return Err(Rejected::ClientData("origin"));
        }
        if json.get("crossOrigin").and_then(Json::as_bool) != Some(false) {
            return Err(Rejected::ClientData("crossOrigin"));
        }
        Ok(())
    }

    fn header(&self, auth_data: &[u8]) -> Result<(u8, u32), Rejected> {
        let (hash, rest) = auth_data
            .split_at_checked(32)
            .ok_or(Rejected::AuthData("short"))?;
        if hash != sha256(&[self.rp_id.as_bytes()]) {
            return Err(Rejected::AuthData("rpIdHash"));
        }
        let flags = *rest.first().ok_or(Rejected::AuthData("short"))?;
        if flags & 0x01 == 0 {
            return Err(Rejected::AuthData("user presence"));
        }
        let counter = rest
            .get(1..5)
            .and_then(|raw| <[u8; 4]>::try_from(raw).ok())
            .map(u32::from_be_bytes)
            .ok_or(Rejected::AuthData("short"))?;
        Ok((flags, counter))
    }

    pub(crate) fn register(
        &self,
        challenge: &str,
        client_data_json: &str,
        attestation_object: &str,
    ) -> Result<Registered, Rejected> {
        let client_data = base64url::decode(client_data_json).unwrap();
        self.client_data(&client_data, "webauthn.create", challenge)?;
        let object = parse_all(&base64url::decode(attestation_object).unwrap());
        assert_eq!(
            lookup(&object, &Cbor::Text("fmt".into())),
            &Cbor::Text("none".into())
        );
        assert_eq!(
            lookup(&object, &Cbor::Text("attStmt".into())),
            &Cbor::Map(Vec::new())
        );
        let Cbor::Bytes(auth_data) = lookup(&object, &Cbor::Text("authData".into())) else {
            panic!("authData is not bytes")
        };
        let (flags, counter) = self.header(auth_data)?;
        if flags & 0x40 == 0 {
            return Err(Rejected::AuthData("attested credential data"));
        }
        let attested = auth_data.get(37..).ok_or(Rejected::AuthData("short"))?;
        let (aaguid, rest) = attested.split_at(16);
        assert_eq!(aaguid, [0; 16]);
        let (length, rest) = rest.split_at(2);
        let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
        let (credential_id, cose) = rest.split_at(length);
        let key = parse_all(cose);
        assert_eq!(lookup(&key, &Cbor::Uint(1)), &Cbor::Uint(2));
        assert_eq!(lookup(&key, &Cbor::Uint(3)), &Cbor::Nint(-7));
        assert_eq!(lookup(&key, &Cbor::Nint(-1)), &Cbor::Uint(1));
        let (Cbor::Bytes(x), Cbor::Bytes(y)) =
            (lookup(&key, &Cbor::Nint(-2)), lookup(&key, &Cbor::Nint(-3)))
        else {
            panic!("coordinates are not bytes")
        };
        let mut public_sec1 = vec![4];
        public_sec1.extend_from_slice(x);
        public_sec1.extend_from_slice(y);
        Ok(Registered {
            credential_id: credential_id.to_vec(),
            public_sec1,
            flags,
            counter,
        })
    }

    pub(crate) fn authenticate(
        &self,
        public_sec1: &[u8],
        stored_counter: u32,
        challenge: &str,
        client_data_json: &str,
        authenticator_data: &str,
        signature: &str,
    ) -> Result<Authenticated, Rejected> {
        let client_data = base64url::decode(client_data_json).unwrap();
        self.client_data(&client_data, "webauthn.get", challenge)?;
        let auth_data = base64url::decode(authenticator_data).unwrap();
        let (flags, counter) = self.header(&auth_data)?;
        if flags & 0x40 != 0 {
            return Err(Rejected::AuthData("unexpected attested data"));
        }
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&sha256(&[&client_data]));
        verify_es256(public_sec1, &signed, &base64url::decode(signature).unwrap())
            .map_err(|_| Rejected::Signature)?;
        if (counter != 0 || stored_counter != 0) && counter <= stored_counter {
            return Err(Rejected::AuthData("counter did not advance"));
        }
        Ok(Authenticated { flags, counter })
    }
}
