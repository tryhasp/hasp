use hasp_crypto::{SecretKey, X25519Secret, hkdf_extract, hmac_sha256};
use hasp_proto::{AccountId, CtxValue, Esid, Hash32, Kdf, Reader, Writer, derive};

pub(crate) struct Qr {
    pub(crate) origin: String,
    pub(crate) account: AccountId,
    pub(crate) esid: Esid,
    pub(crate) e: SecretKey,
}

pub(crate) fn parse_qr(qr: &[u8]) -> Qr {
    let mut r = Reader::new(qr);
    r.map(|r, _| {
        r.key(0)?;
        r.uint()?;
        r.key(1)?;
        let origin = r.text()?.to_owned();
        r.key(2)?;
        let account: AccountId = r.value()?;
        r.key(3)?;
        let esid: Esid = r.value()?;
        r.key(4)?;
        let e = SecretKey::from_bytes(r.fixed()?);
        r.key(5)?;
        r.fixed::<15>()?;
        r.key(6)?;
        r.fixed::<15>()?;
        Ok(Qr {
            origin,
            account,
            esid,
            e,
        })
    })
    .unwrap()
}

pub(crate) fn mac(e: &SecretKey, parts: &[&[u8]]) -> [u8; 32] {
    let key = hkdf_extract(Kdf::EnrolMac.name().as_bytes(), e.expose()).into_secret();
    let message: Vec<u8> = parts.iter().flat_map(|part| part.iter().copied()).collect();
    hmac_sha256(&key, &message)
}

pub(crate) fn commit_of(b_pub: &[u8; 32], esid: &Esid) -> Hash32 {
    let mut w = Writer::new();
    w.array(3).unwrap();
    w.text(Kdf::EnrolCommit.name()).unwrap();
    w.bytes(b_pub).unwrap();
    w.bytes(esid.as_bytes()).unwrap();
    Hash32::digest(&[&w.into_bytes()])
}

pub(crate) fn transcript(qr: &Qr, c_b: &Hash32, a: &[u8; 32], b: &[u8; 32]) -> Hash32 {
    let mut w = Writer::new();
    w.array(6).unwrap();
    w.text(&qr.origin).unwrap();
    w.bytes(qr.account.as_bytes()).unwrap();
    w.bytes(qr.esid.as_bytes()).unwrap();
    w.bytes(c_b.as_bytes()).unwrap();
    w.bytes(a).unwrap();
    w.bytes(b).unwrap();
    Hash32::digest(&[&w.into_bytes()])
}

pub(crate) fn code_of(e: &SecretKey, shared: &SecretKey, transcript: &Hash32) -> String {
    let kc = hkdf_extract(e.expose(), shared.expose()).into_secret();
    let ctx = [CtxValue::Bytes(transcript.as_bytes().to_vec())];
    let code_key = derive(&kc, Kdf::EnrolCode, &ctx).unwrap();
    let head: [u8; 4] = code_key.expose()[..4].try_into().unwrap();
    format!("{:06}", u32::from_be_bytes(head) % 1_000_000)
}

pub(crate) fn pair(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.array(2).unwrap();
    w.bytes(first).unwrap();
    w.bytes(second).unwrap();
    w.into_bytes()
}

pub(crate) fn unpair(bytes: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let mut r = Reader::new(bytes);
    r.array(|r, _| Ok((r.bytes()?.to_vec(), r.fixed::<32>()?)))
        .unwrap()
}

pub(crate) fn request_body(c_b: &Hash32, platform: &str, device: &hasp_proto::DeviceId) -> Vec<u8> {
    use hasp_proto::Wire;
    let mut w = Writer::new();
    w.map(3).unwrap();
    w.key(0).unwrap();
    c_b.encode(&mut w).unwrap();
    w.key(1).unwrap();
    w.text(platform).unwrap();
    w.key(2).unwrap();
    device.encode(&mut w).unwrap();
    w.into_bytes()
}

pub(crate) fn read_request(body: &[u8]) -> (Hash32, String, hasp_proto::DeviceId) {
    let mut r = Reader::new(body);
    r.map(|r, _| {
        r.key(0)?;
        let c_b: Hash32 = r.value()?;
        r.key(1)?;
        let platform = r.text()?.to_owned();
        r.key(2)?;
        let device = r.value()?;
        Ok((c_b, platform, device))
    })
    .unwrap()
}

pub(crate) fn fresh() -> (X25519Secret, [u8; 32]) {
    let secret = X25519Secret::generate().unwrap();
    let public = secret.public_key();
    (secret, public)
}
