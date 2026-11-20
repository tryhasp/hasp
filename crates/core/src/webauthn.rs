use hasp_crypto::{ES256_SEC1_LEN, sha256};
use hasp_proto::base64url;

use crate::CoreError;
use crate::matcher::origin::Origin;
use crate::matcher::psl::PublicSuffixList;

pub const ES256: i32 = -7;
pub const SIGN_COUNT: u32 = 0;

pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;
pub const FLAG_BE: u8 = 0x08;
pub const FLAG_BS: u8 = 0x10;
pub const FLAG_AT: u8 = 0x40;

const MAX_RP_ID: usize = 253;
const MAX_LABEL: usize = 63;
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const COSE_PREFIX: [u8; 10] = [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ceremony {
    Create,
    Get,
}

impl Ceremony {
    fn type_name(self) -> &'static str {
        match self {
            Self::Create => "webauthn.create",
            Self::Get => "webauthn.get",
        }
    }
}

/// The RP ID a page may use (WebAuthn L3 5.1.3 step 7 and 5.1.4.1 step 8): the origin must be
/// secure, and a requested RP ID must equal the origin's host or be a registrable domain suffix
/// of it, so never a public suffix and never an IP address.
pub fn resolve_rp_id(
    psl: &PublicSuffixList,
    origin: &Origin,
    requested: Option<&str>,
) -> Result<String, CoreError> {
    origin
        .check_fillable()
        .map_err(|_| CoreError::Refused("the page origin is not secure"))?;
    let host = origin.domain().ok_or(CoreError::Refused(
        "an IP address cannot be a relying party",
    ))?;
    let Some(requested) = requested.filter(|text| !text.is_empty()) else {
        return Ok(host.to_owned());
    };
    let rp_id = requested.to_ascii_lowercase();
    if !well_formed(&rp_id) {
        return Err(CoreError::Refused("malformed relying party id"));
    }
    if rp_id == host {
        return Ok(rp_id);
    }
    let is_suffix = host
        .strip_suffix(rp_id.as_str())
        .is_some_and(|rest| rest.ends_with('.'));
    let is_public_suffix = psl.public_suffix(&rp_id) == Some(rp_id.as_str());
    if is_suffix && !is_public_suffix {
        Ok(rp_id)
    } else {
        Err(CoreError::Refused(
            "the relying party id is not a registrable suffix of the page origin",
        ))
    }
}

/// The RP ID the operating system hands to a credential provider. The system already checked
/// the app or site against the relying party's association file, so only the shape is checked
/// here: a lowercase host name that is neither an IP address nor a public suffix.
pub fn check_relying_party(psl: &PublicSuffixList, rp_id: &str) -> Result<String, CoreError> {
    let rp_id = rp_id.to_ascii_lowercase();
    if !well_formed(&rp_id) || rp_id.parse::<std::net::IpAddr>().is_ok() {
        return Err(CoreError::Refused("malformed relying party id"));
    }
    if psl.public_suffix(&rp_id) == Some(rp_id.as_str()) {
        return Err(CoreError::Refused(
            "a public suffix cannot be a relying party",
        ));
    }
    Ok(rp_id)
}

fn well_formed(rp_id: &str) -> bool {
    !rp_id.is_empty()
        && rp_id.len() <= MAX_RP_ID
        && rp_id.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

pub fn origin_text(origin: &Origin) -> String {
    let scheme = match origin.scheme() {
        crate::matcher::origin::Scheme::Http => "http",
        crate::matcher::origin::Scheme::Https => "https",
    };
    match origin.explicit_port() {
        Some(port) => format!("{scheme}://{}:{port}", origin.host_string()),
        None => format!("{scheme}://{}", origin.host_string()),
    }
}

pub fn client_data_json(
    ceremony: Ceremony,
    challenge: &str,
    origin: &str,
) -> Result<String, CoreError> {
    let quoted = |text: &str| {
        serde_json::to_string(text).map_err(|_| CoreError::Internal("client data encoding"))
    };
    Ok(format!(
        "{{\"type\":\"{}\",\"challenge\":{},\"origin\":{},\"crossOrigin\":false}}",
        ceremony.type_name(),
        quoted(challenge)?,
        quoted(origin)?,
    ))
}

#[derive(Debug)]
pub struct AttestedCredential<'a> {
    pub credential_id: &'a [u8],
    pub public_sec1: &'a [u8; ES256_SEC1_LEN],
}

pub fn authenticator_data(
    rp_id: &str,
    flags: u8,
    attested: Option<&AttestedCredential<'_>>,
) -> Result<Vec<u8>, CoreError> {
    let mut out = Vec::new();
    out.extend_from_slice(&sha256(&[rp_id.as_bytes()]));
    out.push(if attested.is_some() {
        flags | FLAG_AT
    } else {
        flags
    });
    out.extend_from_slice(&SIGN_COUNT.to_be_bytes());
    if let Some(credential) = attested {
        let length = u16::try_from(credential.credential_id.len())
            .map_err(|_| CoreError::Refused("credential id too long"))?;
        out.extend_from_slice(&[0; 16]);
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(credential.credential_id);
        out.extend_from_slice(&cose_key(credential.public_sec1)?);
    }
    Ok(out)
}

fn cose_key(sec1: &[u8; ES256_SEC1_LEN]) -> Result<Vec<u8>, CoreError> {
    let (x, y) = sec1
        .get(1..33)
        .zip(sec1.get(33..))
        .ok_or(CoreError::Internal("public key"))?;
    let mut out = COSE_PREFIX.to_vec();
    out.extend_from_slice(x);
    out.extend_from_slice(&[0x22, 0x58, 0x20]);
    out.extend_from_slice(y);
    Ok(out)
}

pub fn spki(sec1: &[u8; ES256_SEC1_LEN]) -> Vec<u8> {
    let mut out = SPKI_PREFIX.to_vec();
    out.extend_from_slice(sec1);
    out
}

pub fn attestation_object_none(auth_data: &[u8]) -> Result<Vec<u8>, CoreError> {
    let mut out = vec![0xa3, 0x63];
    out.extend_from_slice(b"fmt");
    out.push(0x64);
    out.extend_from_slice(b"none");
    out.push(0x67);
    out.extend_from_slice(b"attStmt");
    out.push(0xa0);
    out.push(0x68);
    out.extend_from_slice(b"authData");
    let length = u16::try_from(auth_data.len()).map_err(|_| CoreError::Internal("auth data"))?;
    out.push(0x59);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(auth_data);
    Ok(out)
}

pub fn signed_payload(auth_data: &[u8], client_data_json: &str) -> Vec<u8> {
    let mut out = auth_data.to_vec();
    out.extend_from_slice(&sha256(&[client_data_json.as_bytes()]));
    out
}

pub fn signed_payload_with_hash(auth_data: &[u8], client_data_hash: &[u8]) -> Vec<u8> {
    let mut out = auth_data.to_vec();
    out.extend_from_slice(client_data_hash);
    out
}

pub fn decode_b64(text: &str, min: usize, max: usize) -> Result<Vec<u8>, CoreError> {
    base64url::decode(text)
        .filter(|bytes| (min..=max).contains(&bytes.len()))
        .ok_or(CoreError::Refused("malformed base64url value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp(origin: &str, requested: Option<&str>) -> Result<String, CoreError> {
        let origin = Origin::parse(origin)?;
        resolve_rp_id(&PublicSuffixList::bundled(), &origin, requested)
    }

    #[test]
    fn defaults_to_the_origin_host() {
        assert_eq!(
            rp("https://accounts.example.com", None).unwrap(),
            "accounts.example.com"
        );
        assert_eq!(
            rp("https://example.com:8443", Some("")).unwrap(),
            "example.com"
        );
    }

    #[test]
    fn accepts_a_registrable_suffix_of_the_host() {
        assert_eq!(
            rp("https://login.example.com", Some("example.com")).unwrap(),
            "example.com"
        );
        assert_eq!(
            rp("https://login.example.co.uk", Some("Example.co.uk")).unwrap(),
            "example.co.uk"
        );
    }

    #[test]
    fn refuses_public_suffixes_other_domains_and_look_alikes() {
        assert!(rp("https://example.co.uk", Some("co.uk")).is_err());
        assert!(rp("https://example.com", Some("com")).is_err());
        assert!(rp("https://alice.github.io", Some("github.io")).is_err());
        assert!(rp("https://example.com", Some("evil.com")).is_err());
        assert!(rp("https://badexample.com", Some("example.com")).is_err());
        assert!(rp("https://example.com", Some("sub.example.com")).is_err());
    }

    #[test]
    fn refuses_malformed_ids_insecure_origins_and_ip_hosts() {
        assert!(rp("https://example.com", Some("https://example.com")).is_err());
        assert!(rp("https://example.com", Some("example.com:443")).is_err());
        assert!(rp("https://example.com", Some("example.com.")).is_err());
        assert!(rp("https://example.com", Some("exämple.com")).is_err());
        assert!(rp("http://example.com", None).is_err());
        assert!(rp("https://192.0.2.1", None).is_err());
        assert!(rp("https://[::1]", None).is_err());
    }

    #[test]
    fn an_os_relying_party_is_checked_for_shape_only() {
        let psl = PublicSuffixList::bundled();
        assert_eq!(
            check_relying_party(&psl, "Login.Example.com").unwrap(),
            "login.example.com"
        );
        for bad in [
            "localhost",
            "co.uk",
            "github.io",
            "192.0.2.1",
            "::1",
            "",
            "a b.com",
            "-x.com",
            "exämple.com",
        ] {
            assert!(check_relying_party(&psl, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_os_signature_payload_appends_the_hash_unchanged() {
        let hash = [9_u8; 32];
        let payload = signed_payload_with_hash(&[1, 2, 3], &hash);
        assert_eq!(&payload[..3], &[1, 2, 3]);
        assert_eq!(&payload[3..], &hash);
        assert_eq!(
            signed_payload(&[1, 2, 3], "{}")[3..],
            sha256(&[b"{}"]),
            "the browser path hashes clientDataJSON itself"
        );
    }

    #[test]
    fn allows_http_localhost_as_its_own_rp() {
        assert_eq!(rp("http://localhost:3000", None).unwrap(), "localhost");
    }

    #[test]
    fn origin_text_drops_default_ports_and_keeps_others() {
        assert_eq!(
            origin_text(&Origin::parse("https://Example.com:443/path").unwrap()),
            "https://example.com"
        );
        assert_eq!(
            origin_text(&Origin::parse("https://example.com:8443").unwrap()),
            "https://example.com:8443"
        );
    }

    #[test]
    fn client_data_escapes_and_orders_fields() {
        let json = client_data_json(Ceremony::Get, "abc", "https://example.com").unwrap();
        assert_eq!(
            json,
            r#"{"type":"webauthn.get","challenge":"abc","origin":"https://example.com","crossOrigin":false}"#
        );
    }

    #[test]
    fn spki_and_cose_have_the_fixed_layout() {
        let mut sec1 = [7_u8; ES256_SEC1_LEN];
        sec1[0] = 4;
        let spki = spki(&sec1);
        assert_eq!(spki.len(), 91);
        assert_eq!(&spki[26..], &sec1);
        let cose = cose_key(&sec1).unwrap();
        assert_eq!(cose.len(), 77);
        assert_eq!(&cose[10..42], &[7; 32]);
        assert_eq!(&cose[45..], &[7; 32]);
    }
}
