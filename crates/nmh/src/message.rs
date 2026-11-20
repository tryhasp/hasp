use std::fmt;

use hasp_proto::DeviceId;
use hasp_proto::base64url;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const PROTOCOL_VERSION: u8 = 1;
const MAX_JS_INTEGER: u64 = (1 << 53) - 1;
const MAX_HOST_LEN: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Browser {
    Chrome,
    Edge,
    Brave,
    Firefox,
    Safari,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Chromium,
    Gecko,
    WebKit,
}

impl Browser {
    pub fn name(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Edge => "edge",
            Self::Brave => "brave",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
        }
    }

    pub fn family(self) -> Family {
        match self {
            Self::Chrome | Self::Edge | Self::Brave => Family::Chromium,
            Self::Firefox => Family::Gecko,
            Self::Safari => Family::WebKit,
        }
    }
}

/// Text that holds key material in transit. Zeroed on drop, redacted in `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretText(Zeroizing<String>);

impl Serialize for SecretText {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

impl SecretText {
    pub fn new(text: String) -> Self {
        Self(Zeroizing::new(text))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretText(..)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Malformed,
    Refused,
    Declined,
    Revoked,
    Locked,
    Unavailable,
}

/// What the extension did with a desktop `fill_request` (`BrowserFillChannel`).
/// `NeedsConfirmation` means the extension showed its own confirm card in the browser.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FillOutcome {
    Filled,
    NeedsConfirmation,
    NoMatchingPage,
    Locked,
    Unavailable,
}

/// Extension to desktop. This is the whole set the host relays; `status`, `policy`,
/// `list_matches`, `get_secret` and `save` join it later.
/// `data` is the base64url CBOR `enrol_request` of the core client. `page_reply` and
/// `fill_reply` only answer a desktop `page_query` or `fill_request` with the same `id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtensionMessage {
    EnrolRequest {
        id: u64,
        data: String,
    },
    Unlock {
        id: u64,
        device_id: String,
        nonce: String,
    },
    PageReply {
        id: u64,
        host: Option<String>,
        focused: bool,
    },
    FillReply {
        id: u64,
        outcome: FillOutcome,
    },
}

/// Desktop to extension. `data` is the base64url CBOR pairing payload of the core client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum DesktopMessage {
    EnrolReply {
        id: u64,
        data: SecretText,
    },
    UnlockReply {
        id: u64,
        k_ext: SecretText,
        valid_until: u64,
    },
    Lock,
    Error {
        id: Option<u64>,
        code: ErrorCode,
    },
    PageQuery {
        id: u64,
    },
    FillRequest {
        id: u64,
        vault: String,
        item: String,
    },
}

/// First frame from `hasp-nmh` to the app, written after the host verified its caller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub v: u8,
    pub browser: Browser,
    pub origin: String,
}

#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("not a message of the closed set")]
    Malformed,
}

impl ExtensionMessage {
    pub fn decode(frame: &[u8]) -> Result<Self, MessageError> {
        let message: Self = serde_json::from_slice(frame).map_err(|_| MessageError::Malformed)?;
        match &message {
            Self::EnrolRequest { id, data } => {
                check_id(*id)?;
                check_base64url(data)?;
            }
            Self::Unlock {
                id,
                device_id,
                nonce,
            } => {
                check_id(*id)?;
                base64url::decode_array::<16>(device_id).ok_or(MessageError::Malformed)?;
                base64url::decode_array::<16>(nonce).ok_or(MessageError::Malformed)?;
            }
            Self::PageReply { id, host, .. } => {
                check_id(*id)?;
                if let Some(host) = host {
                    check_host(host)?;
                }
            }
            Self::FillReply { id, .. } => check_id(*id)?,
        }
        Ok(message)
    }

    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        serde_json::to_vec(self).map_err(|_| MessageError::Malformed)
    }

    pub fn id(&self) -> u64 {
        match self {
            Self::EnrolRequest { id, .. }
            | Self::Unlock { id, .. }
            | Self::PageReply { id, .. }
            | Self::FillReply { id, .. } => *id,
        }
    }

    pub fn device_id(&self) -> Option<DeviceId> {
        match self {
            Self::Unlock { device_id, .. } => {
                base64url::decode_array::<16>(device_id).map(DeviceId::from_bytes)
            }
            Self::EnrolRequest { .. } | Self::PageReply { .. } | Self::FillReply { .. } => None,
        }
    }

    pub fn nonce(&self) -> Option<[u8; 16]> {
        match self {
            Self::Unlock { nonce, .. } => base64url::decode_array::<16>(nonce),
            Self::EnrolRequest { .. } | Self::PageReply { .. } | Self::FillReply { .. } => None,
        }
    }
}

impl DesktopMessage {
    pub fn decode(frame: &[u8]) -> Result<Self, MessageError> {
        let message: Self = serde_json::from_slice(frame).map_err(|_| MessageError::Malformed)?;
        match &message {
            Self::EnrolReply { id, data } => {
                check_id(*id)?;
                check_base64url(data.expose())?;
            }
            Self::UnlockReply {
                id,
                k_ext,
                valid_until,
            } => {
                check_id(*id)?;
                check_id(*valid_until)?;
                base64url::decode_array::<32>(k_ext.expose()).ok_or(MessageError::Malformed)?;
            }
            Self::Error { id, .. } => {
                if let Some(id) = id {
                    check_id(*id)?;
                }
            }
            Self::PageQuery { id } => check_id(*id)?,
            Self::FillRequest { id, vault, item } => {
                check_id(*id)?;
                check_hex_id(vault)?;
                check_hex_id(item)?;
            }
            Self::Lock => {}
        }
        Ok(message)
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, MessageError> {
        serde_json::to_vec(self)
            .map(Zeroizing::new)
            .map_err(|_| MessageError::Malformed)
    }
}

impl Hello {
    pub fn new(browser: Browser, origin: &str) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            browser,
            origin: origin.to_owned(),
        }
    }

    pub fn decode(frame: &[u8]) -> Result<Self, MessageError> {
        let hello: Self = serde_json::from_slice(frame).map_err(|_| MessageError::Malformed)?;
        if hello.v != PROTOCOL_VERSION {
            return Err(MessageError::Malformed);
        }
        Ok(hello)
    }

    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        serde_json::to_vec(self).map_err(|_| MessageError::Malformed)
    }
}

fn check_id(id: u64) -> Result<(), MessageError> {
    if id > MAX_JS_INTEGER {
        return Err(MessageError::Malformed);
    }
    Ok(())
}

fn check_hex_id(text: &str) -> Result<(), MessageError> {
    if text.len() == 32
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(MessageError::Malformed)
    }
}

fn check_host(host: &str) -> Result<(), MessageError> {
    let valid = !host.is_empty()
        && host.len() <= MAX_HOST_LEN
        && host.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'.' | b'-' | b':' | b'[' | b']')
        });
    if valid {
        Ok(())
    } else {
        Err(MessageError::Malformed)
    }
}

fn check_base64url(text: &str) -> Result<(), MessageError> {
    let valid = !text.is_empty()
        && text.len() % 4 != 1
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if valid {
        Ok(())
    } else {
        Err(MessageError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_type_outside_the_closed_set() {
        let frame = br#"{"type":"get_secret","id":1,"item":"x"}"#;
        assert!(ExtensionMessage::decode(frame).is_err());
        assert!(DesktopMessage::decode(br#"{"type":"unlock","id":1}"#).is_err());
    }

    #[test]
    fn rejects_unknown_fields_and_wrong_shapes() {
        assert!(
            ExtensionMessage::decode(
                br#"{"type":"unlock","id":1,"device_id":"AAAAAAAAAAAAAAAAAAAAAA","x":1}"#
            )
            .is_err()
        );
        assert!(
            ExtensionMessage::decode(br#"{"type":"unlock","id":1,"device_id":"short"}"#).is_err()
        );
        assert!(
            ExtensionMessage::decode(br#"{"type":"enrol_request","id":1,"data":"a b"}"#).is_err()
        );
        assert!(
            ExtensionMessage::decode(
                br#"{"type":"enrol_request","id":9007199254740992,"data":"AAAA"}"#
            )
            .is_err()
        );
        assert!(ExtensionMessage::decode(b"not json").is_err());
    }

    #[test]
    fn accepts_the_two_relayed_requests() {
        let unlock = ExtensionMessage::decode(
            br#"{"type":"unlock","id":7,"device_id":"AAAAAAAAAAAAAAAAAAAAAA","nonce":"AQEBAQEBAQEBAQEBAQEBAQ"}"#,
        )
        .unwrap();
        assert_eq!(unlock.id(), 7);
        assert_eq!(unlock.nonce(), Some([1; 16]));
        assert!(
            ExtensionMessage::decode(
                br#"{"type":"unlock","id":7,"device_id":"AAAAAAAAAAAAAAAAAAAAAA"}"#
            )
            .is_err()
        );
        assert!(
            ExtensionMessage::decode(
                br#"{"type":"unlock","id":7,"device_id":"AAAAAAAAAAAAAAAAAAAAAA","nonce":"AAAA"}"#
            )
            .is_err()
        );
        assert_eq!(unlock.device_id(), Some(DeviceId::from_bytes([0; 16])));
        let enrol =
            ExtensionMessage::decode(br#"{"type":"enrol_request","id":1,"data":"AAAA"}"#).unwrap();
        assert!(enrol.device_id().is_none());
    }

    #[test]
    fn fill_messages_are_closed_and_checked() {
        let request = DesktopMessage::FillRequest {
            id: 3,
            vault: "00112233445566778899aabbccddeeff".to_owned(),
            item: "ffeeddccbbaa99887766554433221100".to_owned(),
        };
        assert_eq!(
            DesktopMessage::decode(&request.encode().unwrap()).unwrap(),
            request
        );
        assert!(
            DesktopMessage::decode(br#"{"type":"fill_request","id":1,"vault":"AA","item":"bb"}"#)
                .is_err()
        );
        assert!(
            DesktopMessage::decode(
                br#"{"type":"fill_request","id":1,"vault":"00112233445566778899AABBCCDDEEFF","item":"ffeeddccbbaa99887766554433221100"}"#
            )
            .is_err()
        );
        assert!(
            DesktopMessage::decode(
                br#"{"type":"fill_request","id":1,"vault":"00112233445566778899aabbccddeeff","item":"ffeeddccbbaa99887766554433221100","value":"x"}"#
            )
            .is_err()
        );
        assert_eq!(
            DesktopMessage::decode(br#"{"type":"page_query","id":4}"#).unwrap(),
            DesktopMessage::PageQuery { id: 4 }
        );
        let page = ExtensionMessage::decode(
            br#"{"type":"page_reply","id":4,"host":"accounts.example.com","focused":true}"#,
        )
        .unwrap();
        assert_eq!(page.id(), 4);
        assert!(
            ExtensionMessage::decode(
                br#"{"type":"page_reply","id":4,"host":null,"focused":false}"#
            )
            .is_ok()
        );
        assert!(
            ExtensionMessage::decode(br#"{"type":"page_reply","id":4,"host":null}"#).is_err(),
            "a reply that does not say whether its window is focused is refused"
        );
        assert!(
            ExtensionMessage::decode(
                br#"{"type":"page_reply","id":4,"host":"a b/c","focused":true}"#
            )
            .is_err()
        );
        assert!(
            ExtensionMessage::decode(br#"{"type":"fill_reply","id":4,"outcome":"filled"}"#).is_ok()
        );
        assert!(
            ExtensionMessage::decode(br#"{"type":"fill_reply","id":4,"outcome":"maybe"}"#).is_err()
        );
        assert!(
            ExtensionMessage::decode(
                br#"{"type":"fill_reply","id":4,"outcome":"filled","password":"x"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn debug_hides_key_material() {
        let reply = DesktopMessage::UnlockReply {
            id: 1,
            k_ext: SecretText::new(base64url::encode(&[9; 32])),
            valid_until: 5,
        };
        assert!(!format!("{reply:?}").contains(&base64url::encode(&[9; 32])));
        let frame = reply.encode().unwrap();
        assert_eq!(DesktopMessage::decode(&frame).unwrap(), reply);
    }

    #[test]
    fn rejects_a_hello_of_another_version() {
        assert!(Hello::decode(br#"{"v":2,"browser":"chrome","origin":"x"}"#).is_err());
        let hello = Hello::new(Browser::Firefox, "a@b");
        assert_eq!(Hello::decode(&hello.encode().unwrap()).unwrap(), hello);
    }
}
