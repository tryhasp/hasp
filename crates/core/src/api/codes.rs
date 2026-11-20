use std::sync::OnceLock;

use super::ids;
use crate::CoreError;
use crate::client::{UNLOCK_NONCE_LEN, pairing_code_of_request, unlock_code};
use crate::matcher::psl::PublicSuffixList;

/// The six digits the extension shows next to the desktop prompt for one `unlock` request.
pub fn extension_unlock_code(device: &str, nonce: &str) -> Result<String, CoreError> {
    let device = ids::device(device)?;
    let nonce: [u8; UNLOCK_NONCE_LEN] =
        hasp_proto::base64url::decode_array(nonce).ok_or(hasp_proto::ProtoError::Format)?;
    Ok(unlock_code(&device, &nonce))
}

/// The six digits the extension shows while the desktop asks the user to approve its pairing.
pub fn extension_pairing_code(enrol_request: &[u8]) -> Result<String, CoreError> {
    pairing_code_of_request(enrol_request)
}

/// The registrable domain of `host` by the public suffix list, private section included.
pub fn registrable_domain(host: &str) -> Option<String> {
    static LIST: OnceLock<PublicSuffixList> = OnceLock::new();
    LIST.get_or_init(PublicSuffixList::bundled)
        .registrable_domain(&host.to_ascii_lowercase())
        .map(str::to_owned)
}
