use std::collections::BTreeMap;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::peer::{CodeTarget, CodeVerifier, PeerError, Requirement, VerifiedCode};

type Grants = BTreeMap<String, Vec<(Requirement, PathBuf)>>;

/// A scripted stand-in for the operating system's code-signature check. A target satisfies a
/// requirement only if it was told to with `sign`; anything else is a `Mismatch`.
#[derive(Clone, Debug)]
pub struct Double {
    parent: Result<CodeTarget, PeerError>,
    peer: Result<CodeTarget, PeerError>,
    signed_as: Arc<Mutex<Grants>>,
}

impl Double {
    pub fn new(parent: CodeTarget, peer: CodeTarget) -> Self {
        Self {
            parent: Ok(parent),
            peer: Ok(peer),
            signed_as: Arc::default(),
        }
    }

    pub fn sign(&self, target: &CodeTarget, requirement: Requirement, path: &str) {
        if let Ok(mut map) = self.signed_as.lock() {
            map.entry(format!("{target:?}"))
                .or_default()
                .push((requirement, PathBuf::from(path)));
        }
    }
}

impl CodeVerifier for Double {
    fn peer_of(&self, _: &UnixStream) -> Result<CodeTarget, PeerError> {
        self.peer.clone()
    }

    fn parent(&self) -> Result<CodeTarget, PeerError> {
        self.parent.clone()
    }

    fn verify(
        &self,
        target: &CodeTarget,
        requirement: &Requirement,
    ) -> Result<VerifiedCode, PeerError> {
        let map = self.signed_as.lock().map_err(|_| PeerError::Unidentified)?;
        map.get(&format!("{target:?}"))
            .and_then(|list| list.iter().find(|(r, _)| r == requirement))
            .map(|(_, path)| VerifiedCode { path: path.clone() })
            .ok_or(PeerError::Mismatch)
    }
}
