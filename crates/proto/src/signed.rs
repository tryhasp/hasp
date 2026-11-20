use core::fmt;
use core::marker::PhantomData;

use hasp_crypto::{Signature, SigningKey, VerifyingKey, verify_strict};

use crate::ProtoError;
use crate::cbor::{Reader, Wire, Writer};
use crate::id::Hash32;
use crate::label::SigLabel;

pub struct Signed<T> {
    pub body: Vec<u8>,
    pub signer: VerifyingKey,
    pub sig: Signature,
    _record: PhantomData<fn() -> T>,
}

impl<T: Wire> Signed<T> {
    pub fn sign(label: SigLabel, body: &T, key: &SigningKey) -> Result<Self, ProtoError> {
        let body = body.to_cbor()?;
        let sig = key.sign(&message(label, &body));
        Ok(Self {
            body,
            signer: key.verifying_key(),
            sig,
            _record: PhantomData,
        })
    }

    pub fn from_parts(body: Vec<u8>, signer: VerifyingKey, sig: Signature) -> Self {
        Self {
            body,
            signer,
            sig,
            _record: PhantomData,
        }
    }

    pub fn verify(&self, label: SigLabel, expected: &VerifyingKey) -> Result<T, ProtoError> {
        if self.signer != *expected {
            return Err(ProtoError::Sig);
        }
        verify_strict(&self.signer, &message(label, &self.body), &self.sig)
            .map_err(|_| ProtoError::Sig)?;
        T::from_cbor(&self.body)
    }

    pub fn unverified(&self) -> Result<T, ProtoError> {
        T::from_cbor(&self.body)
    }

    pub fn hash(&self) -> Hash32 {
        Hash32::digest(&[&self.body])
    }
}

fn message(label: SigLabel, body: &[u8]) -> Vec<u8> {
    let name = label.name().as_bytes();
    let mut message = Vec::with_capacity(name.len().saturating_add(1).saturating_add(body.len()));
    message.extend_from_slice(name);
    message.push(0);
    message.extend_from_slice(body);
    message
}

impl<T> Clone for Signed<T> {
    fn clone(&self) -> Self {
        Self {
            body: self.body.clone(),
            signer: self.signer,
            sig: self.sig,
            _record: PhantomData,
        }
    }
}

impl<T> PartialEq for Signed<T> {
    fn eq(&self, other: &Self) -> bool {
        self.body == other.body && self.signer == other.signer && self.sig == other.sig
    }
}

impl<T> Eq for Signed<T> {}

impl<T> fmt::Debug for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signed")
            .field("body_len", &self.body.len())
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

impl<T: Wire> Wire for Signed<T> {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.array(3)?;
        w.bytes(&self.body)?;
        w.bytes(self.signer.as_bytes())?;
        w.bytes(self.sig.as_bytes())
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        r.array(|r, n| {
            if n != 3 {
                return Err(ProtoError::Format);
            }
            let body = r.bytes()?.to_vec();
            let signer = VerifyingKey::from_bytes(r.fixed()?).map_err(|_| ProtoError::Format)?;
            let sig = Signature::from_bytes(r.fixed()?);
            Ok(Self::from_parts(body, signer, sig))
        })
    }
}
