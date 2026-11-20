use hasp_crypto::{KemPublicKey, SecretKey, Signature, VerifyingKey, XWING_PUBLIC_KEY_LEN};
use zeroize::Zeroizing;

use crate::ProtoError;
use crate::cbor::{Reader, Wire, Writer};

impl Wire for VerifyingKey {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.bytes(self.as_bytes())
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        Self::from_bytes(r.fixed()?).map_err(|_| ProtoError::Format)
    }
}

impl Wire for Signature {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.bytes(self.as_bytes())
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        Ok(Self::from_bytes(r.fixed()?))
    }
}

impl Wire for KemPublicKey {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.bytes(self.as_bytes())
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        Self::from_bytes(r.fixed::<XWING_PUBLIC_KEY_LEN>()?).map_err(|_| ProtoError::Format)
    }
}

impl Wire for SecretKey {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.bytes(self.expose())
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        let bytes = Zeroizing::new(r.fixed::<32>()?);
        Ok(Self::from_bytes(*bytes))
    }
}
