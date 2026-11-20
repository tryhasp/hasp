use hasp_boundary::Mirror;
use hasp_core::api::Secret as CoreSecret;
use zeroize::Zeroize;

pub struct Secret(Vec<u8>);

impl Secret {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn take(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

uniffi::custom_type!(Secret, Vec<u8>, {
    lower: |secret| secret.take(),
    try_lift: |bytes| Ok(Secret::new(bytes)),
});

impl Mirror<CoreSecret> for Secret {
    fn mirror(self) -> CoreSecret {
        CoreSecret::new(self.take())
    }
}

impl Mirror<Secret> for CoreSecret {
    fn mirror(self) -> Secret {
        Secret::new(self.take())
    }
}
