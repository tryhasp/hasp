use std::num::NonZeroU32;

use opaque_ke::rand::{CryptoRng, Error as RngError, RngCore};
use zeroize::{Zeroize, Zeroizing};

use crate::{CryptoError, random};

pub(super) struct OsRng {
    pub(super) failed: bool,
}

pub(super) struct StreamRng {
    bytes: Zeroizing<Vec<u8>>,
    pub(super) offset: usize,
    pub(super) exhausted: bool,
}

impl OsRng {
    pub(super) fn new() -> Self {
        Self { failed: false }
    }

    pub(super) fn checked<T>(&self, result: Result<T, CryptoError>) -> Result<T, CryptoError> {
        if self.failed {
            return Err(CryptoError::Random);
        }
        result
    }

    pub(super) fn fill(&mut self, dest: &mut [u8]) {
        if random::fill_random(dest).is_err() {
            dest.zeroize();
            self.failed = true;
        }
    }
}

impl RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.fill(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.fill(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.fill(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill(dest);
        if self.failed {
            return Err(RngError::from(NonZeroU32::MIN));
        }
        Ok(())
    }
}

impl CryptoRng for OsRng {}

impl StreamRng {
    pub(super) fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self {
            bytes,
            offset: 0,
            exhausted: false,
        }
    }

    pub(super) fn take(&mut self, dest: &mut [u8]) {
        dest.zeroize();
        let end = self.offset.checked_add(dest.len());
        let source = end.and_then(|end| self.bytes.get(self.offset..end));
        match (source, end) {
            (Some(source), Some(end)) => {
                dest.copy_from_slice(source);
                self.offset = end;
            }
            _ => self.exhausted = true,
        }
    }
}

impl RngCore for StreamRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.take(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.take(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.take(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.take(dest);
        if self.exhausted {
            return Err(RngError::from(NonZeroU32::MIN));
        }
        Ok(())
    }
}

impl CryptoRng for StreamRng {}
