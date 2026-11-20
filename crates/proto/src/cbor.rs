use core::fmt;

use zeroize::Zeroizing;

use crate::ProtoError;
use crate::uint::Uint53;

pub const MAX_NESTING: usize = 8;
pub const MAX_ARRAY: usize = 65_536;
pub const MAX_TEXT: usize = 4_096;
pub const MAX_RECORD: usize = 16 * 1024 * 1024;

const UINT: u8 = 0x00;
const BYTES: u8 = 0x40;
const TEXT: u8 = 0x60;
const ARRAY: u8 = 0x80;
const MAP: u8 = 0xa0;
const MAJOR_MASK: u8 = 0xe0;
const ARG_MASK: u8 = 0x1f;
const FALSE: u8 = 0xf4;
const TRUE: u8 = 0xf5;
const NULL: u8 = 0xf6;
const MAX_KEY: u64 = 255;

/// A value with one canonical CBOR encoding.
///
/// `from_cbor` rejects non-shortest integers, indefinite lengths, floats, tags, duplicate,
/// unknown, missing or unsorted keys, trailing bytes and any input that does not re-encode
/// to itself. Every failure is `ProtoError::Format`, except an unsupported `v`, which is
/// `ProtoError::Version`.
///
/// ```
/// use hasp_proto::{Uint53, Wire};
///
/// let bytes = Uint53::new(24)?.to_cbor()?;
/// assert_eq!(bytes, [0x18, 0x18]);
/// assert!(Uint53::from_cbor(&[0x19, 0x00, 0x18]).is_err());
/// # Ok::<(), hasp_proto::ProtoError>(())
/// ```
pub trait Wire: Sized {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError>;
    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError>;

    fn to_cbor(&self) -> Result<Vec<u8>, ProtoError> {
        let mut bytes = self.to_cbor_secret()?;
        Ok(core::mem::take(&mut *bytes))
    }

    fn to_cbor_secret(&self) -> Result<Zeroizing<Vec<u8>>, ProtoError> {
        let mut w = Writer::new();
        self.encode(&mut w)?;
        let bytes = w.into_zeroizing();
        if bytes.len() > MAX_RECORD {
            return Err(ProtoError::Format);
        }
        Ok(bytes)
    }

    fn from_cbor(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() > MAX_RECORD {
            return Err(ProtoError::Format);
        }
        let mut r = Reader::new(bytes);
        let value = Self::decode(&mut r)?;
        r.finish()?;
        if *value.to_cbor_secret()? != bytes {
            return Err(ProtoError::Format);
        }
        Ok(value)
    }
}

#[derive(Default)]
pub struct Writer {
    buf: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Writer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Writer")
            .field("len", &self.buf.len())
            .finish()
    }
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut *self.buf)
    }

    pub fn into_zeroizing(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(core::mem::take(&mut *self.buf))
    }

    fn put(&mut self, data: &[u8]) {
        let spare = self.buf.capacity().saturating_sub(self.buf.len());
        if spare < data.len() {
            let wanted = self.buf.len().saturating_add(data.len()).max(64);
            let mut grown = Zeroizing::new(Vec::with_capacity(wanted.saturating_mul(2)));
            grown.extend_from_slice(&self.buf);
            core::mem::swap(&mut self.buf, &mut grown);
        }
        self.buf.extend_from_slice(data);
    }

    pub fn uint(&mut self, value: u64) -> Result<(), ProtoError> {
        self.head(UINT, value)
    }

    pub fn bytes(&mut self, value: &[u8]) -> Result<(), ProtoError> {
        self.head(BYTES, length(value.len())?)?;
        self.put(value);
        Ok(())
    }

    pub fn text(&mut self, value: &str) -> Result<(), ProtoError> {
        if value.len() > MAX_TEXT {
            return Err(ProtoError::Format);
        }
        self.head(TEXT, length(value.len())?)?;
        self.put(value.as_bytes());
        Ok(())
    }

    pub fn array(&mut self, count: usize) -> Result<(), ProtoError> {
        self.head(ARRAY, length(count)?)
    }

    pub fn map(&mut self, count: usize) -> Result<(), ProtoError> {
        self.head(MAP, length(count)?)
    }

    pub fn key(&mut self, key: u8) -> Result<(), ProtoError> {
        self.head(UINT, u64::from(key))
    }

    pub fn null(&mut self) {
        self.put(&[NULL]);
    }

    pub fn field<T: Wire>(&mut self, key: u8, value: &T) -> Result<(), ProtoError> {
        self.key(key)?;
        value.encode(self)
    }

    pub fn bool(&mut self, value: bool) {
        self.put(&[if value { TRUE } else { FALSE }]);
    }

    fn head(&mut self, major: u8, arg: u64) -> Result<(), ProtoError> {
        let internal = |_| ProtoError::Internal("cbor head");
        if arg < 24 {
            self.put(&[major | u8::try_from(arg).map_err(internal)?]);
        } else if let Ok(v) = u8::try_from(arg) {
            self.put(&[major | 0x18]);
            self.put(&[v]);
        } else if let Ok(v) = u16::try_from(arg) {
            self.put(&[major | 0x19]);
            self.put(&v.to_be_bytes());
        } else if let Ok(v) = u32::try_from(arg) {
            self.put(&[major | 0x1a]);
            self.put(&v.to_be_bytes());
        } else {
            self.put(&[major | 0x1b]);
            self.put(&arg.to_be_bytes());
        }
        Ok(())
    }
}

fn length(len: usize) -> Result<u64, ProtoError> {
    u64::try_from(len).map_err(|_| ProtoError::Internal("cbor length"))
}

#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            depth: 0,
        }
    }

    pub fn finish(self) -> Result<(), ProtoError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(ProtoError::Format)
        }
    }

    pub fn uint(&mut self) -> Result<Uint53, ProtoError> {
        let arg = self.expect(UINT)?;
        Uint53::new(arg).map_err(|_| ProtoError::Format)
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], ProtoError> {
        let len = self.expect(BYTES)?;
        let len = usize::try_from(len).map_err(|_| ProtoError::Format)?;
        self.take(len)
    }

    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ProtoError> {
        self.bytes()?.try_into().map_err(|_| ProtoError::Format)
    }

    pub fn text(&mut self) -> Result<&'a str, ProtoError> {
        let len = self.expect(TEXT)?;
        let len = usize::try_from(len).map_err(|_| ProtoError::Format)?;
        if len > MAX_TEXT {
            return Err(ProtoError::Format);
        }
        core::str::from_utf8(self.take(len)?).map_err(|_| ProtoError::Format)
    }

    pub fn bool(&mut self) -> Result<bool, ProtoError> {
        match self.take(1)?.first() {
            Some(&FALSE) => Ok(false),
            Some(&TRUE) => Ok(true),
            Some(_) | None => Err(ProtoError::Format),
        }
    }

    pub fn is_null(&self) -> bool {
        self.buf.get(self.pos) == Some(&NULL)
    }

    pub fn null(&mut self) -> Result<(), ProtoError> {
        if self.is_null() {
            self.pos = self.pos.checked_add(1).ok_or(ProtoError::Format)?;
            Ok(())
        } else {
            Err(ProtoError::Format)
        }
    }

    pub fn array<T>(
        &mut self,
        body: impl FnOnce(&mut Self, usize) -> Result<T, ProtoError>,
    ) -> Result<T, ProtoError> {
        let count = self.expect(ARRAY)?;
        self.container(count, body)
    }

    pub fn array_of_decode<T>(
        &mut self,
        count: usize,
        body: impl FnOnce(&mut Self) -> Result<T, ProtoError>,
    ) -> Result<T, ProtoError> {
        self.array(|r, n| {
            if n != count {
                return Err(ProtoError::Format);
            }
            body(r)
        })
    }

    pub fn map<T>(
        &mut self,
        body: impl FnOnce(&mut Self, usize) -> Result<T, ProtoError>,
    ) -> Result<T, ProtoError> {
        let count = self.expect(MAP)?;
        self.container(count, body)
    }

    pub fn key(&mut self, expected: u8) -> Result<(), ProtoError> {
        let key = self.expect(UINT)?;
        if key > MAX_KEY || key != u64::from(expected) {
            return Err(ProtoError::Format);
        }
        Ok(())
    }

    pub fn value<T: Wire>(&mut self) -> Result<T, ProtoError> {
        T::decode(self)
    }

    pub fn field<T: Wire>(&mut self, key: u8) -> Result<T, ProtoError> {
        self.key(key)?;
        T::decode(self)
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn container<T>(
        &mut self,
        count: u64,
        body: impl FnOnce(&mut Self, usize) -> Result<T, ProtoError>,
    ) -> Result<T, ProtoError> {
        let count = usize::try_from(count).map_err(|_| ProtoError::Format)?;
        let nested = self.depth.checked_add(1).ok_or(ProtoError::Format)?;
        if count > MAX_ARRAY || count > self.remaining() || nested > MAX_NESTING {
            return Err(ProtoError::Format);
        }
        self.depth = nested;
        let result = body(self, count);
        self.depth = self.depth.saturating_sub(1);
        result
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ProtoError> {
        let end = self.pos.checked_add(len).ok_or(ProtoError::Format)?;
        let slice = self.buf.get(self.pos..end).ok_or(ProtoError::Format)?;
        self.pos = end;
        Ok(slice)
    }

    fn expect(&mut self, major: u8) -> Result<u64, ProtoError> {
        let first = *self.take(1)?.first().ok_or(ProtoError::Format)?;
        if first & MAJOR_MASK != major {
            return Err(ProtoError::Format);
        }
        let (arg, floor) = match first & ARG_MASK {
            ai @ 0..=23 => (u64::from(ai), 0),
            24 => (u64::from(u8::from_be_bytes(self.fixed_be()?)), 24),
            25 => (u64::from(u16::from_be_bytes(self.fixed_be()?)), 0x100),
            26 => (u64::from(u32::from_be_bytes(self.fixed_be()?)), 0x1_0000),
            27 => (u64::from_be_bytes(self.fixed_be()?), 0x1_0000_0000),
            _ => return Err(ProtoError::Format),
        };
        if arg < floor {
            return Err(ProtoError::Format);
        }
        Ok(arg)
    }

    fn fixed_be<const N: usize>(&mut self) -> Result<[u8; N], ProtoError> {
        self.take(N)?.try_into().map_err(|_| ProtoError::Format)
    }
}

impl<const N: usize> Wire for [u8; N] {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.bytes(self)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        r.fixed()
    }
}

impl<T: Wire> Wire for Option<T> {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        if let Some(value) = self {
            value.encode(w)
        } else {
            w.null();
            Ok(())
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        if r.is_null() {
            r.null()?;
            Ok(None)
        } else {
            T::decode(r).map(Some)
        }
    }
}

impl<T: Wire> Wire for Vec<T> {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.array(self.len())?;
        self.iter().try_for_each(|item| item.encode(w))
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        r.array(|r, n| {
            let mut out = Vec::with_capacity(n);
            for _ in 0..n {
                out.push(T::decode(r)?);
            }
            Ok(out)
        })
    }
}

impl Wire for String {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.text(self)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        r.text().map(str::to_owned)
    }
}

impl Wire for bool {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.bool(*self);
        Ok(())
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        r.bool()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_uint(value: u64, expected: &[u8]) {
        let mut w = Writer::new();
        w.uint(value).unwrap();
        assert_eq!(w.into_bytes(), expected);
        let mut r = Reader::new(expected);
        assert_eq!(r.uint().unwrap().get(), value);
        r.finish().unwrap();
    }

    #[test]
    fn encodes_shortest_unsigned_integers() {
        roundtrip_uint(0, &[0x00]);
        roundtrip_uint(23, &[0x17]);
        roundtrip_uint(24, &[0x18, 0x18]);
        roundtrip_uint(255, &[0x18, 0xff]);
        roundtrip_uint(256, &[0x19, 0x01, 0x00]);
        roundtrip_uint(65_535, &[0x19, 0xff, 0xff]);
        roundtrip_uint(65_536, &[0x1a, 0x00, 0x01, 0x00, 0x00]);
        roundtrip_uint(
            Uint53::MAX,
            &[0x1b, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        );
    }

    #[test]
    fn rejects_non_shortest_integers() {
        for bytes in [
            &[0x18, 0x00][..],
            &[0x18, 0x17],
            &[0x19, 0x00, 0xff],
            &[0x1a, 0x00, 0x00, 0xff, 0xff],
            &[0x1b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff],
        ] {
            assert!(Reader::new(bytes).uint().is_err());
        }
    }

    #[test]
    fn rejects_integers_above_2_pow_53() {
        let bytes = [0x1b, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(Reader::new(&bytes).uint().is_err());
    }

    #[test]
    fn rejects_negative_integers_floats_tags_and_simple_values() {
        for bytes in [
            &[0x20][..],
            &[0xf9, 0x3c, 0x00],
            &[0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0],
            &[0xc0, 0x00],
            &[0xd9, 0xd9, 0xf7, 0x00],
            &[0xf7],
            &[0xf0],
        ] {
            assert!(Reader::new(bytes).uint().is_err());
            assert!(Reader::new(bytes).bytes().is_err());
            assert!(Reader::new(bytes).bool().is_err());
            assert!(!Reader::new(bytes).is_null());
        }
    }

    #[test]
    fn rejects_indefinite_lengths() {
        for bytes in [
            &[0x5f, 0xff][..],
            &[0x7f, 0xff],
            &[0x9f, 0xff],
            &[0xbf, 0xff],
        ] {
            assert!(Reader::new(bytes).bytes().is_err());
            assert!(Reader::new(bytes).text().is_err());
            assert!(Reader::new(bytes).array(|_, _| Ok(())).is_err());
            assert!(Reader::new(bytes).map(|_, _| Ok(())).is_err());
        }
    }

    #[test]
    fn rejects_truncated_and_oversized_lengths() {
        assert!(Reader::new(&[0x42, 0x00]).bytes().is_err());
        assert!(
            Reader::new(&[0x9a, 0xff, 0xff, 0xff, 0xff])
                .array(|_, _| Ok(()))
                .is_err()
        );
    }

    #[test]
    fn rejects_text_above_limit_and_invalid_utf8() {
        let mut w = Writer::new();
        w.text(&"a".repeat(MAX_TEXT)).unwrap();
        assert!(Reader::new(&w.into_bytes()).text().is_ok());
        assert!(Writer::new().text(&"a".repeat(MAX_TEXT + 1)).is_err());
        let mut raw = vec![0x79, 0x10, 0x01];
        raw.extend(std::iter::repeat_n(b'a', MAX_TEXT + 1));
        assert!(Reader::new(&raw).text().is_err());
        assert!(Reader::new(&[0x61, 0xff]).text().is_err());
    }

    #[test]
    fn rejects_nesting_deeper_than_eight() {
        let mut ok = vec![0x81; MAX_NESTING];
        ok.push(0x00);
        assert!(descend(&mut Reader::new(&ok), MAX_NESTING).is_ok());
        let mut deep = vec![0x81; MAX_NESTING + 1];
        deep.push(0x00);
        assert!(descend(&mut Reader::new(&deep), MAX_NESTING + 1).is_err());
    }

    fn descend(r: &mut Reader<'_>, levels: usize) -> Result<(), ProtoError> {
        if levels == 0 {
            return r.uint().map(|_| ());
        }
        r.array(|r, n| {
            if n != 1 {
                return Err(ProtoError::Format);
            }
            descend(r, levels.saturating_sub(1))
        })
    }

    #[test]
    fn option_encodes_null_and_rejects_nonnull_garbage() {
        let mut w = Writer::new();
        None::<[u8; 2]>.encode(&mut w).unwrap();
        assert_eq!(w.into_bytes(), [0xf6]);
        assert_eq!(Option::<[u8; 2]>::from_cbor(&[0xf6]).unwrap(), None);
        assert!(Option::<[u8; 2]>::from_cbor(&[0xf7]).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        assert!(<[u8; 1]>::from_cbor(&[0x41, 0x00, 0x00]).is_err());
    }
}
