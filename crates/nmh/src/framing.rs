use std::io::{self, Read, Write};

pub const MAX_FROM_BROWSER: usize = 64 * 1024;
pub const MAX_TO_BROWSER: usize = 1024 * 1024;
pub const MAX_HELLO: usize = 4 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame of {len} bytes exceeds the limit of {max}")]
    TooLarge { len: usize, max: usize },
    #[error("empty frame")]
    Empty,
    #[error("the stream ended inside a frame")]
    Truncated,
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

/// Reads one native-messaging frame: a native-endian `u32` length, then that many bytes.
/// `Ok(None)` is a clean end of stream on a frame boundary. The limit is checked before any
/// allocation, so a hostile length cannot reserve memory.
pub fn read_frame<R: Read>(reader: &mut R, max: usize) -> Result<Option<Vec<u8>>, FrameError> {
    let mut header = [0_u8; 4];
    let mut filled = 0;
    while filled < header.len() {
        let Some(rest) = header.get_mut(filled..) else {
            return Err(FrameError::Truncated);
        };
        match reader.read(rest) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(FrameError::Truncated),
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    let len = usize::try_from(u32::from_ne_bytes(header)).unwrap_or(usize::MAX);
    if len == 0 {
        return Err(FrameError::Empty);
    }
    if len > max {
        return Err(FrameError::TooLarge { len, max });
    }
    let mut body = vec![0_u8; len];
    reader.read_exact(&mut body).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            FrameError::Truncated
        } else {
            FrameError::Io(e)
        }
    })?;
    Ok(Some(body))
}

pub fn write_frame<W: Write>(writer: &mut W, body: &[u8], max: usize) -> Result<(), FrameError> {
    if body.is_empty() {
        return Err(FrameError::Empty);
    }
    if body.len() > max {
        return Err(FrameError::TooLarge {
            len: body.len(),
            max,
        });
    }
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge {
        len: body.len(),
        max,
    })?;
    let mut out = Vec::with_capacity(body.len().saturating_add(4));
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(body);
    writer.write_all(&out)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_frame(&mut out, body, MAX_TO_BROWSER).unwrap();
        out
    }

    #[test]
    fn round_trips_a_frame_with_a_native_endian_length() {
        let bytes = framed(b"{\"a\":1}");
        assert_eq!(bytes.get(..4).unwrap(), 7_u32.to_ne_bytes());
        let read = read_frame(&mut bytes.as_slice(), 64).unwrap().unwrap();
        assert_eq!(read, b"{\"a\":1}");
    }

    #[test]
    fn reads_frames_back_to_back_and_reports_a_clean_end() {
        let mut stream = framed(b"one");
        stream.extend(framed(b"two"));
        let mut cursor = stream.as_slice();
        assert_eq!(read_frame(&mut cursor, 8).unwrap().unwrap(), b"one");
        assert_eq!(read_frame(&mut cursor, 8).unwrap().unwrap(), b"two");
        assert!(read_frame(&mut cursor, 8).unwrap().is_none());
    }

    #[test]
    fn refuses_a_length_over_the_limit_without_reading_the_body() {
        let header = u32::MAX.to_ne_bytes();
        let error = read_frame(&mut header.as_slice(), MAX_FROM_BROWSER).unwrap_err();
        assert!(matches!(error, FrameError::TooLarge { max, .. } if max == MAX_FROM_BROWSER));
    }

    #[test]
    fn accepts_exactly_the_limit_and_refuses_one_byte_more() {
        let at = vec![b'x'; MAX_FROM_BROWSER];
        let bytes = framed(&at);
        assert!(read_frame(&mut bytes.as_slice(), MAX_FROM_BROWSER).is_ok());
        let over = vec![b'x'; MAX_FROM_BROWSER + 1];
        let bytes = framed(&over);
        assert!(matches!(
            read_frame(&mut bytes.as_slice(), MAX_FROM_BROWSER),
            Err(FrameError::TooLarge { .. })
        ));
    }

    #[test]
    fn refuses_an_empty_frame_both_ways() {
        let header = 0_u32.to_ne_bytes();
        assert!(matches!(
            read_frame(&mut header.as_slice(), 8),
            Err(FrameError::Empty)
        ));
        assert!(matches!(
            write_frame(&mut Vec::new(), b"", 8),
            Err(FrameError::Empty)
        ));
    }

    #[test]
    fn refuses_a_truncated_header_and_a_truncated_body() {
        assert!(matches!(
            read_frame(&mut [1_u8, 0].as_slice(), 8),
            Err(FrameError::Truncated)
        ));
        let mut bytes = 5_u32.to_ne_bytes().to_vec();
        bytes.extend_from_slice(b"ab");
        assert!(matches!(
            read_frame(&mut bytes.as_slice(), 8),
            Err(FrameError::Truncated)
        ));
    }

    #[test]
    fn refuses_to_write_over_the_limit() {
        let mut out = Vec::new();
        assert!(matches!(
            write_frame(&mut out, &[0; 9], 8),
            Err(FrameError::TooLarge { len: 9, max: 8 })
        ));
        assert!(out.is_empty());
    }
}
