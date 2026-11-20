use super::{MAX_SECRET, PAYLOAD_VERSION, ProtoError, Reader, SecretBytes, Writer};

pub(super) fn zigzag(value: i32) -> Result<u64, ProtoError> {
    let wide = i64::from(value);
    let mapped = if wide >= 0 {
        wide.checked_mul(2)
    } else {
        wide.checked_neg()
            .and_then(|magnitude| magnitude.checked_mul(2))
            .and_then(|doubled| doubled.checked_sub(1))
    };
    u64::try_from(mapped.ok_or(ProtoError::Format)?).map_err(|_| ProtoError::Format)
}

pub(super) fn unzigzag(value: u64) -> Result<i32, ProtoError> {
    let magnitude = i64::try_from(value.div_ceil(2)).map_err(|_| ProtoError::Format)?;
    let signed = if value.checked_rem(2) == Some(0) {
        magnitude
    } else {
        magnitude.checked_neg().ok_or(ProtoError::Format)?
    };
    i32::try_from(signed).map_err(|_| ProtoError::Format)
}

pub(super) fn secret_bytes(w: &mut Writer, value: &SecretBytes) -> Result<(), ProtoError> {
    if value.len() > MAX_SECRET {
        return Err(ProtoError::Format);
    }
    w.bytes(value.expose())
}

pub(super) fn secret_bytes_read(r: &mut Reader<'_>) -> Result<SecretBytes, ProtoError> {
    let bytes = r.bytes()?;
    if bytes.len() > MAX_SECRET {
        return Err(ProtoError::Format);
    }
    Ok(SecretBytes::from_vec(bytes.to_vec()))
}

pub(super) fn long_text(w: &mut Writer, value: &str, limit: usize) -> Result<(), ProtoError> {
    if value.len() > limit {
        return Err(ProtoError::Format);
    }
    w.bytes(value.as_bytes())
}

pub(super) fn long_text_read(r: &mut Reader<'_>, limit: usize) -> Result<String, ProtoError> {
    let bytes = r.bytes()?;
    if bytes.len() > limit {
        return Err(ProtoError::Format);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| ProtoError::Format)
}

pub(super) fn opt_text(w: &mut Writer, value: Option<&str>) -> Result<(), ProtoError> {
    if let Some(value) = value {
        w.text(value)
    } else {
        w.null();
        Ok(())
    }
}

pub(super) fn opt_text_read(r: &mut Reader<'_>) -> Result<Option<String>, ProtoError> {
    if r.is_null() {
        r.null()?;
        return Ok(None);
    }
    Ok(Some(r.text()?.to_owned()))
}

pub(super) fn opt_uint(w: &mut Writer, value: Option<u64>) -> Result<(), ProtoError> {
    if let Some(value) = value {
        w.uint(value)
    } else {
        w.null();
        Ok(())
    }
}

pub(super) fn opt_uint_read(r: &mut Reader<'_>) -> Result<Option<u64>, ProtoError> {
    if r.is_null() {
        r.null()?;
        return Ok(None);
    }
    Ok(Some(r.uint()?.get()))
}

pub(super) fn list<T>(
    r: &mut Reader<'_>,
    mut each: impl FnMut(&mut Reader<'_>) -> Result<T, ProtoError>,
) -> Result<Vec<T>, ProtoError> {
    r.array(|r, n| {
        let mut items = Vec::with_capacity(n);
        for _ in 0..n {
            items.push(each(r)?);
        }
        Ok(items)
    })
}

pub(super) fn check_version(r: &mut Reader<'_>) -> Result<(), ProtoError> {
    if r.uint()?.get() == u64::from(PAYLOAD_VERSION) {
        Ok(())
    } else {
        Err(ProtoError::Version)
    }
}

pub(super) fn expect_count(found: usize, expected: usize) -> Result<(), ProtoError> {
    if found == expected {
        Ok(())
    } else {
        Err(ProtoError::Format)
    }
}

pub(super) fn narrow<T: TryFrom<u64>>(value: u64) -> Result<T, ProtoError> {
    T::try_from(value).map_err(|_| ProtoError::Format)
}
