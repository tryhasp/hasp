use super::{
    AppAssociation, AppPlatform, AssocSource, AttId, AttachmentDescriptor, MatchMode, Passkey,
    ProtoError, Reader, SecretKey, UrlEntry, UrlKind, Wire, Writer, Zeroizing, expect_count, list,
    narrow, opt_uint, opt_uint_read, secret_bytes, secret_bytes_read, unzigzag, zigzag,
};

pub(super) fn encode_url(w: &mut Writer, url: &UrlEntry) -> Result<(), ProtoError> {
    w.map(5)?;
    w.key(0)?;
    w.bytes(&url.id)?;
    w.key(1)?;
    w.text(&url.url)?;
    w.key(2)?;
    url.mode.encode(w)?;
    w.key(3)?;
    w.array(url.confirmed_hosts.len())?;
    for host in &url.confirmed_hosts {
        w.text(host)?;
    }
    w.key(4)?;
    url.kind.encode(w)
}

pub(super) fn decode_url(r: &mut Reader<'_>) -> Result<UrlEntry, ProtoError> {
    r.map(|r, n| {
        expect_count(n, 5)?;
        r.key(0)?;
        let id = r.fixed()?;
        r.key(1)?;
        let url = r.text()?.to_owned();
        r.key(2)?;
        let mode = MatchMode::decode(r)?;
        r.key(3)?;
        let confirmed_hosts = list(r, |r| Ok(r.text()?.to_owned()))?;
        r.key(4)?;
        let kind = UrlKind::decode(r)?;
        Ok(UrlEntry {
            id,
            url,
            mode,
            confirmed_hosts,
            kind,
        })
    })
}

pub(super) fn encode_app(w: &mut Writer, app: &AppAssociation) -> Result<(), ProtoError> {
    w.map(4)?;
    w.key(0)?;
    app.platform.encode(w)?;
    w.key(1)?;
    w.text(&app.id)?;
    w.key(2)?;
    match &app.cert_sha256 {
        Some(cert) => w.bytes(cert)?,
        None => w.null(),
    }
    w.key(3)?;
    app.source.encode(w)
}

pub(super) fn decode_app(r: &mut Reader<'_>) -> Result<AppAssociation, ProtoError> {
    r.map(|r, n| {
        expect_count(n, 4)?;
        r.key(0)?;
        let platform = AppPlatform::decode(r)?;
        r.key(1)?;
        let id = r.text()?.to_owned();
        r.key(2)?;
        let cert_sha256 = if r.is_null() {
            r.null()?;
            None
        } else {
            Some(r.fixed()?)
        };
        r.key(3)?;
        let source = AssocSource::decode(r)?;
        Ok(AppAssociation {
            platform,
            id,
            cert_sha256,
            source,
        })
    })
}

pub(super) fn encode_passkey(w: &mut Writer, p: &Passkey) -> Result<(), ProtoError> {
    w.map(11)?;
    w.key(0)?;
    w.bytes(&p.credential_id)?;
    w.key(1)?;
    w.text(&p.rp_id)?;
    w.key(2)?;
    w.bytes(&p.user_handle)?;
    w.key(3)?;
    w.text(&p.user_name)?;
    w.key(4)?;
    w.text(&p.display_name)?;
    w.key(5)?;
    w.uint(zigzag(p.algorithm)?)?;
    w.key(6)?;
    secret_bytes(w, &p.private_key)?;
    w.key(7)?;
    w.uint(p.created)?;
    w.key(8)?;
    opt_uint(w, p.last_used)?;
    w.key(9)?;
    w.bool(p.backup_eligible);
    w.key(10)?;
    w.bool(p.backed_up);
    Ok(())
}

pub(super) fn decode_passkey(r: &mut Reader<'_>) -> Result<Passkey, ProtoError> {
    r.map(|r, n| {
        expect_count(n, 11)?;
        r.key(0)?;
        let credential_id = r.bytes()?.to_vec();
        r.key(1)?;
        let rp_id = r.text()?.to_owned();
        r.key(2)?;
        let user_handle = r.bytes()?.to_vec();
        r.key(3)?;
        let user_name = r.text()?.to_owned();
        r.key(4)?;
        let display_name = r.text()?.to_owned();
        r.key(5)?;
        let algorithm = unzigzag(r.uint()?.get())?;
        r.key(6)?;
        let private_key = secret_bytes_read(r)?;
        r.key(7)?;
        let created = r.uint()?.get();
        r.key(8)?;
        let last_used = opt_uint_read(r)?;
        r.key(9)?;
        let backup_eligible = r.bool()?;
        r.key(10)?;
        let backed_up = r.bool()?;
        Ok(Passkey {
            credential_id,
            rp_id,
            user_handle,
            user_name,
            display_name,
            algorithm,
            private_key,
            created,
            last_used,
            backup_eligible,
            backed_up,
        })
    })
}

pub(super) fn encode_attachment(
    w: &mut Writer,
    a: &AttachmentDescriptor,
) -> Result<(), ProtoError> {
    w.map(7)?;
    w.key(0)?;
    a.att_id.encode(w)?;
    w.key(1)?;
    w.bytes(a.file_key.expose())?;
    w.key(2)?;
    w.bytes(&a.nonce_prefix)?;
    w.key(3)?;
    w.uint(a.size)?;
    w.key(4)?;
    w.uint(u64::from(a.chunk_size))?;
    w.key(5)?;
    w.text(&a.name)?;
    w.key(6)?;
    w.text(&a.mime)
}

pub(super) fn decode_attachment(r: &mut Reader<'_>) -> Result<AttachmentDescriptor, ProtoError> {
    r.map(|r, n| {
        expect_count(n, 7)?;
        r.key(0)?;
        let att_id = AttId::decode(r)?;
        r.key(1)?;
        let file_key = SecretKey::from_slice(&Zeroizing::new(r.fixed::<32>()?)[..])?;
        r.key(2)?;
        let nonce_prefix = r.fixed()?;
        r.key(3)?;
        let size = r.uint()?.get();
        r.key(4)?;
        let chunk_size = narrow(r.uint()?.get())?;
        r.key(5)?;
        let name = r.text()?.to_owned();
        r.key(6)?;
        let mime = r.text()?.to_owned();
        Ok(AttachmentDescriptor {
            att_id,
            file_key,
            nonce_prefix,
            size,
            chunk_size,
            name,
            mime,
        })
    })
}
