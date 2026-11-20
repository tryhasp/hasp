use super::{
    Address, Field, FieldKind, Otp, OtpAlgorithm, OtpMode, ProtoError, Purpose, Reader, Section,
    Value, Wire, Writer, expect_count, list, narrow, opt_text, opt_text_read, secret_bytes,
    secret_bytes_read,
};

pub(super) fn encode_section(w: &mut Writer, section: &Section) -> Result<(), ProtoError> {
    w.map(3)?;
    w.key(0)?;
    w.bytes(&section.id)?;
    w.key(1)?;
    w.text(&section.title)?;
    w.key(2)?;
    w.array(section.fields.len())?;
    for field in &section.fields {
        w.map(7)?;
        w.key(0)?;
        w.bytes(&field.id)?;
        w.key(1)?;
        w.text(&field.label)?;
        w.key(2)?;
        field.value.kind().encode(w)?;
        w.key(3)?;
        encode_value(w, &field.value)?;
        w.key(4)?;
        match field.purpose {
            Some(purpose) => purpose.encode(w)?,
            None => w.null(),
        }
        w.key(5)?;
        w.bool(field.concealed);
        w.key(6)?;
        w.bool(field.expires_alert);
    }
    Ok(())
}

pub(super) fn decode_section(r: &mut Reader<'_>) -> Result<Section, ProtoError> {
    r.map(|r, n| {
        expect_count(n, 3)?;
        r.key(0)?;
        let id = r.fixed()?;
        r.key(1)?;
        let title = r.text()?.to_owned();
        r.key(2)?;
        let fields = list(r, decode_field)?;
        Ok(Section { id, title, fields })
    })
}

pub(super) fn decode_field(r: &mut Reader<'_>) -> Result<Field, ProtoError> {
    r.map(|r, n| {
        expect_count(n, 7)?;
        r.key(0)?;
        let id = r.fixed()?;
        r.key(1)?;
        let label = r.text()?.to_owned();
        r.key(2)?;
        let kind = FieldKind::decode(r)?;
        r.key(3)?;
        let value = decode_value(r, kind)?;
        r.key(4)?;
        let purpose = if r.is_null() {
            r.null()?;
            None
        } else {
            Some(Purpose::decode(r)?)
        };
        r.key(5)?;
        let concealed = r.bool()?;
        r.key(6)?;
        let expires_alert = r.bool()?;
        Ok(Field {
            id,
            label,
            value,
            purpose,
            concealed,
            expires_alert,
        })
    })
}

pub(super) fn encode_value(w: &mut Writer, value: &Value) -> Result<(), ProtoError> {
    match value {
        Value::Text(v)
        | Value::Url(v)
        | Value::Email(v)
        | Value::Phone(v)
        | Value::Menu(v)
        | Value::SignInWith(v) => w.text(v),
        Value::Concealed(v) => secret_bytes(w, v),
        Value::Date { year, month, day } => {
            w.array(3)?;
            w.uint(u64::from(*year))?;
            w.uint(u64::from(*month))?;
            w.uint(u64::from(*day))
        }
        Value::MonthYear { year, month } => {
            w.array(2)?;
            w.uint(u64::from(*year))?;
            w.uint(u64::from(*month))
        }
        Value::Otp(otp) => encode_otp(w, otp),
        Value::Address(a) => {
            w.array(5)?;
            for part in [&a.street, &a.city, &a.region, &a.postal_code, &a.country] {
                w.text(part)?;
            }
            Ok(())
        }
        Value::SecurityQuestion { question, answer } => {
            w.array(2)?;
            w.text(question)?;
            secret_bytes(w, answer)
        }
    }
}

pub(super) fn decode_value(r: &mut Reader<'_>, kind: FieldKind) -> Result<Value, ProtoError> {
    Ok(match kind {
        FieldKind::Text => Value::Text(r.text()?.to_owned()),
        FieldKind::Url => Value::Url(r.text()?.to_owned()),
        FieldKind::Email => Value::Email(r.text()?.to_owned()),
        FieldKind::Phone => Value::Phone(r.text()?.to_owned()),
        FieldKind::Menu => Value::Menu(r.text()?.to_owned()),
        FieldKind::SignInWith => Value::SignInWith(r.text()?.to_owned()),
        FieldKind::Concealed => Value::Concealed(secret_bytes_read(r)?),
        FieldKind::Date => r.array(|r, n| {
            expect_count(n, 3)?;
            Ok(Value::Date {
                year: narrow(r.uint()?.get())?,
                month: narrow(r.uint()?.get())?,
                day: narrow(r.uint()?.get())?,
            })
        })?,
        FieldKind::MonthYear => r.array(|r, n| {
            expect_count(n, 2)?;
            Ok(Value::MonthYear {
                year: narrow(r.uint()?.get())?,
                month: narrow(r.uint()?.get())?,
            })
        })?,
        FieldKind::Otp => Value::Otp(decode_otp(r)?),
        FieldKind::Address => r.array(|r, n| {
            expect_count(n, 5)?;
            Ok(Value::Address(Address {
                street: r.text()?.to_owned(),
                city: r.text()?.to_owned(),
                region: r.text()?.to_owned(),
                postal_code: r.text()?.to_owned(),
                country: r.text()?.to_owned(),
            }))
        })?,
        FieldKind::SecurityQuestion => r.array(|r, n| {
            expect_count(n, 2)?;
            Ok(Value::SecurityQuestion {
                question: r.text()?.to_owned(),
                answer: secret_bytes_read(r)?,
            })
        })?,
    })
}

pub(super) fn encode_otp(w: &mut Writer, otp: &Otp) -> Result<(), ProtoError> {
    w.map(8)?;
    w.key(0)?;
    secret_bytes(w, &otp.secret)?;
    w.key(1)?;
    otp.algorithm.encode(w)?;
    w.key(2)?;
    w.uint(u64::from(otp.digits))?;
    let (kind, parameter) = match otp.mode {
        OtpMode::Totp { period_s } => (0, u64::from(period_s)),
        OtpMode::Hotp { counter } => (1, counter),
    };
    w.key(3)?;
    w.uint(kind)?;
    w.key(4)?;
    w.uint(parameter)?;
    w.key(5)?;
    opt_text(w, otp.issuer.as_deref())?;
    w.key(6)?;
    opt_text(w, otp.account.as_deref())?;
    w.key(7)?;
    w.bool(otp.steam);
    Ok(())
}

pub(super) fn decode_otp(r: &mut Reader<'_>) -> Result<Otp, ProtoError> {
    r.map(|r, n| {
        expect_count(n, 8)?;
        r.key(0)?;
        let secret = secret_bytes_read(r)?;
        r.key(1)?;
        let algorithm = OtpAlgorithm::decode(r)?;
        r.key(2)?;
        let digits = narrow(r.uint()?.get())?;
        r.key(3)?;
        let kind = r.uint()?.get();
        r.key(4)?;
        let parameter = r.uint()?.get();
        r.key(5)?;
        let issuer = opt_text_read(r)?;
        r.key(6)?;
        let account = opt_text_read(r)?;
        r.key(7)?;
        let steam = r.bool()?;
        let mode = match kind {
            0 => OtpMode::Totp {
                period_s: narrow(parameter)?,
            },
            1 => OtpMode::Hotp { counter: parameter },
            _ => return Err(ProtoError::Format),
        };
        Ok(Otp {
            secret,
            algorithm,
            digits,
            mode,
            issuer,
            account,
            steam,
        })
    })
}
