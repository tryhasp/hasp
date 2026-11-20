use url::Url;

use crate::otp::{OtpAlg, OtpError, OtpKind, OtpParams, base32};

const DEFAULT_DIGITS: u8 = 6;
const DEFAULT_PERIOD_S: u32 = 30;
const MAX_URI_LEN: usize = 4096;

pub fn parse(text: &str) -> Result<OtpParams, OtpError> {
    let text = text.trim();
    if text.len() > MAX_URI_LEN {
        return Err(OtpError::Uri);
    }
    if let Some(rest) = strip_scheme(text, "steam") {
        let secret = base32::decode(rest.trim_start_matches('/'))?;
        return OtpParams::steam(&secret);
    }
    let url = Url::parse(text).map_err(|_| OtpError::Uri)?;
    if url.scheme() != "otpauth" {
        return Err(OtpError::Uri);
    }
    let kind = url.host_str().ok_or(OtpError::Uri)?.to_ascii_lowercase();
    let label = percent_decode(url.path().trim_start_matches('/'))?;
    let mut secret = None;
    let mut issuer = None;
    let mut algorithm = OtpAlg::Sha1;
    let mut digits = None;
    let mut period = None;
    let mut counter = None;
    let mut steam = kind == "steam";
    for (key, value) in url.query_pairs() {
        match key.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(base32::decode(&value)?),
            "issuer" => issuer = Some(value.into_owned()),
            "algorithm" => algorithm = OtpAlg::parse(&value)?,
            "digits" => digits = Some(value.parse::<u8>().map_err(|_| OtpError::Digits)?),
            "period" => period = Some(value.parse::<u32>().map_err(|_| OtpError::Period)?),
            "counter" => counter = Some(value.parse::<u64>().map_err(|_| OtpError::Uri)?),
            "encoder" => steam = value.eq_ignore_ascii_case("steam"),
            _ => {}
        }
    }
    let secret = secret.ok_or(OtpError::Uri)?;
    let (label_issuer, account) = split_label(&label);
    let issuer = issuer.or(label_issuer);
    let params = if steam {
        OtpParams::steam(&secret)?
    } else {
        let kind = match kind.as_str() {
            "totp" => OtpKind::Totp {
                period_s: period.unwrap_or(DEFAULT_PERIOD_S),
            },
            "hotp" => OtpKind::Hotp {
                counter: counter.ok_or(OtpError::Uri)?,
            },
            _ => return Err(OtpError::Uri),
        };
        OtpParams::new(&secret, kind, algorithm, digits.unwrap_or(DEFAULT_DIGITS))?
    };
    Ok(params.with_label(issuer, account))
}

pub fn encode(params: &OtpParams) -> String {
    let kind = match (params.is_steam(), params.kind()) {
        (true, _) => "steam",
        (false, OtpKind::Totp { .. }) => "totp",
        (false, OtpKind::Hotp { .. }) => "hotp",
    };
    let label = match (params.issuer(), params.account()) {
        (Some(issuer), Some(account)) => {
            format!("{}:{}", percent_encode(issuer), percent_encode(account))
        }
        (Some(issuer), None) => percent_encode(issuer),
        (None, Some(account)) => percent_encode(account),
        (None, None) => String::new(),
    };
    let mut query = vec![format!(
        "secret={}",
        base32::encode(params.expose_secret()).trim_end_matches('=')
    )];
    if let Some(issuer) = params.issuer() {
        query.push(format!("issuer={}", percent_encode(issuer)));
    }
    if params.algorithm() != OtpAlg::Sha1 {
        query.push(format!("algorithm={}", params.algorithm().name()));
    }
    if params.digits() != DEFAULT_DIGITS {
        query.push(format!("digits={}", params.digits()));
    }
    match params.kind() {
        OtpKind::Totp { period_s } if period_s != DEFAULT_PERIOD_S => {
            query.push(format!("period={period_s}"));
        }
        OtpKind::Totp { .. } => {}
        OtpKind::Hotp { counter } => query.push(format!("counter={counter}")),
    }
    format!("otpauth://{kind}/{label}?{}", query.join("&"))
}

fn strip_scheme<'a>(text: &'a str, scheme: &str) -> Option<&'a str> {
    let (head, rest) = text.split_once(':')?;
    head.eq_ignore_ascii_case(scheme).then_some(rest)
}

fn split_label(label: &str) -> (Option<String>, Option<String>) {
    match label.split_once(':') {
        Some((issuer, account)) => (non_empty(issuer), non_empty(account)),
        None => (None, non_empty(label)),
    }
}

fn non_empty(text: &str) -> Option<String> {
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn percent_decode(text: &str) -> Result<String, OtpError> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        if byte == b'%' {
            let pair = bytes.get(i + 1..i + 3).ok_or(OtpError::Uri)?;
            let hex = std::str::from_utf8(pair).map_err(|_| OtpError::Uri)?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| OtpError::Uri)?);
            i += 3;
        } else {
            out.push(byte);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| OtpError::Uri)
}

fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(hex_digit(byte >> 4));
            out.push(hex_digit(byte & 0x0f));
        }
    }
    out
}

fn hex_digit(nibble: u8) -> char {
    char::from_digit(u32::from(nibble), 16).map_or('0', |c| c.to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_google_authenticator_example() {
        let uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        let params = parse(uri).unwrap();
        assert_eq!(params.expose_secret(), b"Hello!\xde\xad\xbe\xef");
        assert_eq!(params.issuer(), Some("Example"));
        assert_eq!(params.account(), Some("alice@google.com"));
        assert_eq!(params.algorithm(), OtpAlg::Sha1);
        assert_eq!(params.digits(), 6);
        assert_eq!(params.kind(), OtpKind::Totp { period_s: 30 });
    }

    #[test]
    fn parses_all_parameters() {
        let uri = "otpauth://totp/ACME%20Co:john.doe%40email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA512&digits=8&period=45";
        let params = parse(uri).unwrap();
        assert_eq!(params.issuer(), Some("ACME Co"));
        assert_eq!(params.account(), Some("john.doe@email.com"));
        assert_eq!(params.algorithm(), OtpAlg::Sha512);
        assert_eq!(params.digits(), 8);
        assert_eq!(params.kind(), OtpKind::Totp { period_s: 45 });
    }

    #[test]
    fn parses_hotp_with_counter() {
        let params =
            parse("otpauth://hotp/svc:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=7")
                .unwrap();
        assert_eq!(params.kind(), OtpKind::Hotp { counter: 7 });
        assert!(parse("otpauth://hotp/svc:me?secret=GEZDGNBVGY3TQOJQ").is_err());
    }

    #[test]
    fn parses_steam_forms() {
        for uri in [
            "steam://GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "otpauth://steam/Steam:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Steam",
            "otpauth://totp/Steam:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&encoder=steam",
        ] {
            let params = parse(uri).unwrap();
            assert!(params.is_steam(), "{uri}");
            assert_eq!(params.digits(), 5);
            assert_eq!(params.expose_secret(), b"12345678901234567890");
        }
    }

    #[test]
    fn rejects_malformed_uris() {
        for uri in [
            "",
            "https://example.com/?secret=ABCDEFGH",
            "otpauth://totp/x",
            "otpauth://totp/x?secret=!!!",
            "otpauth://other/x?secret=ABCDEFGH",
            "otpauth://totp/x?secret=ABCDEFGH&digits=4",
            "otpauth://totp/x?secret=ABCDEFGH&algorithm=MD5",
            "otpauth://totp/x?secret=ABCDEFGH&period=0",
            "otpauth://totp/%zz?secret=ABCDEFGH",
        ] {
            assert!(parse(uri).is_err(), "{uri}");
        }
    }

    #[test]
    fn encode_round_trips() {
        let originals = [
            "otpauth://totp/ACME%20Co:john%40email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=45",
            "otpauth://hotp/me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=3",
            "otpauth://steam/Steam:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Steam",
        ];
        for original in originals {
            let first = parse(original).unwrap();
            let second = parse(&encode(&first)).unwrap();
            assert_eq!(first.expose_secret(), second.expose_secret());
            assert_eq!(first.kind(), second.kind());
            assert_eq!(first.digits(), second.digits());
            assert_eq!(first.algorithm(), second.algorithm());
            assert_eq!(first.issuer(), second.issuer());
            assert_eq!(first.account(), second.account());
            assert_eq!(first.is_steam(), second.is_steam());
        }
    }
}
