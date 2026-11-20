use crate::error::CliError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Attribute {
    Value,
    Otp,
    Type,
    Id,
    Purpose,
    Content,
    Size,
    Name,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Reference {
    pub(crate) vault: String,
    pub(crate) item: String,
    pub(crate) section: Option<String>,
    pub(crate) field: String,
    pub(crate) attribute: Attribute,
}

const SCHEME: &str = "hasp://";

fn decode(segment: &str) -> String {
    segment
        .replace("%2F", "/")
        .replace("%2f", "/")
        .replace("%25", "%")
}

fn attribute(name: &str) -> Result<Attribute, CliError> {
    Ok(match name {
        "value" => Attribute::Value,
        "otp" => Attribute::Otp,
        "type" => Attribute::Type,
        "id" => Attribute::Id,
        "purpose" => Attribute::Purpose,
        "content" => Attribute::Content,
        "size" => Attribute::Size,
        "name" => Attribute::Name,
        other => return Err(CliError::usage(format!("unknown attribute {other}"))),
    })
}

impl Reference {
    pub(crate) fn parse(text: &str) -> Result<Self, CliError> {
        let rest = text
            .strip_prefix(SCHEME)
            .ok_or_else(|| CliError::usage("a secret reference starts with hasp://"))?;
        let (path, query) = match rest.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (rest, None),
        };
        let segments: Vec<String> = path.split('/').map(decode).collect();
        if segments.iter().any(String::is_empty) {
            return Err(CliError::usage("a reference has no empty segments"));
        }
        let (vault, item, section, field) = match segments.as_slice() {
            [vault, item, field] => (vault, item, None, field),
            [vault, item, section, field] => (vault, item, Some(section.clone()), field),
            _ => {
                return Err(CliError::usage(
                    "a reference is hasp://<vault>/<item>/[<section>/]<field>",
                ));
            }
        };
        let attribute = match query {
            None => Attribute::Value,
            Some(query) => match query.split_once('=') {
                Some(("attribute", name)) => attribute(name)?,
                _ => return Err(CliError::usage("the only query is ?attribute=<name>")),
            },
        };
        Ok(Self {
            vault: vault.clone(),
            item: item.clone(),
            section,
            field: field.clone(),
            attribute,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_field_reference() {
        let reference = Reference::parse("hasp://Private/GitHub/password").unwrap();
        assert_eq!(reference.vault, "Private");
        assert_eq!(reference.item, "GitHub");
        assert_eq!(reference.section, None);
        assert_eq!(reference.field, "password");
        assert_eq!(reference.attribute, Attribute::Value);
    }

    #[test]
    fn parses_section_and_attribute() {
        let reference = Reference::parse("hasp://v/i/Login/totp?attribute=otp").unwrap();
        assert_eq!(reference.section.as_deref(), Some("Login"));
        assert_eq!(reference.attribute, Attribute::Otp);
    }

    #[test]
    fn escaped_slash_stays_in_the_name() {
        let reference = Reference::parse("hasp://v/a%2Fb/password").unwrap();
        assert_eq!(reference.item, "a/b");
    }

    #[test]
    fn rejects_other_schemes_and_bad_shapes() {
        assert!(Reference::parse("https://v/i/f").is_err());
        assert!(Reference::parse("hasp://v/i").is_err());
        assert!(Reference::parse("hasp://v//f").is_err());
        assert!(Reference::parse("hasp://v/i/f?attribute=nope").is_err());
    }
}
