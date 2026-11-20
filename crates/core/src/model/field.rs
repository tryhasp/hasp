use std::fmt;

use secrecy::{ExposeSecret, SecretString};

use crate::model::ModelError;
use crate::model::id::Id;
use crate::otp::OtpParams;

const MAX_LABEL_BYTES: usize = 256;
const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_FIELDS_PER_SECTION: usize = 256;
const MIN_YEAR: u16 = 1;
const MAX_YEAR: u16 = 9999;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FieldKind {
    Text,
    Concealed,
    Url,
    Email,
    Phone,
    Date,
    MonthYear,
    Otp,
    Address,
    Menu,
    SecurityQuestion,
    SignInWith,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    Username,
    Password,
    Totp,
    NewPassword,
    CardHolder,
    CardNumber,
    CardExpiry,
    CardExpiryMonth,
    CardExpiryYear,
    CardCvc,
    CardType,
    Name,
    GivenName,
    FamilyName,
    Email,
    Phone,
    Birthday,
    StreetAddress,
    AddressLine1,
    AddressLine2,
    City,
    Region,
    PostalCode,
    Country,
    Organization,
    ApiKey,
    Hostname,
    SshPrivateKey,
    SshPublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    year: u16,
    month: u8,
    day: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MonthYear {
    year: u16,
    month: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Address {
    pub street: String,
    pub city: String,
    pub region: String,
    pub postal_code: String,
    pub country: String,
}

pub enum FieldValue {
    Text(String),
    Concealed(SecretString),
    Url(String),
    Email(String),
    Phone(String),
    Date(Date),
    MonthYear(MonthYear),
    Otp(OtpParams),
    Address(Address),
    Menu(String),
    SecurityQuestion {
        question: String,
        answer: SecretString,
    },
    SignInWith(String),
}

#[derive(Debug)]
pub struct Field {
    id: Id,
    label: String,
    value: FieldValue,
    purpose: Option<Purpose>,
    concealed: bool,
    expires_alert: bool,
}

#[derive(Debug)]
pub struct Section {
    id: Id,
    title: String,
    fields: Vec<Field>,
}

impl Purpose {
    pub fn accepts(self, kind: FieldKind) -> bool {
        use FieldKind as K;
        match self {
            Self::Username
            | Self::Name
            | Self::GivenName
            | Self::FamilyName
            | Self::Organization => {
                matches!(kind, K::Text | K::Email | K::Concealed)
            }
            Self::Password | Self::NewPassword | Self::CardCvc | Self::ApiKey => {
                matches!(kind, K::Concealed | K::Text)
            }
            Self::Totp => kind == K::Otp,
            Self::CardHolder | Self::CardType | Self::CardNumber => {
                matches!(kind, K::Text | K::Concealed | K::Menu)
            }
            Self::CardExpiry => matches!(kind, K::MonthYear | K::Text),
            Self::CardExpiryMonth | Self::CardExpiryYear => matches!(kind, K::Text | K::Menu),
            Self::Email => matches!(kind, K::Email | K::Text),
            Self::Phone => matches!(kind, K::Phone | K::Text),
            Self::Birthday => matches!(kind, K::Date | K::Text),
            Self::StreetAddress => matches!(kind, K::Address | K::Text),
            Self::AddressLine1
            | Self::AddressLine2
            | Self::City
            | Self::Region
            | Self::PostalCode => {
                matches!(kind, K::Text)
            }
            Self::Country => matches!(kind, K::Text | K::Menu),
            Self::Hostname => matches!(kind, K::Text | K::Url),
            Self::SshPrivateKey => matches!(kind, K::Concealed | K::Text),
            Self::SshPublicKey => kind == K::Text,
        }
    }
}

impl Date {
    pub fn new(year: u16, month: u8, day: u8) -> Result<Self, ModelError> {
        if !(MIN_YEAR..=MAX_YEAR).contains(&year)
            || !(1..=days_in_month(year, month)).contains(&day)
        {
            return Err(ModelError::Value("date"));
        }
        Ok(Self { year, month, day })
    }

    pub fn year(self) -> u16 {
        self.year
    }

    pub fn month(self) -> u8 {
        self.month
    }

    pub fn day(self) -> u8 {
        self.day
    }
}

impl MonthYear {
    pub fn new(year: u16, month: u8) -> Result<Self, ModelError> {
        if !(MIN_YEAR..=MAX_YEAR).contains(&year) || !(1..=12).contains(&month) {
            return Err(ModelError::Value("month and year"));
        }
        Ok(Self { year, month })
    }

    pub fn year(self) -> u16 {
        self.year
    }

    pub fn month(self) -> u8 {
        self.month
    }
}

fn days_in_month(year: u16, month: u8) -> u8 {
    let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    }
}

impl FieldValue {
    pub fn kind(&self) -> FieldKind {
        match self {
            Self::Text(_) => FieldKind::Text,
            Self::Concealed(_) => FieldKind::Concealed,
            Self::Url(_) => FieldKind::Url,
            Self::Email(_) => FieldKind::Email,
            Self::Phone(_) => FieldKind::Phone,
            Self::Date(_) => FieldKind::Date,
            Self::MonthYear(_) => FieldKind::MonthYear,
            Self::Otp(_) => FieldKind::Otp,
            Self::Address(_) => FieldKind::Address,
            Self::Menu(_) => FieldKind::Menu,
            Self::SecurityQuestion { .. } => FieldKind::SecurityQuestion,
            Self::SignInWith(_) => FieldKind::SignInWith,
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Text(v)
            | Self::Url(v)
            | Self::Email(v)
            | Self::Phone(v)
            | Self::Menu(v)
            | Self::SignInWith(v) => v.is_empty(),
            Self::Concealed(v) => v.expose_secret().is_empty(),
            Self::SecurityQuestion { question, answer } => {
                question.is_empty() && answer.expose_secret().is_empty()
            }
            Self::Address(a) => a == &Address::default(),
            Self::Date(_) | Self::MonthYear(_) | Self::Otp(_) => false,
        }
    }

    fn validate(&self) -> Result<(), ModelError> {
        let too_long = |text: &str| text.len() > MAX_TEXT_BYTES;
        let bad = match self {
            Self::Text(v)
            | Self::Url(v)
            | Self::Email(v)
            | Self::Phone(v)
            | Self::Menu(v)
            | Self::SignInWith(v) => too_long(v),
            Self::Concealed(v) => v.expose_secret().len() > MAX_TEXT_BYTES,
            Self::SecurityQuestion { question, answer } => {
                too_long(question) || answer.expose_secret().len() > MAX_TEXT_BYTES
            }
            Self::Address(a) => [&a.street, &a.city, &a.region, &a.postal_code, &a.country]
                .iter()
                .any(|v| too_long(v)),
            Self::Date(_) | Self::MonthYear(_) | Self::Otp(_) => false,
        };
        if bad {
            Err(ModelError::Value("value too long"))
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldValue::{:?}(..)", self.kind())
    }
}

impl Field {
    pub fn new(id: Id, label: &str, value: FieldValue) -> Result<Self, ModelError> {
        if label.len() > MAX_LABEL_BYTES {
            return Err(ModelError::Value("label too long"));
        }
        value.validate()?;
        let concealed = matches!(
            value.kind(),
            FieldKind::Concealed | FieldKind::Otp | FieldKind::SecurityQuestion
        );
        Ok(Self {
            id,
            label: label.to_owned(),
            value,
            purpose: None,
            concealed,
            expires_alert: false,
        })
    }

    pub fn with_purpose(mut self, purpose: Purpose) -> Result<Self, ModelError> {
        if !purpose.accepts(self.value.kind()) {
            return Err(ModelError::Value("purpose does not fit the field kind"));
        }
        self.purpose = Some(purpose);
        Ok(self)
    }

    #[must_use]
    pub fn with_concealed(mut self, concealed: bool) -> Self {
        self.concealed = concealed;
        self
    }

    #[must_use]
    pub fn with_expires_alert(mut self, expires_alert: bool) -> Self {
        self.expires_alert = expires_alert;
        self
    }

    pub fn id(&self) -> Id {
        self.id
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn kind(&self) -> FieldKind {
        self.value.kind()
    }

    pub fn value(&self) -> &FieldValue {
        &self.value
    }

    pub fn purpose(&self) -> Option<Purpose> {
        self.purpose
    }

    pub fn is_concealed(&self) -> bool {
        self.concealed
    }

    pub fn expires_alert(&self) -> bool {
        self.expires_alert
    }
}

impl Section {
    pub fn new(id: Id, title: &str, fields: Vec<Field>) -> Result<Self, ModelError> {
        if title.len() > MAX_LABEL_BYTES {
            return Err(ModelError::Value("section title too long"));
        }
        if fields.len() > MAX_FIELDS_PER_SECTION {
            return Err(ModelError::Value("too many fields"));
        }
        Ok(Self {
            id,
            title: title.to_owned(),
            fields,
        })
    }

    pub fn id(&self) -> Id {
        self.id
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn fields(&self) -> &[Field] {
        &self.fields
    }

    pub fn into_fields(self) -> Vec<Field> {
        self.fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otp::{OtpAlg, OtpKind};

    fn id(n: u8) -> Id {
        Id::from_bytes([n; 16])
    }

    #[test]
    fn dates_are_validated_including_leap_years() {
        assert!(Date::new(2024, 2, 29).is_ok());
        assert!(Date::new(2023, 2, 29).is_err());
        assert!(Date::new(1900, 2, 29).is_err());
        assert!(Date::new(2000, 2, 29).is_ok());
        assert!(Date::new(2024, 13, 1).is_err());
        assert!(Date::new(2024, 4, 31).is_err());
        assert!(Date::new(0, 1, 1).is_err());
        assert!(Date::new(2024, 12, 0).is_err());
        assert_eq!(Date::new(2024, 12, 31).unwrap().day(), 31);
    }

    #[test]
    fn month_year_rejects_invalid_months() {
        assert!(MonthYear::new(2030, 12).is_ok());
        assert!(MonthYear::new(2030, 0).is_err());
        assert!(MonthYear::new(2030, 13).is_err());
        assert!(MonthYear::new(2030, 1).unwrap() < MonthYear::new(2030, 2).unwrap());
    }

    #[test]
    fn kind_follows_the_value_for_every_variant() {
        let otp = OtpParams::new(b"k", OtpKind::Totp { period_s: 30 }, OtpAlg::Sha1, 6).unwrap();
        let cases = [
            (FieldValue::Text(String::new()), FieldKind::Text),
            (
                FieldValue::Concealed(SecretString::from("x")),
                FieldKind::Concealed,
            ),
            (FieldValue::Url(String::new()), FieldKind::Url),
            (FieldValue::Email(String::new()), FieldKind::Email),
            (FieldValue::Phone(String::new()), FieldKind::Phone),
            (
                FieldValue::Date(Date::new(2024, 1, 1).unwrap()),
                FieldKind::Date,
            ),
            (
                FieldValue::MonthYear(MonthYear::new(2030, 1).unwrap()),
                FieldKind::MonthYear,
            ),
            (FieldValue::Otp(otp), FieldKind::Otp),
            (FieldValue::Address(Address::default()), FieldKind::Address),
            (FieldValue::Menu(String::new()), FieldKind::Menu),
            (
                FieldValue::SecurityQuestion {
                    question: String::new(),
                    answer: SecretString::from(""),
                },
                FieldKind::SecurityQuestion,
            ),
            (
                FieldValue::SignInWith("kakao".to_owned()),
                FieldKind::SignInWith,
            ),
        ];
        for (value, kind) in cases {
            assert_eq!(value.kind(), kind);
        }
    }

    #[test]
    fn purposes_must_fit_the_kind() {
        let password = Field::new(
            id(1),
            "password",
            FieldValue::Concealed(SecretString::from("pw")),
        )
        .unwrap();
        assert!(password.with_purpose(Purpose::Password).is_ok());
        let url = Field::new(id(2), "site", FieldValue::Url(String::new())).unwrap();
        assert!(url.with_purpose(Purpose::Password).is_err());
        let text = Field::new(id(3), "code", FieldValue::Text(String::new())).unwrap();
        assert!(text.with_purpose(Purpose::Totp).is_err());
    }

    #[test]
    fn secret_kinds_default_to_concealed() {
        let secret =
            Field::new(id(1), "p", FieldValue::Concealed(SecretString::from("pw"))).unwrap();
        assert!(secret.is_concealed());
        let plain = Field::new(id(2), "u", FieldValue::Text("alice".to_owned())).unwrap();
        assert!(!plain.is_concealed());
        assert!(plain.with_concealed(true).is_concealed());
    }

    #[test]
    fn debug_never_prints_values() {
        let field = Field::new(
            id(1),
            "card",
            FieldValue::Text("4111111111111111".to_owned()),
        )
        .unwrap()
        .with_concealed(true);
        assert!(!format!("{field:?}").contains("4111"));
        let secret = Field::new(
            id(2),
            "p",
            FieldValue::Concealed(SecretString::from("hunter2")),
        )
        .unwrap();
        assert!(!format!("{secret:?}").contains("hunter2"));
    }

    #[test]
    fn rejects_oversized_values_labels_and_sections() {
        assert!(Field::new(id(1), &"l".repeat(257), FieldValue::Text(String::new())).is_err());
        assert!(Field::new(id(1), "l", FieldValue::Text("x".repeat(64 * 1024 + 1))).is_err());
        assert!(Section::new(id(1), &"t".repeat(257), Vec::new()).is_err());
        let fields: Vec<Field> = (0..257)
            .map(|_| Field::new(id(1), "f", FieldValue::Text(String::new())).unwrap())
            .collect();
        assert!(Section::new(id(1), "s", fields).is_err());
    }

    #[test]
    fn emptiness_covers_every_variant() {
        assert!(FieldValue::Text(String::new()).is_empty());
        assert!(!FieldValue::Text("x".to_owned()).is_empty());
        assert!(FieldValue::Concealed(SecretString::from("")).is_empty());
        assert!(FieldValue::Address(Address::default()).is_empty());
        assert!(!FieldValue::Date(Date::new(2024, 1, 1).unwrap()).is_empty());
    }
}
