use hasp_crypto::{SecretBytes, SecretKey};
use zeroize::Zeroizing;

use crate::ProtoError;
use crate::cbor::{Reader, Wire, Writer};
use crate::id::{AccountId, AttId, Hash32};

pub const PAYLOAD_VERSION: u32 = 1;
pub const MAX_NOTES: usize = 256 * 1024;
pub const MAX_SECRET: usize = 64 * 1024;
pub const NONCE_PREFIX_LEN: usize = 15;
const OVERVIEW_ENTRIES: usize = 11;
const DETAILS_ENTRIES: usize = 8;

macro_rules! coded {
    ($(#[$meta:meta])* $name:ident { $($variant:ident = $code:literal),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $name {
            $($variant),*
        }

        impl $name {
            fn code(self) -> u64 {
                match self {
                    $(Self::$variant => $code),*
                }
            }

            fn from_code(code: u64) -> Result<Self, ProtoError> {
                match code {
                    $($code => Ok(Self::$variant),)*
                    _ => Err(ProtoError::Format),
                }
            }
        }

        impl Wire for $name {
            fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
                w.uint(self.code())
            }

            fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
                Self::from_code(r.uint()?.get())
            }
        }
    };
}

coded!(FieldKind {
    Text = 0,
    Concealed = 1,
    Url = 2,
    Email = 3,
    Phone = 4,
    Date = 5,
    MonthYear = 6,
    Otp = 7,
    Address = 8,
    Menu = 9,
    SecurityQuestion = 10,
    SignInWith = 11,
});

coded!(Purpose {
    Username = 0,
    Password = 1,
    Totp = 2,
    NewPassword = 3,
    CardHolder = 4,
    CardNumber = 5,
    CardExpiry = 6,
    CardExpiryMonth = 7,
    CardExpiryYear = 8,
    CardCvc = 9,
    CardType = 10,
    Name = 11,
    GivenName = 12,
    FamilyName = 13,
    Email = 14,
    Phone = 15,
    Birthday = 16,
    StreetAddress = 17,
    AddressLine1 = 18,
    AddressLine2 = 19,
    City = 20,
    Region = 21,
    PostalCode = 22,
    Country = 23,
    Organization = 24,
    ApiKey = 25,
    Hostname = 26,
    SshPrivateKey = 27,
    SshPublicKey = 28,
});

coded!(OtpAlgorithm {
    Sha1 = 0,
    Sha256 = 1,
    Sha512 = 2,
});

coded!(MatchMode {
    Domain = 0,
    Host = 1,
    Never = 2,
});

coded!(UrlKind {
    Website = 0,
    SignIn = 1,
    Api = 2,
});

coded!(AppPlatform {
    Ios = 0,
    Android = 1,
    Macos = 2,
    Windows = 3,
});

coded!(AssocSource {
    User = 0,
    Dataset = 1,
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemState {
    Active,
    Archived { at: u64 },
    Trashed { at: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Overview {
    pub kind: String,
    pub title: String,
    pub subtitle: String,
    pub tags: Vec<String>,
    pub favourite: Option<u32>,
    pub state: ItemState,
    pub client_modified: u64,
    pub created: u64,
    pub expires_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtpMode {
    Totp { period_s: u32 },
    Hotp { counter: u64 },
}

pub struct Otp {
    pub secret: SecretBytes,
    pub algorithm: OtpAlgorithm,
    pub digits: u8,
    pub mode: OtpMode,
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub steam: bool,
}

pub struct Address {
    pub street: String,
    pub city: String,
    pub region: String,
    pub postal_code: String,
    pub country: String,
}

pub enum Value {
    Text(String),
    Url(String),
    Email(String),
    Phone(String),
    Menu(String),
    SignInWith(String),
    Concealed(SecretBytes),
    Date {
        year: u16,
        month: u8,
        day: u8,
    },
    MonthYear {
        year: u16,
        month: u8,
    },
    Otp(Otp),
    Address(Address),
    SecurityQuestion {
        question: String,
        answer: SecretBytes,
    },
}

impl Value {
    pub fn kind(&self) -> FieldKind {
        match self {
            Self::Text(_) => FieldKind::Text,
            Self::Url(_) => FieldKind::Url,
            Self::Email(_) => FieldKind::Email,
            Self::Phone(_) => FieldKind::Phone,
            Self::Menu(_) => FieldKind::Menu,
            Self::SignInWith(_) => FieldKind::SignInWith,
            Self::Concealed(_) => FieldKind::Concealed,
            Self::Date { .. } => FieldKind::Date,
            Self::MonthYear { .. } => FieldKind::MonthYear,
            Self::Otp(_) => FieldKind::Otp,
            Self::Address(_) => FieldKind::Address,
            Self::SecurityQuestion { .. } => FieldKind::SecurityQuestion,
        }
    }
}

pub struct Field {
    pub id: [u8; 16],
    pub label: String,
    pub value: Value,
    pub purpose: Option<Purpose>,
    pub concealed: bool,
    pub expires_alert: bool,
}

pub struct Section {
    pub id: [u8; 16],
    pub title: String,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlEntry {
    pub id: [u8; 16],
    pub url: String,
    pub mode: MatchMode,
    pub confirmed_hosts: Vec<String>,
    pub kind: UrlKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppAssociation {
    pub platform: AppPlatform,
    pub id: String,
    pub cert_sha256: Option<[u8; 32]>,
    pub source: AssocSource,
}

pub struct Passkey {
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub display_name: String,
    pub algorithm: i32,
    pub private_key: SecretBytes,
    pub created: u64,
    pub last_used: Option<u64>,
    pub backup_eligible: bool,
    pub backed_up: bool,
}

pub struct AttachmentDescriptor {
    pub att_id: AttId,
    pub file_key: SecretKey,
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
    pub size: u64,
    pub chunk_size: u32,
    pub name: String,
    pub mime: String,
}

pub struct PasswordHistoryEntry {
    pub value: SecretBytes,
    pub replaced_at: u64,
    pub field: [u8; 16],
}

pub struct Details {
    pub sections: Vec<Section>,
    pub notes: Option<String>,
    pub urls: Vec<UrlEntry>,
    pub apps: Vec<AppAssociation>,
    pub passkeys: Vec<Passkey>,
    pub attachments: Vec<AttachmentDescriptor>,
    pub history: Vec<PasswordHistoryEntry>,
}

macro_rules! redacted_debug {
    ($($name:ident),*) => {
        $(
            impl core::fmt::Debug for $name {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.write_str(concat!(stringify!($name), "(..)"))
                }
            }
        )*
    };
}

redacted_debug!(
    Otp,
    Address,
    Value,
    Field,
    Section,
    Passkey,
    AttachmentDescriptor,
    PasswordHistoryEntry,
    Details
);

pub fn encode_overview(overview: &Overview) -> Result<Zeroizing<Vec<u8>>, ProtoError> {
    overview.to_cbor_secret()
}

pub fn decode_overview(bytes: &[u8]) -> Result<Overview, ProtoError> {
    Overview::from_cbor(bytes)
}

pub fn encode_details(details: &Details) -> Result<Zeroizing<Vec<u8>>, ProtoError> {
    details.to_cbor_secret()
}

pub fn decode_details(bytes: &[u8]) -> Result<Details, ProtoError> {
    if bytes.len() > crate::MAX_RECORD {
        return Err(ProtoError::Format);
    }
    let mut r = Reader::new(bytes);
    let details = Details::decode(&mut r)?;
    r.finish()?;
    let again = encode_details(&details)?;
    if again.as_slice() != bytes {
        return Err(ProtoError::Format);
    }
    Ok(details)
}

impl Wire for Overview {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.map(OVERVIEW_ENTRIES)?;
        w.key(0)?;
        w.uint(u64::from(PAYLOAD_VERSION))?;
        w.key(1)?;
        w.text(&self.kind)?;
        w.key(2)?;
        w.text(&self.title)?;
        w.key(3)?;
        w.text(&self.subtitle)?;
        w.key(4)?;
        w.array(self.tags.len())?;
        for tag in &self.tags {
            w.text(tag)?;
        }
        w.key(5)?;
        opt_uint(w, self.favourite.map(u64::from))?;
        let (state, at) = match self.state {
            ItemState::Active => (0, None),
            ItemState::Archived { at } => (1, Some(at)),
            ItemState::Trashed { at } => (2, Some(at)),
        };
        w.key(6)?;
        w.uint(state)?;
        w.key(7)?;
        opt_uint(w, at)?;
        w.key(8)?;
        w.uint(self.client_modified)?;
        w.key(9)?;
        w.uint(self.created)?;
        w.key(10)?;
        opt_uint(w, self.expires_at)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        r.map(|r, n| {
            expect_count(n, OVERVIEW_ENTRIES)?;
            r.key(0)?;
            check_version(r)?;
            r.key(1)?;
            let kind = r.text()?.to_owned();
            r.key(2)?;
            let title = r.text()?.to_owned();
            r.key(3)?;
            let subtitle = r.text()?.to_owned();
            r.key(4)?;
            let tags = list(r, |r| Ok(r.text()?.to_owned()))?;
            r.key(5)?;
            let favourite = opt_uint_read(r)?
                .map(|f| u32::try_from(f).map_err(|_| ProtoError::Format))
                .transpose()?;
            r.key(6)?;
            let state = r.uint()?.get();
            r.key(7)?;
            let at = opt_uint_read(r)?;
            let state = match (state, at) {
                (0, None) => ItemState::Active,
                (1, Some(at)) => ItemState::Archived { at },
                (2, Some(at)) => ItemState::Trashed { at },
                _ => return Err(ProtoError::Format),
            };
            r.key(8)?;
            let client_modified = r.uint()?.get();
            r.key(9)?;
            let created = r.uint()?.get();
            r.key(10)?;
            let expires_at = opt_uint_read(r)?;
            Ok(Self {
                kind,
                title,
                subtitle,
                tags,
                favourite,
                state,
                client_modified,
                created,
                expires_at,
            })
        })
    }
}

impl Wire for Details {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.map(DETAILS_ENTRIES)?;
        w.key(0)?;
        w.uint(u64::from(PAYLOAD_VERSION))?;
        w.key(1)?;
        w.array(self.sections.len())?;
        for section in &self.sections {
            encode_section(w, section)?;
        }
        w.key(2)?;
        match &self.notes {
            Some(notes) => long_text(w, notes, MAX_NOTES)?,
            None => w.null(),
        }
        w.key(3)?;
        w.array(self.urls.len())?;
        for url in &self.urls {
            encode_url(w, url)?;
        }
        w.key(4)?;
        w.array(self.apps.len())?;
        for app in &self.apps {
            encode_app(w, app)?;
        }
        w.key(5)?;
        w.array(self.passkeys.len())?;
        for passkey in &self.passkeys {
            encode_passkey(w, passkey)?;
        }
        w.key(6)?;
        w.array(self.attachments.len())?;
        for attachment in &self.attachments {
            encode_attachment(w, attachment)?;
        }
        w.key(7)?;
        w.array(self.history.len())?;
        for entry in &self.history {
            w.map(3)?;
            w.key(0)?;
            secret_bytes(w, &entry.value)?;
            w.key(1)?;
            w.uint(entry.replaced_at)?;
            w.key(2)?;
            w.bytes(&entry.field)?;
        }
        Ok(())
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        r.map(|r, n| {
            expect_count(n, DETAILS_ENTRIES)?;
            r.key(0)?;
            check_version(r)?;
            r.key(1)?;
            let sections = list(r, decode_section)?;
            r.key(2)?;
            let notes = if r.is_null() {
                r.null()?;
                None
            } else {
                Some(long_text_read(r, MAX_NOTES)?)
            };
            r.key(3)?;
            let urls = list(r, decode_url)?;
            r.key(4)?;
            let apps = list(r, decode_app)?;
            r.key(5)?;
            let passkeys = list(r, decode_passkey)?;
            r.key(6)?;
            let attachments = list(r, decode_attachment)?;
            r.key(7)?;
            let history = list(r, |r| {
                r.map(|r, n| {
                    expect_count(n, 3)?;
                    r.key(0)?;
                    let value = secret_bytes_read(r)?;
                    r.key(1)?;
                    let replaced_at = r.uint()?.get();
                    r.key(2)?;
                    let field = r.fixed()?;
                    Ok(PasswordHistoryEntry {
                        value,
                        replaced_at,
                        field,
                    })
                })
            })?;
            Ok(Self {
                sections,
                notes,
                urls,
                apps,
                passkeys,
                attachments,
                history,
            })
        })
    }
}

mod entries;
mod fields;
mod hidden;
mod primitives;
#[cfg(test)]
mod tests;

use entries::{
    decode_app, decode_attachment, decode_passkey, decode_url, encode_app, encode_attachment,
    encode_passkey, encode_url,
};
use fields::{decode_section, encode_section};
pub use hidden::*;
use primitives::{
    check_version, expect_count, list, long_text, long_text_read, narrow, opt_text, opt_text_read,
    opt_uint, opt_uint_read, secret_bytes, secret_bytes_read, unzigzag, zigzag,
};
