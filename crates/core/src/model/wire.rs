use hasp_crypto::SecretBytes;
use hasp_proto::AttId;
use hasp_proto::ProtoError;
use hasp_proto::payload as p;
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use zeroize::Zeroizing;

use crate::model::field::{
    Address, Date, Field, FieldKind, FieldValue, MonthYear, Purpose, Section,
};
use crate::model::id::Id;
use crate::model::item::{
    AppAssociation, AppPlatform, AssocSource, AttachmentDesc, Details, Item, ItemParts, ItemState,
    Passkey, PasswordHistoryEntry,
};
use crate::model::tag::Tag;
use crate::model::url::{MatchMode, UrlEntry, UrlKind};
use crate::otp::{OtpAlg, OtpKind, OtpParams};

macro_rules! enum_from {
    ($from:ident, $model:ty, $wire:ty, { $($variant:ident),* $(,)? }) => {
        fn $from(value: $wire) -> $model {
            match value {
                $(<$wire>::$variant => <$model>::$variant),*
            }
        }
    };
}

macro_rules! enum_map {
    ($to:ident, $from:ident, $model:ty, $wire:ty, { $($variant:ident),* $(,)? }) => {
        fn $to(value: $model) -> $wire {
            match value {
                $(<$model>::$variant => <$wire>::$variant),*
            }
        }

        fn $from(value: $wire) -> $model {
            match value {
                $(<$wire>::$variant => <$model>::$variant),*
            }
        }
    };
}

enum_from!(kind_from, FieldKind, p::FieldKind, {
    Text, Concealed, Url, Email, Phone, Date, MonthYear, Otp, Address, Menu, SecurityQuestion,
    SignInWith
});

enum_map!(purpose_to, purpose_from, Purpose, p::Purpose, {
    Username, Password, Totp, NewPassword, CardHolder, CardNumber, CardExpiry, CardExpiryMonth,
    CardExpiryYear, CardCvc, CardType, Name, GivenName, FamilyName, Email, Phone, Birthday,
    StreetAddress, AddressLine1, AddressLine2, City, Region, PostalCode, Country, Organization,
    ApiKey, Hostname, SshPrivateKey, SshPublicKey
});

enum_map!(alg_to, alg_from, OtpAlg, p::OtpAlgorithm, { Sha1, Sha256, Sha512 });
enum_map!(mode_to, mode_from, MatchMode, p::MatchMode, { Domain, Host, Never });
enum_map!(url_kind_to, url_kind_from, UrlKind, p::UrlKind, { Website, SignIn, Api });
enum_map!(platform_to, platform_from, AppPlatform, p::AppPlatform, {
    Ios, Android, Macos, Windows
});
enum_map!(source_to, source_from, AssocSource, p::AssocSource, { User, Dataset });

type Bytes = Zeroizing<Vec<u8>>;

pub fn encode_item(item: &Item) -> Result<(Bytes, Bytes), ProtoError> {
    let overview = overview_to(item);
    let details = details_to(item.details())?;
    Ok((p::encode_overview(&overview)?, p::encode_details(&details)?))
}

pub fn decode_item(overview: &[u8], details: &[u8]) -> Result<Item, ProtoError> {
    let overview = p::decode_overview(overview)?;
    let details = details_from(p::decode_details(details)?)?;
    let tags = overview
        .tags
        .iter()
        .map(|tag| Tag::new(tag).map_err(|_| ProtoError::Format))
        .collect::<Result<Vec<_>, _>>()?;
    let state = match overview.state {
        p::ItemState::Active => ItemState::Active,
        p::ItemState::Archived { at } => ItemState::Archived { at },
        p::ItemState::Trashed { at } => ItemState::Trashed { at },
    };
    Item::new(ItemParts {
        kind: overview.kind,
        title: overview.title,
        subtitle: overview.subtitle,
        tags,
        favourite: overview.favourite,
        state,
        sections: details.sections,
        notes: details.notes,
        urls: details.urls,
        apps: details.apps,
        passkeys: details.passkeys,
        attachments: details.attachments,
        password_history: details.password_history,
        client_modified: overview.client_modified,
        created: overview.created,
        expires_at: overview.expires_at,
    })
    .map_err(|_| ProtoError::Format)
}

fn overview_to(item: &Item) -> p::Overview {
    let o = item.overview();
    p::Overview {
        kind: o.kind.clone(),
        title: o.title.clone(),
        subtitle: o.subtitle.clone(),
        tags: o.tags.iter().map(|tag| tag.as_str().to_owned()).collect(),
        favourite: o.favourite,
        state: match o.state {
            ItemState::Active => p::ItemState::Active,
            ItemState::Archived { at } => p::ItemState::Archived { at },
            ItemState::Trashed { at } => p::ItemState::Trashed { at },
        },
        client_modified: o.client_modified,
        created: o.created,
        expires_at: o.expires_at,
    }
}

fn details_to(d: &Details) -> Result<p::Details, ProtoError> {
    Ok(p::Details {
        sections: d
            .sections
            .iter()
            .map(section_to)
            .collect::<Result<_, _>>()?,
        notes: d.notes.clone(),
        urls: d.urls.iter().map(url_to).collect(),
        apps: d.apps.iter().map(app_to).collect(),
        passkeys: d.passkeys.iter().map(passkey_to).collect(),
        attachments: d.attachments.iter().map(attachment_to).collect(),
        history: d
            .password_history
            .iter()
            .map(|entry| p::PasswordHistoryEntry {
                value: SecretBytes::from_vec(entry.value.expose_secret().as_bytes().to_vec()),
                replaced_at: entry.replaced_at,
                field: *entry.field.as_bytes(),
            })
            .collect(),
    })
}

struct DetailsParts {
    sections: Vec<Section>,
    notes: Option<String>,
    urls: Vec<UrlEntry>,
    apps: Vec<AppAssociation>,
    passkeys: Vec<Passkey>,
    attachments: Vec<AttachmentDesc>,
    password_history: Vec<PasswordHistoryEntry>,
}

fn details_from(d: p::Details) -> Result<DetailsParts, ProtoError> {
    Ok(DetailsParts {
        sections: d
            .sections
            .into_iter()
            .map(section_from)
            .collect::<Result<_, _>>()?,
        notes: d.notes,
        urls: d.urls.into_iter().map(url_from).collect::<Result<_, _>>()?,
        apps: d.apps.into_iter().map(app_from).collect(),
        passkeys: d.passkeys.into_iter().map(passkey_from).collect(),
        attachments: d.attachments.into_iter().map(attachment_from).collect(),
        password_history: d
            .history
            .into_iter()
            .map(|entry| {
                let value = String::from_utf8(entry.value.expose().to_vec())
                    .map_err(|_| ProtoError::Format)?;
                Ok(PasswordHistoryEntry {
                    value: SecretString::from(value),
                    replaced_at: entry.replaced_at,
                    field: Id::from_bytes(entry.field),
                })
            })
            .collect::<Result<_, ProtoError>>()?,
    })
}

fn section_to(section: &Section) -> Result<p::Section, ProtoError> {
    Ok(p::Section {
        id: *section.id().as_bytes(),
        title: section.title().to_owned(),
        fields: section
            .fields()
            .iter()
            .map(|field| {
                Ok(p::Field {
                    id: *field.id().as_bytes(),
                    label: field.label().to_owned(),
                    value: value_to(field.value()),
                    purpose: field.purpose().map(purpose_to),
                    concealed: field.is_concealed(),
                    expires_alert: field.expires_alert(),
                })
            })
            .collect::<Result<_, ProtoError>>()?,
    })
}

fn section_from(section: p::Section) -> Result<Section, ProtoError> {
    let fields = section
        .fields
        .into_iter()
        .map(field_from)
        .collect::<Result<Vec<_>, _>>()?;
    Section::new(Id::from_bytes(section.id), &section.title, fields).map_err(|_| ProtoError::Format)
}

fn field_from(field: p::Field) -> Result<Field, ProtoError> {
    let kind = field.value.kind();
    let value = value_from(field.value)?;
    let mut out = Field::new(Id::from_bytes(field.id), &field.label, value)
        .map_err(|_| ProtoError::Format)?;
    if let Some(purpose) = field.purpose {
        out = out
            .with_purpose(purpose_from(purpose))
            .map_err(|_| ProtoError::Format)?;
    }
    if out.kind() != kind_from(kind) {
        return Err(ProtoError::Format);
    }
    Ok(out
        .with_concealed(field.concealed)
        .with_expires_alert(field.expires_alert))
}

fn secret_text(value: &SecretString) -> SecretBytes {
    SecretBytes::from_vec(value.expose_secret().as_bytes().to_vec())
}

fn text_secret(value: &SecretBytes) -> Result<SecretString, ProtoError> {
    String::from_utf8(value.expose().to_vec())
        .map(SecretString::from)
        .map_err(|_| ProtoError::Format)
}

fn value_to(value: &FieldValue) -> p::Value {
    match value {
        FieldValue::Text(v) => p::Value::Text(v.clone()),
        FieldValue::Url(v) => p::Value::Url(v.clone()),
        FieldValue::Email(v) => p::Value::Email(v.clone()),
        FieldValue::Phone(v) => p::Value::Phone(v.clone()),
        FieldValue::Menu(v) => p::Value::Menu(v.clone()),
        FieldValue::SignInWith(v) => p::Value::SignInWith(v.clone()),
        FieldValue::Concealed(v) => p::Value::Concealed(secret_text(v)),
        FieldValue::Date(d) => p::Value::Date {
            year: d.year(),
            month: d.month(),
            day: d.day(),
        },
        FieldValue::MonthYear(m) => p::Value::MonthYear {
            year: m.year(),
            month: m.month(),
        },
        FieldValue::Otp(otp) => p::Value::Otp(p::Otp {
            secret: SecretBytes::from_vec(otp.expose_secret().to_vec()),
            algorithm: alg_to(otp.algorithm()),
            digits: otp.digits(),
            mode: match otp.kind() {
                OtpKind::Totp { period_s } => p::OtpMode::Totp { period_s },
                OtpKind::Hotp { counter } => p::OtpMode::Hotp { counter },
            },
            issuer: otp.issuer().map(str::to_owned),
            account: otp.account().map(str::to_owned),
            steam: otp.is_steam(),
        }),
        FieldValue::Address(a) => p::Value::Address(p::Address {
            street: a.street.clone(),
            city: a.city.clone(),
            region: a.region.clone(),
            postal_code: a.postal_code.clone(),
            country: a.country.clone(),
        }),
        FieldValue::SecurityQuestion { question, answer } => p::Value::SecurityQuestion {
            question: question.clone(),
            answer: secret_text(answer),
        },
    }
}

fn value_from(value: p::Value) -> Result<FieldValue, ProtoError> {
    Ok(match value {
        p::Value::Text(v) => FieldValue::Text(v),
        p::Value::Url(v) => FieldValue::Url(v),
        p::Value::Email(v) => FieldValue::Email(v),
        p::Value::Phone(v) => FieldValue::Phone(v),
        p::Value::Menu(v) => FieldValue::Menu(v),
        p::Value::SignInWith(v) => FieldValue::SignInWith(v),
        p::Value::Concealed(v) => FieldValue::Concealed(text_secret(&v)?),
        p::Value::Date { year, month, day } => {
            FieldValue::Date(Date::new(year, month, day).map_err(|_| ProtoError::Format)?)
        }
        p::Value::MonthYear { year, month } => {
            FieldValue::MonthYear(MonthYear::new(year, month).map_err(|_| ProtoError::Format)?)
        }
        p::Value::Otp(otp) => {
            let params = if otp.steam {
                OtpParams::steam(otp.secret.expose())
            } else {
                let kind = match otp.mode {
                    p::OtpMode::Totp { period_s } => OtpKind::Totp { period_s },
                    p::OtpMode::Hotp { counter } => OtpKind::Hotp { counter },
                };
                OtpParams::new(
                    otp.secret.expose(),
                    kind,
                    alg_from(otp.algorithm),
                    otp.digits,
                )
            };
            FieldValue::Otp(
                params
                    .map(|p| p.with_label(otp.issuer, otp.account))
                    .map_err(|_| ProtoError::Format)?,
            )
        }
        p::Value::Address(a) => FieldValue::Address(Address {
            street: a.street,
            city: a.city,
            region: a.region,
            postal_code: a.postal_code,
            country: a.country,
        }),
        p::Value::SecurityQuestion { question, answer } => FieldValue::SecurityQuestion {
            question,
            answer: text_secret(&answer)?,
        },
    })
}

fn url_to(url: &UrlEntry) -> p::UrlEntry {
    p::UrlEntry {
        id: *url.id().as_bytes(),
        url: url.url().to_owned(),
        mode: mode_to(url.mode()),
        confirmed_hosts: url.confirmed_hosts().to_vec(),
        kind: url_kind_to(url.kind()),
    }
}

fn url_from(url: p::UrlEntry) -> Result<UrlEntry, ProtoError> {
    let mut entry = UrlEntry::new(
        Id::from_bytes(url.id),
        &url.url,
        mode_from(url.mode),
        url_kind_from(url.kind),
    )
    .map_err(|_| ProtoError::Format)?;
    for host in url.confirmed_hosts {
        entry.confirm_host(&host).map_err(|_| ProtoError::Format)?;
    }
    Ok(entry)
}

fn app_to(app: &AppAssociation) -> p::AppAssociation {
    p::AppAssociation {
        platform: platform_to(app.platform),
        id: app.id.clone(),
        cert_sha256: app.cert_sha256,
        source: source_to(app.source),
    }
}

fn app_from(app: p::AppAssociation) -> AppAssociation {
    AppAssociation {
        platform: platform_from(app.platform),
        id: app.id,
        cert_sha256: app.cert_sha256,
        source: source_from(app.source),
    }
}

fn passkey_to(passkey: &Passkey) -> p::Passkey {
    p::Passkey {
        credential_id: passkey.credential_id.clone(),
        rp_id: passkey.rp_id.clone(),
        user_handle: passkey.user_handle.clone(),
        user_name: passkey.user_name.clone(),
        display_name: passkey.display_name.clone(),
        algorithm: passkey.algorithm,
        private_key: SecretBytes::from_vec(passkey.private_key.expose_secret().to_vec()),
        created: passkey.created,
        last_used: passkey.last_used,
        backup_eligible: passkey.backup_eligible,
        backed_up: passkey.backed_up,
    }
}

fn passkey_from(passkey: p::Passkey) -> Passkey {
    Passkey {
        credential_id: passkey.credential_id,
        rp_id: passkey.rp_id,
        user_handle: passkey.user_handle,
        user_name: passkey.user_name,
        display_name: passkey.display_name,
        algorithm: passkey.algorithm,
        private_key: SecretSlice::from(passkey.private_key.expose().to_vec()),
        created: passkey.created,
        last_used: passkey.last_used,
        backup_eligible: passkey.backup_eligible,
        backed_up: passkey.backed_up,
    }
}

fn attachment_to(a: &AttachmentDesc) -> p::AttachmentDescriptor {
    p::AttachmentDescriptor {
        att_id: AttId::from_bytes(*a.att_id.as_bytes()),
        file_key: a.file_key.duplicate(),
        nonce_prefix: a.nonce_prefix,
        size: a.size,
        chunk_size: a.chunk_size,
        name: a.name.clone(),
        mime: a.mime.clone(),
    }
}

fn attachment_from(a: p::AttachmentDescriptor) -> AttachmentDesc {
    AttachmentDesc {
        att_id: Id::from_bytes(*a.att_id.as_bytes()),
        file_key: a.file_key,
        nonce_prefix: a.nonce_prefix,
        size: a.size,
        chunk_size: a.chunk_size,
        name: a.name,
        mime: a.mime,
    }
}
