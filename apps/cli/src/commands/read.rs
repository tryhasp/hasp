use hasp_core::model::field::Field;
use hasp_core::model::item::Item;
use hasp_core::transport::Transport;
use hasp_core::{CoreError, model::field::FieldValue};
use hasp_crypto::to_hex;
use hasp_proto::AttId;
use serde_json::json;

use crate::app::App;
use crate::cli::ReadArgs;
use crate::error::CliError;
use crate::fsx;
use crate::itemspec::{field_matches, kind_name, purpose_name, value_text};
use crate::reference::{Attribute, Reference};
use crate::resolve::{self};

pub(crate) async fn run<T: Transport>(app: &App<'_, T>, args: ReadArgs) -> Result<(), CliError> {
    let reference = Reference::parse(&args.reference)?;
    let mut client = app.open().await?;
    let (vault, id) = resolve::item(&client, Some(&reference.vault), &reference.item)?;
    let item = client.item(&vault, &id)?;
    let bytes = match locate(&item, &reference)? {
        Located::Field(field) => field_bytes(&reference, field, app.now())?,
        Located::File(index) => {
            let desc = item
                .details()
                .attachments
                .get(index)
                .ok_or_else(|| CliError::not_found("file"))?;
            match reference.attribute {
                Attribute::Content => {
                    let att = AttId::from_bytes(*desc.att_id.as_bytes());
                    client
                        .download_attachment(&vault, &id, &att, &App::<T>::cancel())
                        .await?
                        .to_vec()
                }
                Attribute::Size => desc.size.to_string().into_bytes(),
                Attribute::Name => desc.name.clone().into_bytes(),
                Attribute::Type => desc.mime.clone().into_bytes(),
                Attribute::Value | Attribute::Otp | Attribute::Id | Attribute::Purpose => {
                    return Err(CliError::usage(
                        "a file takes ?attribute=content|size|name|type",
                    ));
                }
            }
        }
    };
    emit(app, &args, &bytes)
}

enum Located<'a> {
    Field(&'a Field),
    File(usize),
}

fn locate<'a>(item: &'a Item, reference: &Reference) -> Result<Located<'a>, CliError> {
    let mut found: Vec<&Field> = Vec::new();
    for section in &item.details().sections {
        if let Some(wanted) = &reference.section
            && section.title().to_lowercase() != wanted.to_lowercase()
        {
            continue;
        }
        for field in section.fields() {
            if field_matches(field, &reference.field) {
                found.push(field);
            }
        }
    }
    match found.as_slice() {
        [one] => return Ok(Located::Field(one)),
        [] => {}
        many => {
            return Err(CliError::ambiguous(
                &format!("field {}", reference.field),
                many.iter().map(|f| f.label().to_owned()).collect(),
            ));
        }
    }
    if reference.section.is_none()
        && let Some(index) = item
            .details()
            .attachments
            .iter()
            .position(|a| a.name == reference.field)
    {
        return Ok(Located::File(index));
    }
    Err(CliError::not_found(format!("no field {}", reference.field)))
}

fn field_bytes(reference: &Reference, field: &Field, now: u64) -> Result<Vec<u8>, CliError> {
    Ok(match reference.attribute {
        Attribute::Value | Attribute::Content => value_text(field.value()).into_bytes(),
        Attribute::Otp => match field.value() {
            FieldValue::Otp(params) => {
                use secrecy::ExposeSecret;
                params
                    .code_at(now)
                    .map_err(CoreError::from)?
                    .expose_secret()
                    .to_owned()
                    .into_bytes()
            }
            FieldValue::Text(_)
            | FieldValue::Concealed(_)
            | FieldValue::Url(_)
            | FieldValue::Email(_)
            | FieldValue::Phone(_)
            | FieldValue::Date(_)
            | FieldValue::MonthYear(_)
            | FieldValue::Address(_)
            | FieldValue::Menu(_)
            | FieldValue::SecurityQuestion { .. }
            | FieldValue::SignInWith(_) => {
                return Err(CliError::usage("the field is not a one-time password"));
            }
        },
        Attribute::Type => kind_name(field.kind()).to_owned().into_bytes(),
        Attribute::Id => to_hex(field.id().as_bytes()).into_bytes(),
        Attribute::Purpose => field
            .purpose()
            .map(purpose_name)
            .ok_or_else(|| CliError::not_found("the field has no purpose"))?
            .to_owned()
            .into_bytes(),
        Attribute::Size | Attribute::Name => {
            return Err(CliError::usage("size and name belong to files"));
        }
    })
}

fn emit<T: Transport>(app: &App<'_, T>, args: &ReadArgs, bytes: &[u8]) -> Result<(), CliError> {
    if let Some(path) = &args.out_file {
        fsx::write_private(path, bytes)?;
        return app
            .out
            .record(vec![("written", json!(path.display().to_string()))]);
    }
    if app.out.format() == crate::output::Format::Json {
        let text = String::from_utf8_lossy(bytes).into_owned();
        return app.out.record(vec![("value", json!(text))]);
    }
    app.out.raw(bytes)?;
    if args.newline {
        app.out.raw(b"\n")?;
    }
    Ok(())
}
