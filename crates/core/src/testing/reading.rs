use std::path::PathBuf;

use secrecy::ExposeSecret;

use crate::import::report::{Fate, Subject};
use crate::import::{ImportBatch, ImportItem};
use crate::model::field::{Field, FieldValue, Section};
use crate::model::item::Item;
use crate::model::template::Templates;

pub fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testvectors/import")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

pub fn templates() -> Templates {
    Templates::bundled().unwrap()
}

pub fn find<'a>(batch: &'a ImportBatch, title: &str) -> &'a ImportItem {
    batch
        .vaults
        .iter()
        .flat_map(|v| &v.items)
        .find(|i| i.item.overview().title == title)
        .unwrap_or_else(|| panic!("no item titled {title}"))
}

pub fn field<'a>(item: &'a Item, label: &str) -> Option<&'a Field> {
    item.details()
        .sections
        .iter()
        .flat_map(Section::fields)
        .find(|f| f.label() == label)
}

pub fn text_of(field: &Field) -> String {
    match field.value() {
        FieldValue::Text(v)
        | FieldValue::Url(v)
        | FieldValue::Email(v)
        | FieldValue::Phone(v)
        | FieldValue::Menu(v)
        | FieldValue::SignInWith(v) => v.clone(),
        FieldValue::Concealed(v) => v.expose_secret().to_owned(),
        FieldValue::Otp(o) => format!(
            "otp:{:?}:{}:{:?}:{:?}:{:?}:{:?}:{}",
            o.expose_secret(),
            o.digits(),
            o.kind(),
            o.algorithm(),
            o.issuer(),
            o.account(),
            o.is_steam()
        ),
        FieldValue::Date(d) => format!("{}-{}-{}", d.year(), d.month(), d.day()),
        FieldValue::MonthYear(m) => format!("{}-{}", m.year(), m.month()),
        FieldValue::Address(a) => format!(
            "{}|{}|{}|{}|{}",
            a.street, a.city, a.region, a.postal_code, a.country
        ),
        FieldValue::SecurityQuestion { question, answer } => {
            format!("{question}|{}", answer.expose_secret())
        }
    }
}

pub fn value(item: &Item, label: &str) -> String {
    text_of(field(item, label).unwrap_or_else(|| panic!("no field {label}")))
}

pub fn lost(batch: &ImportBatch, title: &str) -> Vec<(Subject, Fate)> {
    let report = batch
        .report
        .items
        .iter()
        .find(|i| i.title == title)
        .unwrap();
    report
        .entries
        .iter()
        .map(|e| (e.subject.clone(), e.fate.clone()))
        .collect()
}
