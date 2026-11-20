use secrecy::{ExposeSecret, SecretString};

use crate::model::field::{Field, FieldValue, Purpose, Section};
use crate::model::id::Id;
use crate::model::item::{Item, ItemParts, ItemState};

pub fn login_item(title: &str, password: &str) -> Item {
    let password_field = Field::new(
        Id::from_bytes([200; 16]),
        "password",
        FieldValue::Concealed(SecretString::from(password)),
    )
    .unwrap()
    .with_purpose(Purpose::Password)
    .unwrap()
    .with_concealed(true);
    let section = Section::new(Id::from_bytes([7; 16]), "", vec![password_field]).unwrap();
    Item::new(ItemParts {
        kind: "login".to_owned(),
        title: title.to_owned(),
        subtitle: String::new(),
        tags: Vec::new(),
        favourite: None,
        state: ItemState::Active,
        sections: vec![section],
        notes: None,
        urls: Vec::new(),
        apps: Vec::new(),
        passkeys: Vec::new(),
        attachments: Vec::new(),
        password_history: Vec::new(),
        client_modified: 10,
        created: 10,
        expires_at: None,
    })
    .unwrap()
}

pub fn password_of(item: &Item) -> String {
    item.details()
        .sections
        .iter()
        .flat_map(|s| s.fields().iter())
        .find_map(|f| match f.value() {
            FieldValue::Concealed(v) => Some(v.expose_secret().to_owned()),
            _ => None,
        })
        .unwrap()
}
