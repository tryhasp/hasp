use serde::Serialize;
use tsify::{Ts, Tsify};
use wasm_bindgen::JsValue;

hasp_boundary::hasp_error! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, thiserror::Error, Tsify)]
    #[serde(tag = "kind", rename_all = "kebab-case")]
}

impl From<HaspError> for Ts<HaspError> {
    fn from(error: HaspError) -> Self {
        Self::from_rust(&error)
            .unwrap_or_else(|_| Self::new_unchecked(JsValue::from_str("internal")))
    }
}

pub(crate) fn thrown<E: Into<HaspError>>(error: E) -> Ts<HaspError> {
    error.into().into()
}

#[cfg(feature = "replay")]
pub(crate) fn exported<T: Tsify + Serialize>(value: &T) -> Result<Ts<T>, Ts<HaspError>> {
    Ts::from_rust(value).map_err(|_| HaspError::Internal.into())
}

#[cfg(test)]
mod tests {
    use super::HaspError;

    #[test]
    fn every_variant_has_its_own_message() {
        let mut messages: Vec<String> = HaspError::ALL.iter().map(ToString::to_string).collect();
        messages.sort();
        messages.dedup();
        assert_eq!(messages.len(), HaspError::ALL.len());
    }
}
