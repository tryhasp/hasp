hasp_boundary::hasp_error! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
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
