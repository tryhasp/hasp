use serde_json::Value;

pub(crate) fn unhex(text: &str) -> Vec<u8> {
    crate::from_hex(text).unwrap()
}

pub(crate) fn array<const N: usize>(text: &str) -> [u8; N] {
    unhex(text).try_into().unwrap()
}

pub(crate) fn field(value: &Value, name: &str) -> Vec<u8> {
    unhex(value[name].as_str().unwrap())
}

pub(crate) fn load(name: &str) -> Value {
    let path = format!(
        "{}/../../testvectors/crypto/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
