use std::collections::BTreeSet;

use crate::device::Device;

pub fn hash_hex(secret: &str) -> String {
    hasp_crypto::to_hex(&hasp_crypto::sha256(&[secret.as_bytes()]))
}

pub fn vault_secret_hashes(device: &Device) -> BTreeSet<String> {
    let mut hashes = BTreeSet::new();
    for filter in [None, Some("--archived"), Some("--trashed")] {
        let mut args = vec!["item", "list"];
        args.extend(filter);
        for item in device.data(&args).as_array().unwrap() {
            let id = item["id"].as_str().unwrap();
            let shown = device.data(&["--reveal", "item", "get", id]);
            for field in shown["fields"].as_array().unwrap() {
                if field["concealed"] == true {
                    hashes.insert(hash_hex(field["value"].as_str().unwrap()));
                }
            }
        }
    }
    hashes
}

pub fn item_count(device: &Device) -> usize {
    [None, Some("--archived"), Some("--trashed")]
        .into_iter()
        .map(|filter| {
            let mut args = vec!["item", "list"];
            args.extend(filter);
            device.data(&args).as_array().unwrap().len()
        })
        .sum()
}
