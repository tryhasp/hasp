use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

use serde_json::Value;

use crate::secrets::hash_hex;

fn text(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| !text.is_empty())
}

pub fn onepux_data(path: &Path) -> Value {
    let bytes = std::fs::read(path).unwrap();
    if path.extension().is_some_and(|ext| ext == "json") {
        return serde_json::from_slice(&bytes).unwrap();
    }
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut entry = archive.by_name("export.data").unwrap();
    let mut data = Vec::new();
    entry.read_to_end(&mut data).unwrap();
    serde_json::from_slice(&data).unwrap()
}

pub fn onepux_items(data: &Value) -> Vec<&Value> {
    data["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|account| account["vaults"].as_array().unwrap())
        .flat_map(|vault| vault["items"].as_array().unwrap())
        .collect()
}

pub fn onepux_secrets(data: &Value) -> BTreeSet<String> {
    let mut secrets = BTreeSet::new();
    for item in onepux_items(data) {
        let details = &item["details"];
        for field in details["loginFields"].as_array().into_iter().flatten() {
            if field["fieldType"] == "P" {
                secrets.extend(text(&field["value"]).map(hash_hex));
            }
        }
        secrets.extend(text(&details["password"]).map(hash_hex));
        for section in details["sections"].as_array().into_iter().flatten() {
            for field in section["fields"].as_array().into_iter().flatten() {
                let value = &field["value"];
                for key in ["concealed", "totp", "creditCardNumber"] {
                    secrets.extend(text(&value[key]).map(hash_hex));
                }
                secrets.extend(text(&value["sshKey"]["privateKey"]).map(hash_hex));
            }
        }
    }
    secrets
}

pub fn bitwarden_secrets(data: &Value) -> BTreeSet<String> {
    let mut secrets = BTreeSet::new();
    for item in data["items"].as_array().unwrap() {
        secrets.extend(text(&item["login"]["password"]).map(hash_hex));
        secrets.extend(text(&item["login"]["totp"]).map(hash_hex));
        secrets.extend(text(&item["card"]["number"]).map(hash_hex));
        secrets.extend(text(&item["card"]["code"]).map(hash_hex));
        secrets.extend(text(&item["sshKey"]["privateKey"]).map(hash_hex));
        secrets.extend(text(&item["identity"]["ssn"]).map(hash_hex));
        secrets.extend(text(&item["identity"]["passportNumber"]).map(hash_hex));
        secrets.extend(text(&item["identity"]["licenseNumber"]).map(hash_hex));
        for field in item["fields"].as_array().into_iter().flatten() {
            if field["type"] == 1 {
                secrets.extend(text(&field["value"]).map(hash_hex));
            }
        }
    }
    secrets
}

pub fn csv_secrets(path: &Path, columns: &[&str]) -> BTreeSet<String> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .unwrap();
    let headers = reader.headers().unwrap().clone();
    let wanted: Vec<usize> = headers
        .iter()
        .enumerate()
        .filter(|(_, name)| columns.contains(name))
        .map(|(index, _)| index)
        .collect();
    let mut secrets = BTreeSet::new();
    for record in reader.records() {
        let record = record.unwrap();
        for index in &wanted {
            secrets.extend(record.get(*index).filter(|v| !v.is_empty()).map(hash_hex));
        }
    }
    secrets
}
