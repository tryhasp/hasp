use hasp_core::client::{Client, ItemSummary, VaultSummary};
use hasp_core::store::{LocalVaultStatus, Store};
use hasp_core::transport::Transport;
use hasp_crypto::{from_hex, to_hex};
use hasp_proto::{ItemId, VaultId};

use crate::error::CliError;

pub(crate) fn parse_hex16(text: &str) -> Option<[u8; 16]> {
    from_hex(text)?.try_into().ok()
}

pub(crate) fn unescape(segment: &str) -> String {
    segment.replace("%2F", "/").replace("%2f", "/")
}

pub(crate) fn vault_label(vault: &VaultSummary) -> String {
    format!("{} ({})", vault.name, to_hex(vault.vault_id.as_bytes()))
}

pub(crate) fn item_label(item: &ItemSummary) -> String {
    format!(
        "{} ({}, vault {})",
        item.overview.title,
        to_hex(item.item_id.as_bytes()),
        to_hex(item.vault_id.as_bytes())
    )
}

pub(crate) fn active_vaults<T: Transport, S: Store>(
    client: &Client<T, S>,
) -> Result<Vec<VaultSummary>, CliError> {
    Ok(client
        .vaults()?
        .into_iter()
        .filter(|vault| vault.status == LocalVaultStatus::Active)
        .collect())
}

pub(crate) fn vault<T: Transport, S: Store>(
    client: &Client<T, S>,
    spec: &str,
) -> Result<VaultId, CliError> {
    let spec = unescape(spec);
    let vaults = active_vaults(client)?;
    if let Some(bytes) = parse_hex16(&spec)
        && let Some(found) = vaults.iter().find(|v| *v.vault_id.as_bytes() == bytes)
    {
        return Ok(found.vault_id);
    }
    let exact: Vec<&VaultSummary> = vaults.iter().filter(|v| v.name == spec).collect();
    let matched = if exact.is_empty() {
        let folded = spec.to_lowercase();
        vaults
            .iter()
            .filter(|v| v.name.to_lowercase() == folded)
            .collect()
    } else {
        exact
    };
    match matched.as_slice() {
        [one] => Ok(one.vault_id),
        [] => Err(CliError::not_found(format!("no vault named {spec}"))),
        many => Err(CliError::ambiguous(
            &format!("vault {spec}"),
            many.iter().map(|v| vault_label(v)).collect(),
        )),
    }
}

pub(crate) fn default_vault<T: Transport, S: Store>(
    client: &Client<T, S>,
    spec: Option<&str>,
) -> Result<VaultId, CliError> {
    match spec {
        Some(spec) => vault(client, spec),
        None => Ok(client.private_vault()?),
    }
}

pub(crate) fn items_in<T: Transport, S: Store>(
    client: &Client<T, S>,
    spec: Option<&str>,
) -> Result<Vec<ItemSummary>, CliError> {
    let vaults = match spec {
        Some(spec) => vec![vault(client, spec)?],
        None => active_vaults(client)?
            .into_iter()
            .map(|v| v.vault_id)
            .collect(),
    };
    let mut out = Vec::new();
    for id in vaults {
        out.extend(client.items(&id)?);
    }
    Ok(out)
}

pub(crate) fn item<T: Transport, S: Store>(
    client: &Client<T, S>,
    vault_spec: Option<&str>,
    spec: &str,
) -> Result<(VaultId, ItemId), CliError> {
    let spec = unescape(spec);
    let items = items_in(client, vault_spec)?;
    if let Some(bytes) = parse_hex16(&spec)
        && let Some(found) = items.iter().find(|i| *i.item_id.as_bytes() == bytes)
    {
        return Ok((found.vault_id, found.item_id));
    }
    let exact: Vec<&ItemSummary> = items.iter().filter(|i| i.overview.title == spec).collect();
    let matched = if exact.is_empty() {
        let folded = spec.to_lowercase();
        items
            .iter()
            .filter(|i| i.overview.title.to_lowercase() == folded)
            .collect()
    } else {
        exact
    };
    match matched.as_slice() {
        [one] => Ok((one.vault_id, one.item_id)),
        [] => Err(CliError::not_found(format!("no item named {spec}"))),
        many => Err(CliError::ambiguous(
            &format!("item {spec}"),
            many.iter().map(|i| item_label(i)).collect(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes = [0xab_u8; 16];
        assert_eq!(parse_hex16(&to_hex(&bytes)), Some(bytes));
    }

    #[test]
    fn rejects_short_or_non_hex_ids() {
        assert_eq!(parse_hex16("abcd"), None);
        assert_eq!(parse_hex16(&"zz".repeat(16)), None);
    }

    #[test]
    fn escaped_slash_decodes() {
        assert_eq!(unescape("a%2Fb"), "a/b");
    }
}
