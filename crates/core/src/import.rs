use std::collections::BTreeMap;

use hasp_proto::VaultKind;
use secrecy::SecretSlice;

use crate::import::report::MigrationReport;
use crate::model::ModelError;
use crate::model::id::Id;
use crate::model::item::Item;
use crate::model::tag::Tag;

pub mod bitwarden;
mod build;
pub mod cxf;
pub mod delimited;
pub mod onepux;
pub mod report;
pub(crate) mod time;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("format: {0}")]
    Format(&'static str),
    #[error("the export is encrypted")]
    Encrypted,
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    #[error("limit exceeded: {0}")]
    Limit(&'static str),
    #[error("zip container: {0}")]
    Zip(&'static str),
    #[error("json at line {line} column {column}")]
    Json { line: usize, column: usize },
    #[error("csv: {0}")]
    Csv(&'static str),
    #[error("model: {0}")]
    Model(#[from] ModelError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    OnePassword,
    Bitwarden,
    Csv,
    Cxf,
}

#[derive(Debug)]
pub struct AttachedFile {
    pub id: Id,
    pub name: String,
    pub mime: String,
    pub data: SecretSlice<u8>,
}

#[derive(Debug)]
pub struct ImportItem {
    pub source_id: String,
    pub item: Item,
    pub files: Vec<AttachedFile>,
}

#[derive(Debug)]
pub struct ImportVault {
    pub source_id: String,
    pub name: String,
    pub kind: VaultKind,
    pub items: Vec<ImportItem>,
}

#[derive(Debug)]
pub struct ImportBatch {
    pub source: Source,
    pub vaults: Vec<ImportVault>,
    pub report: MigrationReport,
}

impl Source {
    pub fn name(self) -> &'static str {
        match self {
            Self::OnePassword => "1password",
            Self::Bitwarden => "bitwarden",
            Self::Csv => "csv",
            Self::Cxf => "cxf",
        }
    }

    /// The tag every imported item carries: `imported/<source>/<date>`.
    pub fn tag(self, date: &str) -> Result<Tag, ModelError> {
        Tag::new(&format!("imported/{}/{date}", self.name()))
    }
}

impl ImportBatch {
    pub fn item_count(&self) -> usize {
        self.vaults.iter().map(|v| v.items.len()).sum()
    }

    pub fn counts_by_kind(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for item in self.vaults.iter().flat_map(|v| &v.items) {
            *counts.entry(item.item.overview().kind.clone()).or_insert(0) += 1;
        }
        counts
    }
}
