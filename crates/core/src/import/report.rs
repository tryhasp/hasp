use crate::import::{ImportError, Source};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Imported,
    ImportedWithLoss,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Subject {
    Category(String),
    Field(String),
    Url(String),
    Tag(String),
    Passkey(String),
    Attachment(String),
    PasswordHistory,
    Reference(String),
    RepromptSetting,
    Item,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    NotExportedBySource,
    NoEquivalent,
    InvalidValue,
    TooLarge,
    Rejected(String),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fate {
    Mapped { to: String },
    Approximated { reason: Reason },
    Lost { reason: Reason },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Entry {
    pub subject: Subject,
    pub fate: Fate,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ItemReport {
    pub source_id: String,
    pub title: String,
    pub template: Option<String>,
    pub outcome: Outcome,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Note {
    HistoryStartsAtImport,
    SharedVaultMembersMustBeReinvited { vault: String },
    OrganizationVault { vault: String },
    AttachmentsNotInExport,
    PasskeysNotExportedBySource,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MigrationReport {
    pub source: Source,
    pub items: Vec<ItemReport>,
    pub notes: Vec<Note>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub imported: usize,
    pub with_loss: usize,
    pub skipped: usize,
}

impl Fate {
    pub fn is_loss(&self) -> bool {
        !matches!(self, Self::Mapped { .. })
    }
}

impl ItemReport {
    pub fn losses(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(|e| e.fate.is_loss())
    }
}

impl MigrationReport {
    pub fn new(source: Source) -> Self {
        Self {
            source,
            items: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn note(&mut self, note: Note) {
        if !self.notes.contains(&note) {
            self.notes.push(note);
        }
    }

    pub fn counts(&self) -> Counts {
        let count = |outcome: &Outcome| self.items.iter().filter(|i| &i.outcome == outcome).count();
        Counts {
            imported: count(&Outcome::Imported),
            with_loss: count(&Outcome::ImportedWithLoss),
            skipped: count(&Outcome::Skipped),
        }
    }

    pub fn to_json(&self) -> Result<String, ImportError> {
        serde_json::to_string_pretty(self).map_err(|_| ImportError::Format("report"))
    }
}
