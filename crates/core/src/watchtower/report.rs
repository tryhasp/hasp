use crate::model::id::Id;
use crate::watchtower::estimate::WeakReason;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Category {
    Pwned,
    Reused,
    Weak,
    InsecureUrl,
    Expiring,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detail {
    Pwned { count: u64 },
    Reused { items: usize },
    Weak { bits: u32, reasons: Vec<WeakReason> },
    InsecureUrl,
    Expiring { days_left: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub detail: Detail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemReport {
    pub item: Id,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub pwned: usize,
    pub reused: usize,
    pub weak: usize,
    pub insecure_url: usize,
    pub expiring: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub items: Vec<ItemReport>,
    pub counts: Counts,
}

impl Finding {
    pub fn category(&self) -> Category {
        match self.detail {
            Detail::Pwned { .. } => Category::Pwned,
            Detail::Reused { .. } => Category::Reused,
            Detail::Weak { .. } => Category::Weak,
            Detail::InsecureUrl => Category::InsecureUrl,
            Detail::Expiring { .. } => Category::Expiring,
        }
    }
}

impl Counts {
    pub fn get(&self, category: Category) -> usize {
        match category {
            Category::Pwned => self.pwned,
            Category::Reused => self.reused,
            Category::Weak => self.weak,
            Category::InsecureUrl => self.insecure_url,
            Category::Expiring => self.expiring,
        }
    }

    pub fn total(&self) -> usize {
        self.pwned + self.reused + self.weak + self.insecure_url + self.expiring
    }

    pub(crate) fn add(&mut self, category: Category) {
        let slot = match category {
            Category::Pwned => &mut self.pwned,
            Category::Reused => &mut self.reused,
            Category::Weak => &mut self.weak,
            Category::InsecureUrl => &mut self.insecure_url,
            Category::Expiring => &mut self.expiring,
        };
        *slot += 1;
    }
}

impl ItemReport {
    pub fn severity(&self) -> Severity {
        self.findings
            .iter()
            .map(|finding| finding.severity)
            .max()
            .unwrap_or(Severity::Low)
    }
}
