use hasp_proto::VaultKind;
use zeroize::Zeroizing;

use crate::import::build::Draft;
use crate::import::report::{MigrationReport, Reason, Subject};
use crate::import::{ImportBatch, ImportError, ImportItem, ImportVault, Source};
use crate::model::field::Purpose;
use crate::model::item::ItemState;
use crate::model::template::Templates;
use crate::model::url::MatchMode;

const MAX_BYTES: usize = 256 << 20;
const MAX_ROWS: usize = 1_000_000;
const MAX_COLUMNS: usize = 256;
const VAULT_NAME: &str = "CSV import";
const SECRET_HINTS: [&str; 7] = ["password", "secret", "pin", "cvv", "cvc", "token", "key"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Column {
    Title,
    Url,
    Username,
    Password,
    Notes,
    Totp,
    Folder,
    Tags,
    Favorite,
    Kind,
    CustomFields,
    Ignored,
    Unmapped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsvPlan {
    pub delimiter: u8,
    pub headers: Vec<String>,
    pub columns: Vec<Column>,
}

const ALIASES: &[(Column, &[&str])] = &[
    (
        Column::Title,
        &[
            "title",
            "name",
            "itemname",
            "account",
            "accountname",
            "entry",
        ],
    ),
    (
        Column::Url,
        &[
            "url",
            "website",
            "web",
            "weburl",
            "websiteurl",
            "webaddress",
            "loginuri",
            "uri",
            "site",
            "origin",
            "address",
        ],
    ),
    (
        Column::Username,
        &[
            "username",
            "user",
            "login",
            "loginname",
            "loginusername",
            "userid",
            "email",
            "emailaddress",
        ],
    ),
    (
        Column::Password,
        &["password", "pass", "loginpassword", "pwd"],
    ),
    (
        Column::Notes,
        &[
            "notes",
            "note",
            "extra",
            "comments",
            "comment",
            "description",
            "memo",
        ],
    ),
    (
        Column::Totp,
        &[
            "totp",
            "otp",
            "otpauth",
            "otpurl",
            "loginotp",
            "logintotp",
            "onetimepassword",
            "twofactor",
        ],
    ),
    (Column::Folder, &["folder", "grouping", "group"]),
    (Column::Tags, &["tags", "labels"]),
    (
        Column::Favorite,
        &["favorite", "favourite", "fav", "starred"],
    ),
    (Column::Kind, &["type", "itemtype"]),
    (Column::CustomFields, &["fields", "customfields"]),
    (
        Column::Ignored,
        &[
            "reprompt",
            "httprealm",
            "formactionorigin",
            "guid",
            "timecreated",
            "timelastused",
            "timepasswordchanged",
            "created",
            "modified",
            "lastmodified",
            "archived",
            "id",
        ],
    ),
];

pub fn detect(bytes: &[u8]) -> Result<CsvPlan, ImportError> {
    let text = decode(bytes)?;
    let delimiter = sniff_delimiter(&text);
    let mut reader = reader(&text, delimiter);
    let headers = reader
        .records()
        .next()
        .ok_or(ImportError::Csv("empty file"))?
        .map_err(|_| ImportError::Csv("malformed"))?;
    if headers.len() > MAX_COLUMNS {
        return Err(ImportError::Limit("csv columns"));
    }
    let headers: Vec<String> = headers.iter().map(|h| h.trim().to_owned()).collect();
    let mut used: Vec<Column> = Vec::new();
    let columns: Vec<Column> = headers
        .iter()
        .map(|header| {
            let role = role_of(header);
            if role == Column::Ignored || role == Column::Unmapped || !used.contains(&role) {
                used.push(role);
                role
            } else {
                Column::Unmapped
            }
        })
        .collect();
    let known = [
        Column::Title,
        Column::Url,
        Column::Username,
        Column::Password,
    ];
    if !columns.iter().any(|c| known.contains(c)) {
        return Err(ImportError::Csv("no recognised columns"));
    }
    Ok(CsvPlan {
        delimiter,
        headers,
        columns,
    })
}

pub fn parse(bytes: &[u8], templates: &Templates) -> Result<ImportBatch, ImportError> {
    let plan = detect(bytes)?;
    parse_with_plan(bytes, &plan, templates)
}

pub fn parse_with_plan(
    bytes: &[u8],
    plan: &CsvPlan,
    templates: &Templates,
) -> Result<ImportBatch, ImportError> {
    let text = decode(bytes)?;
    let mut reader = reader(&text, plan.delimiter);
    let mut report = MigrationReport::new(Source::Csv);
    let mut items: Vec<ImportItem> = Vec::new();
    let mut seen: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for (index, record) in reader.records().enumerate().skip(1) {
        if index > MAX_ROWS {
            return Err(ImportError::Limit("csv rows"));
        }
        let record = record.map_err(|_| ImportError::Csv("malformed"))?;
        if record.iter().all(|cell| cell.trim().is_empty()) {
            continue;
        }
        let cells: Vec<&str> = record.iter().collect();
        let (item, item_report) = read_row(&mut seen, &cells, plan, templates);
        report.items.push(item_report);
        items.extend(item);
    }
    Ok(ImportBatch {
        source: Source::Csv,
        vaults: vec![ImportVault {
            source_id: String::new(),
            name: VAULT_NAME.to_owned(),
            kind: VaultKind::Private,
            items,
        }],
        report,
    })
}

struct Row<'a> {
    cells: &'a [&'a str],
    plan: &'a CsvPlan,
}

impl<'a> Row<'a> {
    fn cell(&self, column: Column) -> &'a str {
        self.plan
            .columns
            .iter()
            .position(|c| *c == column)
            .and_then(|i| self.cells.get(i))
            .map_or("", |v| v.trim())
    }

    fn urls(&self) -> Vec<&'a str> {
        self.cell(Column::Url)
            .lines()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .collect()
    }

    fn add_tags(&self, draft: &mut Draft) {
        if !self.cell(Column::Folder).is_empty() {
            draft.tag(self.cell(Column::Folder));
        }
        for tag in self
            .cell(Column::Tags)
            .split([',', ';'])
            .map(str::trim)
            .filter(|t| !t.is_empty())
        {
            draft.tag(tag);
        }
    }

    fn add_credentials(&self, draft: &mut Draft, urls: &[&str]) {
        for url in urls {
            draft.url(url, MatchMode::Domain);
        }
        let credentials = vec![
            draft.text(
                "username",
                self.cell(Column::Username),
                Some(Purpose::Username),
            ),
            draft.secret(
                "password",
                self.cell(Column::Password),
                Some(Purpose::Password),
            ),
            Some(self.cell(Column::Totp))
                .filter(|t| !t.is_empty())
                .and_then(|t| draft.otp("one-time password", t, Some(Purpose::Totp))),
        ];
        draft.section("", credentials);
    }

    fn add_extra_columns(&self, draft: &mut Draft) {
        let mut extra = Vec::new();
        for line in self.cell(Column::CustomFields).lines() {
            if let Some((name, value)) = line.split_once(':') {
                extra.push(draft.text(name.trim(), value, None));
            }
        }
        for (index, column) in self.plan.columns.iter().enumerate() {
            if *column != Column::Unmapped {
                continue;
            }
            let (Some(header), Some(value)) = (self.plan.headers.get(index), self.cells.get(index))
            else {
                continue;
            };
            let secretive = SECRET_HINTS.iter().any(|h| normalize(header).contains(h));
            extra.push(if secretive {
                draft.secret(header, value, None)
            } else {
                draft.text(header, value, None)
            });
        }
        draft.section("Imported columns", extra);
    }
}

fn read_row(
    seen: &mut std::collections::BTreeMap<String, usize>,
    cells: &[&str],
    plan: &CsvPlan,
    templates: &Templates,
) -> (Option<ImportItem>, crate::import::report::ItemReport) {
    let fields = Row { cells, plan };
    let urls = fields.urls();
    let kind = normalize(fields.cell(Column::Kind));
    let secure_note = matches!(kind.as_str(), "note" | "securenote")
        || urls.first().is_some_and(|u| *u == "http://sn");
    let template = templates
        .get(if secure_note { "secure-note" } else { "login" })
        .map_or("custom", |t| t.id.as_str());
    let username = fields.cell(Column::Username);
    let title = [fields.cell(Column::Title), host_of(urls.first()), username]
        .into_iter()
        .find(|t| !t.is_empty())
        .unwrap_or("Untitled");
    let natural = format!(
        "{template}\u{1f}{}\u{1f}{}\u{1f}{}",
        fields.cell(Column::Title).to_lowercase(),
        urls.first().copied().unwrap_or_default().to_lowercase(),
        username.to_lowercase()
    );
    let occurrence = seen.entry(natural.clone()).or_insert(0);
    *occurrence += 1;
    let mut draft = Draft::new(&format!("{natural}#{occurrence}"), template, title);
    if !kind.is_empty() && !matches!(kind.as_str(), "login" | "note" | "securenote") {
        draft.approximated(Subject::Category(kind.clone()), Reason::NoEquivalent);
    }
    username.clone_into(&mut draft.subtitle);
    draft.notes = Some(fields.cell(Column::Notes).to_owned()).filter(|n| !n.is_empty());
    draft.state = ItemState::Active;
    if is_truthy(fields.cell(Column::Favorite)) {
        draft.favourite = Some(1);
    }
    fields.add_tags(&mut draft);
    if !secure_note {
        fields.add_credentials(&mut draft, &urls);
    }
    fields.add_extra_columns(&mut draft);
    draft.finish()
}

fn role_of(header: &str) -> Column {
    let key = normalize(header);
    ALIASES
        .iter()
        .find(|(_, names)| names.contains(&key.as_str()))
        .map_or(Column::Unmapped, |(column, _)| *column)
}

fn normalize(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "y" | "x"
    )
}

fn host_of<'a>(url: Option<&&'a str>) -> &'a str {
    url.and_then(|u| {
        let rest = u.split_once("://").map_or(*u, |(_, r)| r);
        rest.split(['/', '?', '#']).next()
    })
    .unwrap_or("")
}

fn decode(bytes: &[u8]) -> Result<Zeroizing<String>, ImportError> {
    if bytes.len() > MAX_BYTES {
        return Err(ImportError::Limit("file size"));
    }
    let text = match bytes {
        [0xff, 0xfe, rest @ ..] => utf16(rest, u16::from_le_bytes)?,
        [0xfe, 0xff, rest @ ..] => utf16(rest, u16::from_be_bytes)?,
        [0xef, 0xbb, 0xbf, rest @ ..] => utf8(rest)?,
        _ => utf8(bytes)?,
    };
    Ok(Zeroizing::new(text))
}

fn utf8(bytes: &[u8]) -> Result<String, ImportError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| ImportError::Csv("not utf-8"))
}

fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> Result<String, ImportError> {
    let units = bytes.as_chunks::<2>().0.iter().map(|c| unit(*c));
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .map_err(|_| ImportError::Csv("not utf-16"))
}

fn sniff_delimiter(text: &str) -> u8 {
    let line = text.lines().next().unwrap_or("");
    b",;\t"
        .iter()
        .copied()
        .max_by_key(|d| line.bytes().filter(|b| b == d).count())
        .filter(|d| line.bytes().any(|b| b == *d))
        .unwrap_or(b',')
}

fn reader(text: &str, delimiter: u8) -> csv::Reader<&[u8]> {
    csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .has_headers(false)
        .flexible(true)
        .from_reader(text.as_bytes())
}
