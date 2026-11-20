use std::fmt::Write as _;

use serde_json::{Map, Value, json};

use crate::env::Io;
use crate::error::CliError;

pub(crate) const CONCEALED: &str = "<concealed>";
pub(crate) const SCHEMA_VERSION: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    Table,
    Json,
}

#[derive(Debug)]
pub(crate) struct Output<'a> {
    io: &'a dyn Io,
    format: Format,
    quiet: bool,
    reveal: bool,
}

pub(crate) fn escape_controls(text: &str, keep_lines: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() && !(keep_lines && c == '\n') {
            write!(out, "\\u{{{:x}}}", u32::from(c)).ok();
        } else {
            out.push(c);
        }
    }
    out
}

pub(crate) fn display(value: &Value) -> String {
    match value {
        Value::Null => "-".to_owned(),
        Value::String(text) => escape_controls(text, false),
        Value::Array(items) => items.iter().map(display).collect::<Vec<_>>().join(","),
        other => other.to_string(),
    }
}

impl std::fmt::Debug for dyn Io + '_ {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Io(..)")
    }
}

impl<'a> Output<'a> {
    pub(crate) fn new(
        io: &'a dyn Io,
        requested: Option<Format>,
        quiet: bool,
        reveal: bool,
    ) -> Self {
        let format = requested.unwrap_or(if io.stdout_is_tty() {
            Format::Table
        } else {
            Format::Json
        });
        Self {
            io,
            format,
            quiet,
            reveal,
        }
    }

    pub(crate) fn format(&self) -> Format {
        self.format
    }

    pub(crate) fn reveal(&self) -> bool {
        self.reveal
    }

    pub(crate) fn secret(&self, value: &str) -> Value {
        if self.reveal {
            Value::String(value.to_owned())
        } else {
            Value::String(CONCEALED.to_owned())
        }
    }

    pub(crate) fn note(&self, text: &str) {
        if !self.quiet {
            self.io.err(&format!("{}\n", escape_controls(text, true)));
        }
    }

    pub(crate) fn warn(&self, text: &str) {
        self.io.err(&format!("{}\n", escape_controls(text, true)));
    }

    fn json(&self, data: &Value) -> Result<(), CliError> {
        let document = json!({ "schema_version": SCHEMA_VERSION, "data": data });
        self.io.out(format!("{document}\n").as_bytes())
    }

    pub(crate) fn record(&self, fields: Vec<(&str, Value)>) -> Result<(), CliError> {
        match self.format {
            Format::Json => {
                let map: Map<String, Value> = fields
                    .into_iter()
                    .map(|(key, value)| (key.to_owned(), value))
                    .collect();
                self.json(&Value::Object(map))
            }
            Format::Table => {
                if self.quiet {
                    return Ok(());
                }
                let width = fields.iter().map(|(key, _)| key.len()).max().unwrap_or(0);
                let text: String = fields
                    .iter()
                    .map(|(key, value)| format!("{key:<width$}  {}\n", display(value)))
                    .collect::<Vec<_>>()
                    .concat();
                self.io.out(text.as_bytes())
            }
        }
    }

    pub(crate) fn list(&self, headers: &[&str], rows: Vec<Vec<Value>>) -> Result<(), CliError> {
        match self.format {
            Format::Json => {
                let items: Vec<Value> = rows
                    .into_iter()
                    .map(|row| {
                        let map: Map<String, Value> = headers
                            .iter()
                            .zip(row)
                            .map(|(header, value)| ((*header).to_owned(), value))
                            .collect();
                        Value::Object(map)
                    })
                    .collect();
                self.json(&Value::Array(items))
            }
            Format::Table => {
                if self.quiet {
                    return Ok(());
                }
                let cells: Vec<Vec<String>> = rows
                    .iter()
                    .map(|row| row.iter().map(display).collect())
                    .collect();
                let widths: Vec<usize> = headers
                    .iter()
                    .enumerate()
                    .map(|(column, header)| {
                        cells
                            .iter()
                            .filter_map(|row| row.get(column))
                            .map(|cell| cell.chars().count())
                            .chain(std::iter::once(header.chars().count()))
                            .max()
                            .unwrap_or(0)
                    })
                    .collect();
                let upper: Vec<String> = headers.iter().map(|h| h.to_uppercase()).collect();
                let text: String = std::iter::once(&upper)
                    .chain(cells.iter())
                    .map(|row| render_row(row, &widths))
                    .collect::<Vec<_>>()
                    .concat();
                self.io.out(text.as_bytes())
            }
        }
    }

    pub(crate) fn document(&self, data: &Value) -> Result<(), CliError> {
        self.json(data)
    }

    pub(crate) fn raw(&self, bytes: &[u8]) -> Result<(), CliError> {
        self.io.out(bytes)
    }
}

fn render_row(row: &[String], widths: &[usize]) -> String {
    let last = widths.len().saturating_sub(1);
    let cells: Vec<String> = row
        .iter()
        .enumerate()
        .map(|(column, cell)| {
            let width = widths.get(column).copied().unwrap_or(0);
            if column == last {
                cell.clone()
            } else {
                format!("{cell:<width$}")
            }
        })
        .collect();
    format!("{}\n", cells.join("  "))
}

pub(crate) fn report_error(io: &dyn Io, format: Format, error: &CliError) {
    let code = error.code.as_deref();
    let head = match code {
        Some(code) => format!("hasp: {code}: {}", error.message),
        None => format!("hasp: {}", error.message),
    };
    let line = match error.retry_after {
        Some(seconds) => format!("{head} (retry in {seconds} s)"),
        None => head,
    };
    io.err(&format!("{line}\n"));
    for candidate in &error.candidates {
        io.err(&format!("  {candidate}\n"));
    }
    if format == Format::Json {
        let document = json!({
            "schema_version": SCHEMA_VERSION,
            "error": {
                "exit": error.exit_code(),
                "code": code,
                "message": error.message,
                "candidates": error.candidates,
                "retry_after": error.retry_after,
            },
        });
        io.out(format!("{document}\n").as_bytes()).ok();
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{display, escape_controls};

    #[test]
    fn terminal_escapes_in_vault_data_are_neutralised() {
        let hostile = "Bank\u{1b}]52;c;ZXZpbA==\u{7}\u{9b}2J\nnext";
        let shown = display(&json!(hostile));
        assert!(shown.chars().all(|c| !c.is_control()));
        assert!(shown.contains("\\u{1b}"));
        assert!(!escape_controls(hostile, true).contains('\u{1b}'));
        assert!(escape_controls(hostile, true).contains('\n'));
    }
}
