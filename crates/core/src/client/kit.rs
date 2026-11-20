mod pdf;

use std::fmt::Write;

use hasp_proto::crockford_encode;
use zeroize::Zeroizing;

use super::signup::EmergencyKit;
use crate::CoreError;

const KIT_FORMAT: u64 = 1;

const WARNINGS: [&str; 3] = [
    "This kit and your account password together unlock the account. Keep both safe.",
    "Keep the recovery code apart from this kit.",
    "Print it, then delete the file. The server never holds the Secret Key.",
];

/// The Emergency Kit of protocol 4.4 in both forms: exact text and a printable one-page PDF.
pub struct KitDocument {
    pub text: Zeroizing<String>,
    pub pdf: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for KitDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KitDocument(..)")
    }
}

impl EmergencyKit {
    /// The QR payload of protocol 4.4: the opaque Crockford base32 of `qr_blob`.
    pub fn qr_text(&self) -> Result<Zeroizing<String>, CoreError> {
        Ok(Zeroizing::new(crockford_encode(&self.qr_blob()?)))
    }

    pub fn text(&self, created: u64) -> String {
        let mut out = String::new();
        let _written = write!(
            out,
            "Hasp Emergency Kit\nCreated {}, kit version {KIT_FORMAT}\n\n",
            date(created)
        );
        for (label, value) in self.rows() {
            let _written = writeln!(out, "{label}: {value}");
        }
        out.push('\n');
        for line in WARNINGS {
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// The kit as text plus a PDF. The PDF uses the standard Latin-1 fonts, so a login with
    /// characters outside Latin-1 prints them as `?`; the QR code and the text carry it exactly.
    pub fn document(&self, created: u64) -> Result<KitDocument, CoreError> {
        let qr = self.qr_text()?;
        Ok(KitDocument {
            text: Zeroizing::new(self.text(created)),
            pdf: Zeroizing::new(pdf::render(&pdf::Page {
                title: "Hasp Emergency Kit",
                subtitle: &format!("Created {}, kit version {KIT_FORMAT}", date(created)),
                rows: &self.rows(),
                warnings: &WARNINGS,
                qr: qr.as_bytes(),
            })?),
        })
    }

    fn rows(&self) -> [(&'static str, &str); 5] {
        [
            ("Server", &self.origin),
            ("Login id", &self.login),
            ("Secret Key", self.secret_key()),
            ("Server key fingerprint", &self.server_fingerprint),
            ("Account password", ""),
        ]
    }
}

fn date(unix: u64) -> String {
    let days = i64::try_from(unix / 86_400).unwrap_or(0);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests;
