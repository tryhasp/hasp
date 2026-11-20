use std::fmt::Write;

use secrecy::ExposeSecret;

use crate::model::item::{Details, Item};

use super::reading::text_of;

pub fn signature(item: &Item) -> String {
    let mut out = overview_line(item);
    let d = item.details();
    section_lines(&mut out, d);
    url_lines(&mut out, d);
    for a in &d.apps {
        writeln!(out, "A {a:?}").unwrap();
    }
    passkey_lines(&mut out, d);
    history_lines(&mut out, d);
    out
}

fn overview_line(item: &Item) -> String {
    let o = item.overview();
    format!(
        "{}|{}|{}|{:?}|{:?}|{:?}|{}|{}|{:?}|{:?}\n",
        o.kind,
        o.title,
        o.subtitle,
        o.tags
            .iter()
            .map(crate::model::tag::Tag::as_str)
            .collect::<Vec<_>>(),
        o.favourite,
        o.state,
        o.created,
        o.client_modified,
        o.flags,
        item.details().notes
    )
}

fn section_lines(out: &mut String, d: &Details) {
    for section in &d.sections {
        writeln!(out, "S {:?} {:?}", section.id(), section.title()).unwrap();
        for f in section.fields() {
            writeln!(
                out,
                "F {:?} {} {:?} {:?} {} {} {}",
                f.id(),
                f.label(),
                f.kind(),
                f.purpose(),
                f.is_concealed(),
                f.expires_alert(),
                text_of(f)
            )
            .unwrap();
        }
    }
}

fn url_lines(out: &mut String, d: &Details) {
    for u in &d.urls {
        writeln!(
            out,
            "U {:?} {} {:?} {:?} {:?}",
            u.id(),
            u.url(),
            u.mode(),
            u.confirmed_hosts(),
            u.kind()
        )
        .unwrap();
    }
}

fn passkey_lines(out: &mut String, d: &Details) {
    for p in &d.passkeys {
        writeln!(
            out,
            "K {:?} {} {:?} {} {} {} {:?} {} {:?} {} {}",
            p.credential_id,
            p.rp_id,
            p.user_handle,
            p.user_name,
            p.display_name,
            p.algorithm,
            p.private_key.expose_secret(),
            p.created,
            p.last_used,
            p.backup_eligible,
            p.backed_up
        )
        .unwrap();
    }
}

fn history_lines(out: &mut String, d: &Details) {
    for h in &d.password_history {
        writeln!(
            out,
            "H {} {} {:?}",
            h.value.expose_secret(),
            h.replaced_at,
            h.field
        )
        .unwrap();
    }
}
