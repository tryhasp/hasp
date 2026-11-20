use std::fs;
use std::path::PathBuf;

use hasp_proto::ProtoError;
use hasp_replay::{GROUPS, normalise_login, normalise_password, replay};
use serde_json::{Value, json};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors")
}

const CASES: &[(&str, &str, &[u32])] = &[
    (
        "ascii",
        "plain ASCII",
        &[
            0x63, 0x6f, 0x72, 0x72, 0x65, 0x63, 0x74, 0x20, 0x68, 0x6f, 0x72, 0x73, 0x65,
        ],
    ),
    (
        "trim-ascii",
        "spaces, tab and newline around the text",
        &[
            0x20, 0x09, 0x70, 0x61, 0x73, 0x73, 0x20, 0x77, 0x6f, 0x72, 0x64, 0x0a, 0x20,
        ],
    ),
    (
        "trim-ideographic-space",
        "U+3000 around the text",
        &[0x3000, 0x70, 0x77, 0x3000],
    ),
    (
        "trim-nbsp",
        "U+00A0 around the text",
        &[0xa0, 0x70, 0x77, 0xa0],
    ),
    (
        "trim-next-line",
        "U+0085 NEL around the text",
        &[0x85, 0x70, 0x77, 0x85],
    ),
    (
        "trim-bom",
        "U+FEFF byte order mark before the text",
        &[0xfeff, 0x70, 0x77],
    ),
    (
        "trim-zero-width-space",
        "U+200B is not whitespace",
        &[0x200b, 0x70, 0x77, 0x200b],
    ),
    (
        "trim-line-separator",
        "U+2028 around the text",
        &[0x2028, 0x70, 0x77, 0x2028],
    ),
    (
        "trim-only-whitespace",
        "whitespace only",
        &[0x20, 0x3000, 0x09],
    ),
    ("empty", "empty string", &[]),
    (
        "korean-precomposed",
        "Hangul syllables U+BE44 U+BC00 U+BC88 U+D638 (NFC)",
        &[0xbe44, 0xbc00, 0xbc88, 0xd638],
    ),
    (
        "korean-conjoining-jamo",
        "same word as conjoining jamo (NFD)",
        &[
            0x1107, 0x1175, 0x1106, 0x1175, 0x11af, 0x1107, 0x1165, 0x11ab, 0x1112, 0x1169,
        ],
    ),
    (
        "korean-compat-jamo",
        "compatibility jamo U+3142 U+3163 U+3141 U+3163 U+3139",
        &[0x3142, 0x3163, 0x3141, 0x3163, 0x3139],
    ),
    (
        "korean-mixed-latin",
        "Hangul with Latin and digits",
        &[
            0xd55c, 0xae00, 0x50, 0x61, 0x73, 0x73, 0x31, 0x32, 0x33, 0x21,
        ],
    ),
    (
        "korean-halfwidth-jamo",
        "halfwidth Hangul U+FFA1 U+FFC2",
        &[0xffa1, 0xffc2],
    ),
    (
        "korean-syllable-lvt",
        "U+AC01 (LVT) and U+AC00 (LV)",
        &[0xac01, 0xac00],
    ),
    (
        "fullwidth-latin",
        "fullwidth Latin and digits",
        &[0xff30, 0xff21, 0xff33, 0xff33, 0xff11, 0xff12, 0xff13],
    ),
    (
        "fullwidth-lower",
        "fullwidth lowercase",
        &[0xff50, 0xff41, 0xff53, 0xff53],
    ),
    ("ligature-fi", "U+FB01 fi ligature", &[0xfb01, 0x6c, 0x65]),
    ("ligature-ffi", "U+FB03 ffi ligature", &[0xfb03, 0x63, 0x65]),
    (
        "circled-digits",
        "U+2460 to U+2462",
        &[0x2460, 0x2461, 0x2462],
    ),
    ("superscript", "x followed by U+00B2", &[0x78, 0xb2]),
    ("roman-numeral", "U+2163", &[0x2163]),
    ("arabic-ligature", "U+FDFA expands to 18 scalars", &[0xfdfa]),
    ("ohm-sign", "U+2126 OHM SIGN", &[0x2126]),
    ("angstrom-sign", "U+212B ANGSTROM SIGN", &[0x212b]),
    ("latin-precomposed", "U+00E9", &[0xe9]),
    ("latin-decomposed", "e U+0301", &[0x65, 0x301]),
    ("latin-capital-e-acute", "U+00C9", &[0xc9]),
    (
        "combining-order",
        "a U+0323 U+0301 versus U+0301 U+0323 canonical ordering",
        &[0x61, 0x301, 0x323],
    ),
    (
        "turkish-dotted-capital-i",
        "U+0130 I with dot above",
        &[0x130],
    ),
    ("turkish-dotless-small-i", "U+0131 dotless i", &[0x131]),
    (
        "turkish-word-istanbul",
        "ISTANBUL with U+0130",
        &[0x130, 0x53, 0x54, 0x41, 0x4e, 0x42, 0x55, 0x4c],
    ),
    (
        "turkish-word-kiraz",
        "KIRAZ with ASCII I",
        &[0x4b, 0x49, 0x52, 0x41, 0x5a],
    ),
    ("german-sharp-s", "U+00DF", &[0xdf]),
    ("german-capital-sharp-s", "U+1E9E", &[0x1e9e]),
    (
        "german-strasse",
        "STRASSE and Strasse with U+00DF",
        &[0x53, 0x74, 0x72, 0x61, 0xdf, 0x65],
    ),
    (
        "greek-final-sigma",
        "ODYSSEUS with capital sigma at the end",
        &[0x39f, 0x394, 0x3a5, 0x3a3, 0x3a3, 0x395, 0x3a5, 0x3a3],
    ),
    ("greek-small-final-sigma", "U+03C2", &[0x3c2]),
    ("greek-sigma-alone", "U+03A3", &[0x3a3]),
    ("cherokee", "U+13A0 and U+AB70", &[0x13a0, 0xab70]),
    ("titlecase-digraph", "U+01C5", &[0x1c5]),
    ("long-s", "U+017F LATIN SMALL LETTER LONG S", &[0x17f]),
    ("kelvin-sign", "U+212A KELVIN SIGN", &[0x212a]),
    ("emoji", "U+1F510 with ascii", &[0x1f510, 0x70, 0x77]),
    (
        "emoji-zwj-family",
        "man woman girl joined by ZWJ",
        &[0x1f468, 0x200d, 0x1f469, 0x200d, 0x1f467],
    ),
    ("emoji-skin-tone", "U+1F44D U+1F3FD", &[0x1f44d, 0x1f3fd]),
    (
        "unicode-16-cyrillic-tje",
        "U+1C89 added in Unicode 16.0",
        &[0x1c89],
    ),
    (
        "unicode-16-garay",
        "U+10D50 GARAY CAPITAL LETTER A, added in Unicode 16.0",
        &[0x10d50],
    ),
    (
        "unicode-15-1-cjk",
        "U+2EBF0 added in Unicode 15.1",
        &[0x2ebf0],
    ),
    (
        "unicode-17-sidetic",
        "U+10940 SIDETIC LETTER N01, added in Unicode 17.0",
        &[0x10940],
    ),
    (
        "unicode-18-armenian",
        "U+0558 added in Unicode 18.0",
        &[0x558],
    ),
    (
        "zero-width-space-inside",
        "U+200B between letters is default-ignorable",
        &[0x70, 0x200b, 0x77],
    ),
    (
        "soft-hyphen-inside",
        "U+00AD between letters is default-ignorable",
        &[0x70, 0xad, 0x77],
    ),
    (
        "greek-iota-subscript",
        "U+1F88 capital alpha with psili and prosgegrammeni",
        &[0x1f88],
    ),
    (
        "greek-iota-subscript-then-mark",
        "U+1F96 followed by U+0487",
        &[0x1f96, 0x487],
    ),
    (
        "unassigned-between-spaces",
        "U+0378 inside trimmed spaces",
        &[0x20, 0x378, 0x20],
    ),
    ("unassigned", "U+0378 is unassigned", &[0x378]),
    ("noncharacter", "U+FDD0", &[0xfdd0]),
    ("private-use", "U+E000", &[0xe000]),
    ("cjk-compat", "U+F900 compatibility ideograph", &[0xf900]),
    ("halfwidth-katakana", "U+FF76 U+FF9E", &[0xff76, 0xff9e]),
    (
        "mixed-case-ascii",
        "MiXeD CaSe",
        &[0x4d, 0x69, 0x58, 0x65, 0x44, 0x20, 0x43, 0x61, 0x53, 0x65],
    ),
    (
        "email-like",
        "User@Example.COM with fullwidth at-sign",
        &[
            0x55, 0x73, 0x65, 0x72, 0xff20, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x43,
            0x4f, 0x4d,
        ],
    ),
];

fn text_vectors(rule: &str, apply: fn(&str) -> Result<String, ProtoError>) -> Value {
    let cases: Vec<Value> = CASES
        .iter()
        .map(|(name, note, scalars)| {
            let input: String = scalars
                .iter()
                .filter_map(|code| char::from_u32(*code))
                .collect();
            match apply(&input) {
                Ok(output) => {
                    let utf8: String = output
                        .bytes()
                        .flat_map(|byte| [byte >> 4, byte & 15])
                        .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
                        .collect();
                    json!({ "name": name, "note": note, "scalars": scalars, "utf8": utf8 })
                }
                Err(error) => {
                    json!({ "name": name, "note": note, "scalars": scalars, "err": error.name() })
                }
            }
        })
        .collect();
    json!({
        "rule": rule,
        "generator": "hasp-replay: HASP_UPDATE_VECTORS=1 cargo test -p hasp-replay",
        "cases": cases,
    })
}

fn sync(name: &str, value: &Value) {
    let path = root().join("text").join(name);
    let text = format!(
        "{}\n",
        serde_json::to_string_pretty(value).unwrap_or_default()
    );
    if std::env::var_os("HASP_UPDATE_VECTORS").is_some() {
        fs::create_dir_all(root().join("text")).unwrap_or_default();
        fs::write(&path, &text).unwrap_or_default();
    }
    assert_eq!(
        fs::read_to_string(&path).unwrap_or_default(),
        text,
        "{name} is out of date"
    );
}

#[test]
fn text_vectors_are_current() {
    sync(
        "password.json",
        &text_vectors("trim (Unicode White_Space), NFKD (protocol 2.1)", |input| {
            Ok(normalise_password(input))
        }),
    );
    sync(
        "login.json",
        &text_vectors(
            "trim (Unicode White_Space), reject unassigned, NFKC_Casefold, Unicode 18.0.0 (protocol 2.1)",
            normalise_login,
        ),
    );
}

#[test]
fn every_group_replays_identically() {
    for group in GROUPS {
        let path = root().join(format!("{group}.json"));
        let json = fs::read_to_string(&path).unwrap_or_default();
        let outcomes = replay(group, &json).unwrap_or_else(|error| panic!("{group}: {error}"));
        assert!(!outcomes.is_empty(), "{group}");
        for outcome in outcomes {
            assert!(
                outcome.matches(),
                "{group} {}: expected {} got {}",
                outcome.name,
                outcome.expected,
                outcome.actual
            );
        }
    }
}
