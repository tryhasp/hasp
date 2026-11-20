use std::io::Write;
use std::sync::Mutex;

use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

const REDACTED: &str = "[redacted]";

const SENSITIVE_FIELDS: &[&str] = &[
    "token",
    "authorization",
    "password",
    "login",
    "secret",
    "key",
    "body",
    "headers",
    "cookie",
];

const SENSITIVE_PREFIXES: &[&str] = &["SGN1-", "INV1-", "Bearer "];

#[derive(Debug)]
pub struct RedactingLayer<W> {
    out: Mutex<W>,
}

impl<W: Write + Send + 'static> RedactingLayer<W> {
    pub fn new(out: W) -> Self {
        Self {
            out: Mutex::new(out),
        }
    }
}

#[derive(Default)]
struct Collect {
    fields: Map<String, Value>,
}

fn guard(name: &str, value: Value) -> Value {
    let lower = name.to_ascii_lowercase();
    let named = SENSITIVE_FIELDS
        .iter()
        .any(|sensitive| lower == *sensitive || lower.ends_with(&format!("_{sensitive}")));
    let shaped = value.as_str().is_some_and(|text| {
        SENSITIVE_PREFIXES.iter().any(|prefix| {
            text.to_ascii_uppercase()
                .contains(&prefix.to_ascii_uppercase())
        })
    });
    if named || shaped {
        Value::String(REDACTED.to_owned())
    } else {
        value
    }
}

impl Visit for Collect {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields.insert(
            field.name().to_owned(),
            guard(field.name(), Value::String(value.to_owned())),
        );
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields.insert(
            field.name().to_owned(),
            guard(field.name(), Value::from(value)),
        );
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields.insert(
            field.name().to_owned(),
            guard(field.name(), Value::from(value)),
        );
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields.insert(
            field.name().to_owned(),
            guard(field.name(), Value::from(value)),
        );
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields.insert(
            field.name().to_owned(),
            guard(field.name(), Value::String(format!("{value:?}"))),
        );
    }
}

impl<S: Subscriber, W: Write + Send + 'static> Layer<S> for RedactingLayer<W> {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut collect = Collect::default();
        event.record(&mut collect);
        let mut line = Map::new();
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        line.insert("ts".to_owned(), Value::from(at));
        line.insert(
            "level".to_owned(),
            Value::from(event.metadata().level().as_str()),
        );
        line.insert("target".to_owned(), Value::from(event.metadata().target()));
        if let Some(message) = collect.fields.remove("message") {
            line.insert("msg".to_owned(), message);
        }
        line.extend(collect.fields);
        let Ok(mut text) = serde_json::to_string(&Value::Object(line)) else {
            return;
        };
        text.push('\n');
        if let Ok(mut out) = self.out.lock() {
            let _written = out.write_all(text.as_bytes());
        }
    }
}

pub fn init(level: &str) {
    let filter = match level {
        "error" => LevelFilter::ERROR,
        "warn" => LevelFilter::WARN,
        "debug" => LevelFilter::DEBUG,
        "trace" => LevelFilter::TRACE,
        _ => LevelFilter::INFO,
    };
    let _installed = tracing_subscriber::registry()
        .with(RedactingLayer::new(std::io::stderr()).with_filter(filter))
        .try_init();
}

#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub(crate) struct Sink(pub(crate) std::sync::Arc<Mutex<Vec<u8>>>);

#[cfg(test)]
impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut bytes) = self.0.lock() {
            bytes.extend_from_slice(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture(emit: impl FnOnce()) -> Vec<Value> {
        let sink = Sink::default();
        let subscriber = tracing_subscriber::registry().with(RedactingLayer::new(sink.clone()));
        tracing::subscriber::with_default(subscriber, emit);
        let bytes = sink.0.lock().unwrap().clone();
        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn writes_one_json_object_per_event() {
        let lines = capture(|| tracing::info!(op = "pull", status = 200_u16, "request"));
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["msg"], "request");
        assert_eq!(lines[0]["op"], "pull");
        assert_eq!(lines[0]["status"], 200);
        assert_eq!(lines[0]["level"], "INFO");
    }

    #[test]
    fn redacts_sensitive_field_names() {
        let lines = capture(|| {
            tracing::info!(
                token = "abc",
                login = "alice",
                session_token = "x",
                authorization = "y",
                "event"
            );
        });
        for name in ["token", "login", "session_token", "authorization"] {
            assert_eq!(lines[0][name], REDACTED, "{name}");
        }
    }

    #[test]
    fn redacts_values_shaped_like_codes_and_bearer_tokens() {
        let lines = capture(|| {
            tracing::warn!(
                detail = "SGN1-ABCDE",
                other = "Bearer abc",
                fine = "hello",
                "event"
            );
        });
        assert_eq!(lines[0]["detail"], REDACTED);
        assert_eq!(lines[0]["other"], REDACTED);
        assert_eq!(lines[0]["fine"], "hello");
    }

    #[test]
    fn keeps_the_error_code_name() {
        let lines = capture(|| tracing::info!(code = "E_AUTH", "request"));
        assert_eq!(lines[0]["code"], "E_AUTH");
    }
}
