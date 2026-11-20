use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use crate::model::ModelError;

const MAX_TAG_BYTES: usize = 256;

#[derive(Debug, Clone)]
pub struct Tag {
    original: String,
    key: String,
}

impl Tag {
    pub fn new(text: &str) -> Result<Self, ModelError> {
        let original = crate::text::nfc(text.trim());
        if original.is_empty()
            || original.len() > MAX_TAG_BYTES
            || original.split('/').any(|segment| segment.trim().is_empty())
            || original.chars().any(char::is_control)
        {
            return Err(ModelError::Tag);
        }
        let key = original.to_lowercase();
        Ok(Self { original, key })
    }

    pub fn as_str(&self) -> &str {
        &self.original
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.original.split('/').map(str::trim)
    }

    pub fn is_within(&self, ancestor: &Self) -> bool {
        self.key == ancestor.key
            || self
                .key
                .strip_prefix(ancestor.key.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
    }
}

impl PartialEq for Tag {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for Tag {}

impl PartialOrd for Tag {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Tag {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

impl Hash for Tag {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_case_and_normalisation_insensitively_and_keeps_original() {
        let composed = Tag::new("Work/\u{c11c}\u{bc84}").unwrap();
        let decomposed = Tag::new("work/\u{1109}\u{1165}\u{1107}\u{1165}").unwrap();
        assert_eq!(composed, decomposed);
        assert_eq!(composed.as_str(), "Work/\u{c11c}\u{bc84}");
        assert_eq!(
            Tag::new("CAFE\u{301}").unwrap(),
            Tag::new("caf\u{e9}").unwrap()
        );
    }

    #[test]
    fn rejects_empty_segments_and_controls() {
        for text in ["", "  ", "/", "a//b", "a/", "/a", "a\nb"] {
            assert!(Tag::new(text).is_err(), "{text:?}");
        }
        assert!(Tag::new(&"x".repeat(257)).is_err());
    }

    #[test]
    fn nesting_follows_slash_segments() {
        let parent = Tag::new("Work").unwrap();
        assert!(Tag::new("work/clients").unwrap().is_within(&parent));
        assert!(parent.is_within(&parent));
        assert!(!Tag::new("workshop").unwrap().is_within(&parent));
        assert_eq!(Tag::new("a/b/c").unwrap().segments().count(), 3);
    }
}
