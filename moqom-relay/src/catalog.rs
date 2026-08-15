//! What a publisher said about themselves, read from a `.catalog` object.
//!
//! Catalogs are the one payload a relay is allowed to look at. They are JSON,
//! they are never encrypted, and they exist so a third party — a viewer, a
//! recorder, this process — can read a publisher's description without our
//! client code. Media objects stay opaque; this module is not a hole in that.
//!
//! The only field taken today is `locale`. The rest of the document is for
//! subscribers. A catalog this cannot parse is ignored rather than failed:
//! forwarding already happened, and a malformed description must not take
//! the session down.

/// Longest BCP 47 tag we will store. Typical tags are much shorter.
const MAX_LOCALE: usize = 35;

/// The locale a catalog object names, if this payload is a catalog we can read.
///
/// `None` means the bytes are not a JSON object we understand — leave whatever
/// was last reported. `Some("")` means a readable catalog that does not claim
/// a locale, which is how a publisher clears one. `Some(tag)` is the tag.
#[must_use]
pub fn locale_in(payload: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let object = value.as_object()?;
    match object.get("locale") {
        None | Some(serde_json::Value::Null) => Some(String::new()),
        Some(value) => {
            let raw = value.as_str()?;
            if raw.is_empty() {
                return Some(String::new());
            }
            Some(normalize(raw)?)
        }
    }
}

/// A BCP 47 tag we will report, or `None` if it is not one.
fn normalize(raw: &str) -> Option<String> {
    let tag = raw.trim().replace('_', "-");
    if tag.is_empty() || tag.len() > MAX_LOCALE {
        return None;
    }
    let mut parts = tag.split('-');
    let language = parts.next()?;
    if !(2..=8).contains(&language.len()) || !language.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    for part in parts {
        if !(1..=8).contains(&part.len()) || !part.chars().all(|c| c.is_ascii_alphanumeric()) {
            return None;
        }
    }
    Some(tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_catalog_names_its_locale() {
        assert_eq!(
            locale_in(br#"{"version":1,"tracks":[],"locale":"en-US"}"#).as_deref(),
            Some("en-US")
        );
        assert_eq!(
            locale_in(br#"{"version":1,"tracks":[],"locale":"en_GB"}"#).as_deref(),
            Some("en-GB")
        );
    }

    #[test]
    fn an_older_catalog_clears_the_claim() {
        assert_eq!(
            locale_in(br#"{"version":1,"tracks":[]}"#).as_deref(),
            Some("")
        );
    }

    #[test]
    fn junk_is_not_a_catalog() {
        assert_eq!(locale_in(b"not json"), None);
        assert_eq!(locale_in(br#"{"locale":1}"#), None);
        assert_eq!(locale_in(br#"{"locale":"not a locale"}"#), None);
    }
}
