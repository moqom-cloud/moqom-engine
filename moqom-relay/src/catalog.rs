//! What a publisher said about themselves, read from a `.catalog` object.
//!
//! Catalogs are sealed end to end like the media they describe. What a relay
//! may read is the catalog's disclosure, an object property in the shape of a
//! catalog that names each track's kind and geometry and the locale, and
//! nothing else; the functions here take its bytes. Media and the catalog body
//! stay opaque; this module is not a hole in that.
//!
//! Two things are taken: `locale`, for the control plane, and each track's
//! kind and geometry, which is what usage is tiered on (see [`crate::usage`]).
//! The rest of the document is for subscribers. A catalog this cannot parse is
//! ignored rather than failed: forwarding already happened, and a malformed
//! description must not take the session down.

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

/// What one catalogued track carries, as far as tiering needs to know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Described {
    /// A camera or screen rung. Either dimension may be missing from an older
    /// or hand-written catalog, which [`crate::usage`] then estimates.
    Video {
        /// Pixels across.
        width: Option<u32>,
        /// Pixels down.
        height: Option<u32>,
    },
    /// Audio or data: nothing that counts towards a tier.
    Other,
}

#[derive(serde::Deserialize)]
struct Document {
    #[serde(default)]
    tracks: Vec<Entry>,
}

#[derive(serde::Deserialize)]
struct Entry {
    name: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    width: Option<u32>,
    #[serde(default)]
    height: Option<u32>,
}

/// Every track a catalog object lists, by name, or `None` if the payload is
/// not a catalog this can read.
///
/// Fields beside these are ignored rather than refused: a catalog gaining a
/// field is a newer client, not a reason to stop tiering what it sends.
#[must_use]
pub fn tracks_in(payload: &[u8]) -> Option<Vec<(String, Described)>> {
    let document: Document = serde_json::from_slice(payload).ok()?;
    Some(
        document
            .tracks
            .into_iter()
            .filter(|entry| !entry.name.is_empty() && !entry.name.starts_with('.'))
            .map(|entry| {
                let described = match entry.kind.as_str() {
                    "video" | "screen" => Described::Video {
                        width: entry.width,
                        height: entry.height,
                    },
                    _ => Described::Other,
                };
                (entry.name, described)
            })
            .collect(),
    )
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
    fn a_catalog_describes_its_tracks() {
        let tracks = tracks_in(
            br#"{"version":1,"tracks":[
                {"name":"video/720p","kind":"video","width":1280,"height":720,"rung":1},
                {"name":"screen/1080p","kind":"screen"},
                {"name":"audio","kind":"audio","sampleRate":48000},
                {"name":".policy","kind":"data"}
            ]}"#,
        )
        .expect("a catalog");
        assert_eq!(
            tracks,
            [
                (
                    "video/720p".to_owned(),
                    Described::Video {
                        width: Some(1280),
                        height: Some(720)
                    }
                ),
                (
                    "screen/1080p".to_owned(),
                    Described::Video {
                        width: None,
                        height: None
                    }
                ),
                ("audio".to_owned(), Described::Other),
            ]
        );
        assert_eq!(tracks_in(b"not json"), None);
    }

    /// Byte for byte what `Catalog.disclosure()` writes in MoqomKit.
    #[test]
    fn a_disclosure_is_read_as_a_catalog() {
        let disclosure = br#"{"keyID":9,"locale":"fr-FR","tracks":[{"height":720,"kind":"video","name":"video\/720p","width":1280},{"kind":"audio","name":"audio"}],"version":1}"#;
        assert_eq!(locale_in(disclosure).as_deref(), Some("fr-FR"));
        assert_eq!(
            tracks_in(disclosure).expect("a catalog"),
            [
                (
                    "video/720p".to_owned(),
                    Described::Video {
                        width: Some(1280),
                        height: Some(720)
                    }
                ),
                ("audio".to_owned(), Described::Other),
            ]
        );
    }

    #[test]
    fn junk_is_not_a_catalog() {
        assert_eq!(locale_in(b"not json"), None);
        assert_eq!(locale_in(br#"{"locale":1}"#), None);
        assert_eq!(locale_in(br#"{"locale":"not a locale"}"#), None);
    }
}
