//! Reason phrases, per draft-19 §1.4.4.

use bytes::{Buf, BufMut, Bytes};

use crate::coding::{decode_bytes, encode_bytes, encoded_bytes_len};
use crate::error::DecodeError;

/// Maximum reason phrase length in bytes.
pub const MAX_LEN: usize = 1024;

/// A reason phrase exceeded [`MAX_LEN`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("reason phrase is {len} bytes, exceeding the {MAX_LEN} byte maximum")]
pub struct ReasonTooLong {
    /// The oversized length.
    pub len: usize,
}

/// Human-readable diagnostic text attached to an error.
///
/// Carried as UTF-8 but decoded as bytes. A peer that sends invalid UTF-8 has
/// violated a SHOULD, and dropping an otherwise well-formed error message over
/// bad diagnostic text would discard the very information needed to work out
/// what went wrong. Validity is offered as a question ([`Self::as_str`]) rather
/// than imposed as a precondition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReasonPhrase(Bytes);

impl ReasonPhrase {
    /// An empty reason phrase.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Bytes::new())
    }

    /// Build from bytes.
    ///
    /// # Errors
    /// [`ReasonTooLong`] beyond [`MAX_LEN`].
    pub fn new(text: impl Into<Bytes>) -> Result<Self, ReasonTooLong> {
        let text = text.into();
        if text.len() > MAX_LEN {
            return Err(ReasonTooLong { len: text.len() });
        }
        Ok(Self(text))
    }

    /// Build from a string, truncating at a character boundary if needed.
    ///
    /// Useful where the text is a formatted diagnostic that could exceed the
    /// limit: losing the tail of a message is better than failing to report the
    /// error at all.
    #[must_use]
    pub fn truncating(text: &str) -> Self {
        if text.len() <= MAX_LEN {
            return Self(Bytes::copy_from_slice(text.as_bytes()));
        }
        let mut end = MAX_LEN;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        Self(Bytes::copy_from_slice(&text.as_bytes()[..end]))
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    /// The text, if it is valid UTF-8.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// Whether the phrase is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Encoded size in bytes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        encoded_bytes_len(&self.0)
    }

    /// Append the length-prefixed phrase to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        encode_bytes(buf, &self.0);
    }

    /// Read a length-prefixed phrase.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] if the
    /// declared length exceeds [`MAX_LEN`], which draft-19 makes a
    /// `PROTOCOL_VIOLATION`.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        Ok(Self(Bytes::from(decode_bytes(buf, MAX_LEN)?)))
    }
}

impl std::fmt::Display for ReasonPhrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.as_str() {
            Some(text) => f.write_str(text),
            None => write!(f, "<{} bytes of non-UTF-8>", self.0.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for text in ["", "not found", "τρόπος"] {
            let phrase = ReasonPhrase::new(text.as_bytes().to_vec()).unwrap();
            let mut buf = Vec::new();
            phrase.encode(&mut buf);
            assert_eq!(buf.len(), phrase.encoded_len());

            let mut cursor = buf.as_slice();
            let decoded = ReasonPhrase::decode(&mut cursor).unwrap();
            assert_eq!(decoded, phrase);
            assert_eq!(decoded.as_str(), Some(text));
        }
    }

    #[test]
    fn rejects_oversized_input() {
        assert!(ReasonPhrase::new(vec![b'x'; MAX_LEN]).is_ok());
        assert_eq!(
            ReasonPhrase::new(vec![b'x'; MAX_LEN + 1]),
            Err(ReasonTooLong { len: MAX_LEN + 1 })
        );
    }

    #[test]
    fn an_oversized_declared_length_is_fatal() {
        let mut buf = Vec::new();
        crate::varint::VarInt::new(MAX_LEN as u64 + 1)
            .unwrap()
            .encode(&mut buf);
        buf.extend_from_slice(&vec![b'x'; MAX_LEN + 1]);

        let mut cursor = buf.as_slice();
        assert!(ReasonPhrase::decode(&mut cursor).unwrap_err().is_fatal());
    }

    /// Truncation must not split a multi-byte character, or the result is not
    /// the UTF-8 the field is defined to carry.
    #[test]
    fn truncation_respects_character_boundaries() {
        let text = "é".repeat(MAX_LEN); // two bytes each
        let phrase = ReasonPhrase::truncating(&text);

        assert!(phrase.as_bytes().len() <= MAX_LEN);
        assert!(phrase.as_str().is_some(), "truncated mid-character");
        assert_eq!(
            phrase.as_bytes().len(),
            MAX_LEN,
            "should fill the budget exactly"
        );

        let short = ReasonPhrase::truncating("fine");
        assert_eq!(short.as_str(), Some("fine"));
    }

    /// Invalid UTF-8 should not cost us the error report it accompanies.
    #[test]
    fn invalid_utf8_decodes_and_displays_safely() {
        let mut buf = Vec::new();
        encode_bytes(&mut buf, &[0xFF, 0xFE]);

        let mut cursor = buf.as_slice();
        let phrase = ReasonPhrase::decode(&mut cursor).unwrap();
        assert!(phrase.as_str().is_none());
        assert_eq!(phrase.to_string(), "<2 bytes of non-UTF-8>");
    }

    #[test]
    fn empty_is_empty() {
        assert!(ReasonPhrase::empty().is_empty());
        assert_eq!(ReasonPhrase::empty().encoded_len(), 1);
    }
}
