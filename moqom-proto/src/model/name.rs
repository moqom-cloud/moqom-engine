//! Track namespaces and full track names, per draft-19 §2.4.1.
//!
//! A namespace is an ordered tuple of byte strings rather than a flat string,
//! and that structure is load-bearing: relays match on *prefixes*, which is how
//! `SUBSCRIBE_NAMESPACE` yields a room roster without a roster protocol. Every
//! room, participant, and device in MOQOM is a position in a tuple.
//!
//! Values are compared bytewise. The specification deliberately imposes no
//! character encoding, so anything that wants UTF-8 must canonicalise before it
//! gets here or exact comparison stops meaning what it appears to mean.

use bytes::{Buf, BufMut, Bytes};

use crate::error::DecodeError;
use crate::varint::VarInt;

/// Maximum number of fields in a namespace (draft-19 §2.4.1).
pub const MAX_FIELDS: usize = 32;

/// Maximum total byte length of a namespace, and of a full track name.
///
/// Counts field *values* only — the varint length prefixes are excluded.
pub const MAX_LEN: usize = 4096;

/// A namespace or track name that violates draft-19 §2.4.1.
///
/// Every variant corresponds to a `PROTOCOL_VIOLATION` when it arrives from a
/// peer, which is why construction is fallible: making these unrepresentable
/// means the rest of the stack cannot accidentally emit one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    /// More than [`MAX_FIELDS`] namespace fields.
    #[error("namespace has more than {MAX_FIELDS} fields")]
    TooManyFields,

    /// A namespace field of zero length, which the specification forbids.
    #[error("namespace field is empty")]
    EmptyField,

    /// Total length exceeds [`MAX_LEN`] bytes.
    #[error("name exceeds {MAX_LEN} bytes")]
    TooLong,
}

impl From<NameError> for DecodeError {
    fn from(e: NameError) -> Self {
        Self::Invalid(match e {
            NameError::TooManyFields => "namespace has too many fields",
            NameError::EmptyField => "namespace field is empty",
            NameError::TooLong => "name exceeds maximum length",
        })
    }
}

/// An ordered tuple of byte strings identifying a namespace.
///
/// Cheap to clone: fields are [`Bytes`], so cloning bumps refcounts rather than
/// copying. The relay clones namespaces constantly during subscription
/// matching, which makes that the difference between a memcpy per match and
/// nothing.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct TrackNamespace {
    fields: Vec<Bytes>,
}

impl TrackNamespace {
    /// The empty namespace, which is valid and matches everything as a prefix.
    #[must_use]
    pub const fn empty() -> Self {
        Self { fields: Vec::new() }
    }

    /// Construct from fields, validating field count, emptiness, and length.
    ///
    /// # Errors
    /// [`NameError`] if any draft-19 §2.4.1 constraint is violated.
    pub fn new(fields: Vec<Bytes>) -> Result<Self, NameError> {
        if fields.len() > MAX_FIELDS {
            return Err(NameError::TooManyFields);
        }
        let mut total = 0usize;
        for field in &fields {
            if field.is_empty() {
                return Err(NameError::EmptyField);
            }
            total += field.len();
            if total > MAX_LEN {
                return Err(NameError::TooLong);
            }
        }
        Ok(Self { fields })
    }

    /// Construct from anything sliceable, copying each field.
    ///
    /// Convenience for building namespaces from literals and owned strings:
    /// `TrackNamespace::from_parts(["acme", "r", "room-42"])`.
    ///
    /// # Errors
    /// [`NameError`] if any draft-19 §2.4.1 constraint is violated.
    pub fn from_parts<I, T>(parts: I) -> Result<Self, NameError>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        Self::new(
            parts
                .into_iter()
                .map(|p| Bytes::copy_from_slice(p.as_ref()))
                .collect(),
        )
    }

    /// The fields, in order.
    #[must_use]
    pub fn fields(&self) -> &[Bytes] {
        &self.fields
    }

    /// Number of fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether the namespace has no fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Total length of all field values, excluding length prefixes.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.fields.iter().map(Bytes::len).sum()
    }

    /// Append a field.
    ///
    /// # Errors
    /// [`NameError`] if the result would violate a constraint.
    pub fn push(&mut self, field: Bytes) -> Result<(), NameError> {
        if field.is_empty() {
            return Err(NameError::EmptyField);
        }
        if self.fields.len() == MAX_FIELDS {
            return Err(NameError::TooManyFields);
        }
        if self.byte_len() + field.len() > MAX_LEN {
            return Err(NameError::TooLong);
        }
        self.fields.push(field);
        Ok(())
    }

    /// Whether `prefix` is a leading subsequence of this namespace.
    ///
    /// This is the operation `SUBSCRIBE_NAMESPACE` is built on, and the reason
    /// namespaces are tuples rather than strings. Comparing tuple fields cannot
    /// produce the false match that string prefixes can: `("acme", "room")` is
    /// not a prefix of `("acme", "roomies")`, though `"acme/room"` *is* a
    /// string prefix of `"acme/roomies"`.
    #[must_use]
    pub fn starts_with(&self, prefix: &Self) -> bool {
        prefix.fields.len() <= self.fields.len()
            && prefix.fields.iter().zip(&self.fields).all(|(a, b)| a == b)
    }

    /// The field count as a varint.
    ///
    /// Infallible rather than checked: the constructors cap the count at
    /// [`MAX_FIELDS`] and `fields` is private, so the cast cannot truncate.
    /// Encoding a namespace is on the hot path and should not be able to panic.
    fn count_varint(&self) -> VarInt {
        debug_assert!(self.fields.len() <= MAX_FIELDS);
        VarInt::from_u32(self.fields.len() as u32)
    }

    /// A field length as a varint, infallible for the same reason: every field
    /// is at most [`MAX_LEN`] bytes.
    fn field_len_varint(field: &Bytes) -> VarInt {
        debug_assert!(field.len() <= MAX_LEN);
        VarInt::from_u32(field.len() as u32)
    }

    /// Encoded size in bytes, including length prefixes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.count_varint().size()
            + self
                .fields
                .iter()
                .map(|f| Self::field_len_varint(f).size() + f.len())
                .sum::<usize>()
    }

    /// Append the wire representation to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        self.count_varint().encode(buf);
        for field in &self.fields {
            Self::field_len_varint(field).encode(buf);
            buf.put_slice(field);
        }
    }

    /// Read a namespace from `buf`.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] if any
    /// §2.4.1 constraint is violated.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        let count = VarInt::decode(buf)?.get();

        // Bound the count *before* allocating. It is a peer-supplied varint, so
        // it can claim 2^62 fields, and reserving on it would be a
        // one-message OOM.
        if count > MAX_FIELDS as u64 {
            return Err(NameError::TooManyFields.into());
        }
        let count = count as usize;

        let mut fields = Vec::with_capacity(count);
        let mut total = 0usize;
        for _ in 0..count {
            let len = VarInt::decode(buf)?.get();
            let len =
                usize::try_from(len).map_err(|_| DecodeError::Invalid("field length overflow"))?;

            if len == 0 {
                return Err(NameError::EmptyField.into());
            }
            total += len;
            if total > MAX_LEN {
                return Err(NameError::TooLong.into());
            }
            if buf.remaining() < len {
                return Err(DecodeError::Short {
                    needed: len - buf.remaining(),
                });
            }
            fields.push(buf.copy_to_bytes(len));
        }

        Ok(Self { fields })
    }
}

/// A namespace paired with a track name, uniquely identifying a track.
///
/// The default is the empty namespace with an empty name. That is not a
/// placeholder: draft-19's Redirect structure uses exactly that encoding to
/// mean "reuse the original request's track".
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct FullTrackName {
    namespace: TrackNamespace,
    name: Bytes,
}

impl FullTrackName {
    /// Pair a namespace with a name, checking the combined length.
    ///
    /// # Errors
    /// [`NameError::TooLong`] if namespace bytes plus name bytes exceed
    /// [`MAX_LEN`].
    pub fn new(namespace: TrackNamespace, name: Bytes) -> Result<Self, NameError> {
        if namespace.byte_len() + name.len() > MAX_LEN {
            return Err(NameError::TooLong);
        }
        Ok(Self { namespace, name })
    }

    /// The namespace.
    #[must_use]
    pub fn namespace(&self) -> &TrackNamespace {
        &self.namespace
    }

    /// The track name, which may be empty.
    #[must_use]
    pub fn name(&self) -> &Bytes {
        &self.name
    }

    /// Encoded size in bytes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.namespace.encoded_len() + crate::coding::encoded_bytes_len(&self.name)
    }

    /// Append the wire representation to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        self.namespace.encode(buf);
        crate::coding::encode_bytes(buf, &self.name);
    }

    /// Read a full track name from `buf`.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] if a
    /// constraint is violated.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        let namespace = TrackNamespace::decode(buf)?;

        // The name's own bound is whatever the namespace has not already spent.
        let remaining_budget = MAX_LEN - namespace.byte_len();
        let name = crate::coding::decode_bytes(buf, remaining_budget)?;

        Ok(Self {
            namespace,
            name: Bytes::from(name),
        })
    }
}

/// Render bytes as a string when they are valid UTF-8 and as hex otherwise.
///
/// Namespaces are conventionally UTF-8 even though the wire format does not
/// require it, and an unreadable namespace in a log is a real cost when
/// debugging subscription matching.
fn render(bytes: &[u8], f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return write!(f, "{s:?}");
    }
    write!(f, "0x")?;
    for b in bytes {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

impl std::fmt::Debug for TrackNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(")?;
        for (i, field) in self.fields.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            render(field, f)?;
        }
        write!(f, ")")
    }
}

impl std::fmt::Debug for FullTrackName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}/", self.namespace)?;
        render(&self.name, f)
    }
}

/// Render bytes for [`Display`](std::fmt::Display): unquoted when UTF-8, hex
/// otherwise.
///
/// Separate from [`render`] because the two have different jobs. `Debug` quotes
/// and escapes, so a field containing a separator cannot be mistaken for two
/// fields; `Display` is for log lines and error messages read by people, where
/// quotes around every field are noise.
fn render_plain(bytes: &[u8], f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return f.write_str(s);
    }
    write!(f, "0x")?;
    for b in bytes {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

/// Slash-separated fields, which is how namespaces are written by hand.
///
/// Not a wire format and not reversible: a field may itself contain a slash, and
/// this does not escape it. Anything that needs to recover the fields must use
/// [`TrackNamespace::fields`] — the point of the tuple encoding is that the wire
/// never has to parse a separator, and rendering one here does not change that.
impl std::fmt::Display for TrackNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, field) in self.fields.iter().enumerate() {
            if i > 0 {
                f.write_str("/")?;
            }
            render_plain(field, f)?;
        }
        Ok(())
    }
}

/// The namespace, then the track name, separated the same way.
impl std::fmt::Display for FullTrackName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.namespace.is_empty() {
            write!(f, "{}/", self.namespace)?;
        }
        render_plain(&self.name, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(parts: &[&str]) -> TrackNamespace {
        TrackNamespace::from_parts(parts).unwrap()
    }

    #[test]
    fn round_trips() {
        for case in [
            ns(&[]),
            ns(&["acme"]),
            ns(&["acme", "r", "room-42", "alice", "iphone"]),
        ] {
            let mut buf = Vec::new();
            case.encode(&mut buf);
            assert_eq!(
                buf.len(),
                case.encoded_len(),
                "encoded_len disagrees for {case:?}"
            );

            let mut cursor = buf.as_slice();
            assert_eq!(TrackNamespace::decode(&mut cursor).unwrap(), case);
            assert!(cursor.is_empty());
        }
    }

    /// The reason namespaces are tuples. A string-prefix scheme would match
    /// `"acme/room"` against `"acme/roomies"` and leak one room's roster into
    /// another's subscription.
    #[test]
    fn prefix_matching_cannot_partially_match_a_field() {
        let room = ns(&["acme", "r", "room"]);
        let roomies = ns(&["acme", "r", "roomies"]);

        assert!(roomies.starts_with(&ns(&["acme", "r"])));
        assert!(!roomies.starts_with(&room));
        assert!(!room.starts_with(&roomies));

        assert!(
            room.starts_with(&ns(&[])),
            "empty namespace is a prefix of everything"
        );
        assert!(room.starts_with(&room), "a namespace is its own prefix");
        assert!(
            !ns(&["acme"]).starts_with(&room),
            "a prefix is not suffixed by its extension"
        );
    }

    #[test]
    fn rejects_spec_violations_at_construction() {
        assert_eq!(
            TrackNamespace::new(vec![Bytes::from_static(b"")]).unwrap_err(),
            NameError::EmptyField
        );

        let too_many: Vec<Bytes> = (0..=MAX_FIELDS).map(|_| Bytes::from_static(b"x")).collect();
        assert_eq!(
            TrackNamespace::new(too_many).unwrap_err(),
            NameError::TooManyFields
        );

        let oversized = vec![Bytes::from(vec![b'x'; MAX_LEN + 1])];
        assert_eq!(
            TrackNamespace::new(oversized).unwrap_err(),
            NameError::TooLong
        );

        assert!(TrackNamespace::new(vec![Bytes::from(vec![b'x'; MAX_LEN])]).is_ok());
    }

    /// A peer can claim 2^62 fields in a single varint. Reserving on that
    /// number before reading any of them is a one-message memory exhaustion,
    /// so the bound has to be checked before the allocation.
    #[test]
    fn absurd_field_count_is_rejected_before_allocating() {
        let mut buf = Vec::new();
        VarInt::new(1 << 40).unwrap().encode(&mut buf);

        let mut cursor = buf.as_slice();
        let err = TrackNamespace::decode(&mut cursor).unwrap_err();
        assert!(err.is_fatal());
        assert_eq!(err, NameError::TooManyFields.into());
    }

    #[test]
    fn truncated_namespace_is_short_not_fatal() {
        let mut buf = Vec::new();
        ns(&["acme", "room"]).encode(&mut buf);

        for cut in 1..buf.len() {
            let mut cursor = &buf[..cut];
            let err = TrackNamespace::decode(&mut cursor).unwrap_err();
            assert!(
                !err.is_fatal(),
                "truncating to {cut} bytes should be a short read, got {err}"
            );
        }
    }

    #[test]
    fn full_track_name_round_trips_including_empty_name() {
        for name in [Bytes::from_static(b""), Bytes::from_static(b"video")] {
            let original = FullTrackName::new(ns(&["acme", "r", "room-42"]), name).unwrap();

            let mut buf = Vec::new();
            original.encode(&mut buf);
            assert_eq!(buf.len(), original.encoded_len());

            let mut cursor = buf.as_slice();
            assert_eq!(FullTrackName::decode(&mut cursor).unwrap(), original);
            assert!(cursor.is_empty());
        }
    }

    /// The 4096 limit applies to the namespace and the name *together*, so a
    /// namespace that is itself legal can still leave no room for a name.
    #[test]
    fn full_track_name_length_budget_is_shared() {
        let full = TrackNamespace::new(vec![Bytes::from(vec![b'x'; MAX_LEN])]).unwrap();

        assert!(FullTrackName::new(full.clone(), Bytes::from_static(b"")).is_ok());
        assert_eq!(
            FullTrackName::new(full, Bytes::from_static(b"v")).unwrap_err(),
            NameError::TooLong
        );
    }

    #[test]
    fn debug_renders_utf8_and_falls_back_to_hex() {
        assert_eq!(format!("{:?}", ns(&["acme", "r"])), r#"("acme", "r")"#);

        let binary = TrackNamespace::new(vec![Bytes::from_static(&[0xff, 0x00])]).unwrap();
        assert_eq!(format!("{binary:?}"), "(0xff00)");
    }

    mod properties {
        use proptest::prelude::*;

        use super::*;

        /// Valid namespaces: 0..=32 fields, each 1..=64 bytes of arbitrary
        /// data, which keeps the total well inside [`MAX_LEN`].
        fn any_namespace() -> impl Strategy<Value = TrackNamespace> {
            prop::collection::vec(prop::collection::vec(any::<u8>(), 1..64), 0..=MAX_FIELDS)
                .prop_map(|fields| {
                    TrackNamespace::new(fields.into_iter().map(Bytes::from).collect()).unwrap()
                })
        }

        proptest! {
            #[test]
            fn round_trips(namespace in any_namespace()) {
                let mut buf = Vec::new();
                namespace.encode(&mut buf);
                prop_assert_eq!(buf.len(), namespace.encoded_len());

                let mut cursor = buf.as_slice();
                prop_assert_eq!(TrackNamespace::decode(&mut cursor).unwrap(), namespace);
                prop_assert!(cursor.is_empty());
            }

            /// The decoder is fed peer-controlled bytes on every message, so
            /// the floor is that it terminates with a verdict and never panics
            /// or over-reads.
            #[test]
            fn decode_is_total(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
                let mut cursor = bytes.as_slice();
                match TrackNamespace::decode(&mut cursor) {
                    Ok(n) => {
                        prop_assert!(n.len() <= MAX_FIELDS);
                        prop_assert!(n.byte_len() <= MAX_LEN);
                        prop_assert!(n.fields().iter().all(|f| !f.is_empty()));
                    }
                    Err(e) => prop_assert!(e.is_fatal() || cursor.len() <= bytes.len()),
                }
            }

            /// Every leading subsequence of a namespace is a prefix of it, and
            /// nothing longer is. This is the invariant relay subscription
            /// matching rests on.
            #[test]
            fn every_leading_subsequence_is_a_prefix(namespace in any_namespace()) {
                for i in 0..=namespace.len() {
                    let prefix =
                        TrackNamespace::new(namespace.fields()[..i].to_vec()).unwrap();
                    prop_assert!(namespace.starts_with(&prefix));

                    if i < namespace.len() {
                        prop_assert!(!prefix.starts_with(&namespace));
                    }
                }
            }
        }
    }

    #[test]
    fn push_enforces_the_same_rules_as_new() {
        let mut n = ns(&["acme"]);
        assert!(n.push(Bytes::from_static(b"r")).is_ok());
        assert_eq!(
            n.push(Bytes::from_static(b"")).unwrap_err(),
            NameError::EmptyField
        );
        assert_eq!(n.len(), 2, "a rejected push must not mutate");
    }
}
