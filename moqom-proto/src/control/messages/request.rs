//! `REQUEST_OK` and `REQUEST_ERROR`, per draft-19 §10.5 and §10.6.
//!
//! Draft-19 collapsed the per-request response messages into this pair, so
//! `SUBSCRIBE_ERROR`, `FETCH_ERROR`, `ANNOUNCE_ERROR` and the rest are all one
//! message now, and `PUBLISH_OK`, `TRACK_STATUS_OK` and friends are shorthand
//! for a `REQUEST_OK` on the corresponding stream rather than distinct types.
//! `SUBSCRIBE_OK` and `FETCH_OK` are the two survivors, because they carry
//! fields nothing else does.
//!
//! Which request a response belongs to is not in the message. It is the
//! bidirectional stream the response arrives on.

use bytes::{Buf, BufMut, Bytes};

use crate::coding::{decode_bytes, encode_bytes, encoded_bytes_len};
use crate::control::params::Parameters;
use crate::control::properties::Properties;
use crate::control::reason::ReasonPhrase;
use crate::error::DecodeError;
use crate::model::FullTrackName;
use crate::varint::VarInt;

/// Maximum length of a Redirect's Connect URI, matching GOAWAY's limit.
pub const MAX_CONNECT_URI_LEN: usize = 8192;

/// A `REQUEST_ERROR` error code, per draft-19 §15.11.2.
///
/// A newtype rather than an enum because the registry is extensible and
/// reserves a greasing range: an unrecognised code is a code from a newer peer,
/// not a malformed message, and rejecting one would break exactly the
/// forward-compatibility the range exists to provide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestErrorCode(pub u64);

impl RequestErrorCode {
    /// An implementation-specific or generic failure.
    pub const INTERNAL_ERROR: Self = Self(0x0);
    /// Not authorized for this action on this track. May become retryable if
    /// the token is not yet valid.
    pub const UNAUTHORIZED: Self = Self(0x1);
    /// An implementation-specific timeout elapsed.
    pub const TIMEOUT: Self = Self(0x2);
    /// This request type is not supported.
    pub const NOT_SUPPORTED: Self = Self(0x3);
    /// Auth token failed to deserialize during registration.
    pub const MALFORMED_AUTH_TOKEN: Self = Self(0x4);
    /// Auth token has expired.
    pub const EXPIRED_AUTH_TOKEN: Self = Self(0x5);
    /// A GOAWAY was received, so new requests are being refused.
    pub const GOING_AWAY: Self = Self(0x6);
    /// Overloaded. Pair with a Retry Interval.
    pub const EXCESSIVE_LOAD: Self = Self(0x9);
    /// Track or namespace is not available here.
    pub const DOES_NOT_EXIST: Self = Self(0x10);
    /// The requested filter or location range cannot be satisfied.
    pub const INVALID_RANGE: Self = Self(0x11);
    /// A relay publisher found the track malformed.
    pub const MALFORMED_TRACK: Self = Self(0x12);
    /// The subscriber does not want this track or namespace.
    pub const UNINTERESTED: Self = Self(0x20);
    /// The prefix overlaps another subscription of the same type.
    pub const PREFIX_OVERLAP: Self = Self(0x30);
    /// The prefix matches more publishers than the relay will enumerate.
    pub const NAMESPACE_TOO_LARGE: Self = Self(0x31);
    /// A joining FETCH referenced a request that is not an established
    /// subscription.
    pub const INVALID_JOINING_REQUEST_ID: Self = Self(0x32);
    /// A mandatory track property was not understood.
    pub const UNSUPPORTED_EXTENSION: Self = Self(0x33);
    /// Try elsewhere. The only code for which a Redirect is present.
    pub const REDIRECT: Self = Self(0x34);
    /// Too many conflicting filters to aggregate a `SUBSCRIBE_TRACKS`.
    pub const CONFLICTING_FILTERS: Self = Self(0x35);
    /// A filter parameter is invalid.
    pub const INVALID_FILTER: Self = Self(0x36);

    /// The registered name, if this build knows the code.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::INTERNAL_ERROR => "INTERNAL_ERROR",
            Self::UNAUTHORIZED => "UNAUTHORIZED",
            Self::TIMEOUT => "TIMEOUT",
            Self::NOT_SUPPORTED => "NOT_SUPPORTED",
            Self::MALFORMED_AUTH_TOKEN => "MALFORMED_AUTH_TOKEN",
            Self::EXPIRED_AUTH_TOKEN => "EXPIRED_AUTH_TOKEN",
            Self::GOING_AWAY => "GOING_AWAY",
            Self::EXCESSIVE_LOAD => "EXCESSIVE_LOAD",
            Self::DOES_NOT_EXIST => "DOES_NOT_EXIST",
            Self::INVALID_RANGE => "INVALID_RANGE",
            Self::MALFORMED_TRACK => "MALFORMED_TRACK",
            Self::UNINTERESTED => "UNINTERESTED",
            Self::PREFIX_OVERLAP => "PREFIX_OVERLAP",
            Self::NAMESPACE_TOO_LARGE => "NAMESPACE_TOO_LARGE",
            Self::INVALID_JOINING_REQUEST_ID => "INVALID_JOINING_REQUEST_ID",
            Self::UNSUPPORTED_EXTENSION => "UNSUPPORTED_EXTENSION",
            Self::REDIRECT => "REDIRECT",
            Self::CONFLICTING_FILTERS => "CONFLICTING_FILTERS",
            Self::INVALID_FILTER => "INVALID_FILTER",
            _ => return None,
        })
    }
}

impl std::fmt::Display for RequestErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "unknown({:#x})", self.0),
        }
    }
}

/// Where to retry a rejected request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Redirect {
    /// Session URI to connect to. Empty means stay on the current session.
    connect_uri: Bytes,
    /// Replacement track name. An empty namespace *and* empty name together
    /// mean the original request's values are reused.
    pub track: FullTrackName,
}

impl Redirect {
    /// Redirect to a different track on the current session.
    #[must_use]
    pub fn to_track(track: FullTrackName) -> Self {
        Self {
            connect_uri: Bytes::new(),
            track,
        }
    }

    /// Redirect to another endpoint, keeping the original track.
    ///
    /// # Errors
    /// [`DecodeError::Invalid`] if the URI exceeds [`MAX_CONNECT_URI_LEN`].
    pub fn to_uri(uri: impl Into<Bytes>) -> Result<Self, DecodeError> {
        let uri = uri.into();
        if uri.len() > MAX_CONNECT_URI_LEN {
            return Err(DecodeError::Invalid("connect URI exceeds maximum length"));
        }
        Ok(Self {
            connect_uri: uri,
            track: FullTrackName::default(),
        })
    }

    /// The connect URI, empty if the current session should be reused.
    #[must_use]
    pub const fn connect_uri(&self) -> &Bytes {
        &self.connect_uri
    }

    /// Whether the track should be replaced, as opposed to reused.
    ///
    /// Both parts must be empty to mean "reuse", so a namespace-only redirect
    /// still counts as a replacement.
    #[must_use]
    pub fn replaces_track(&self) -> bool {
        !(self.track.namespace().is_empty() && self.track.name().is_empty())
    }

    /// Encoded size.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        encoded_bytes_len(&self.connect_uri) + self.track.encoded_len()
    }

    /// Append to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        encode_bytes(buf, &self.connect_uri);
        self.track.encode(buf);
    }

    /// Read a redirect.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] if the URI
    /// is oversized or the track name is malformed.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        Ok(Self {
            connect_uri: Bytes::from(decode_bytes(buf, MAX_CONNECT_URI_LEN)?),
            track: FullTrackName::decode(buf)?,
        })
    }
}

/// Accepts a PUBLISH, `REQUEST_UPDATE`, `TRACK_STATUS`, `SUBSCRIBE_NAMESPACE`,
/// `SUBSCRIBE_TRACKS`, or `PUBLISH_NAMESPACE`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestOk {
    /// Response parameters.
    pub parameters: Parameters,
    /// Track Properties, running to the end of the message.
    ///
    /// Only ever populated in a response to `TRACK_STATUS`. Every other request
    /// type must leave this empty, and receiving properties in one of those is
    /// a `PROTOCOL_VIOLATION` — which this type cannot check, because it does
    /// not know what request it is answering. See [`Self::check_properties`].
    pub properties: Properties,
}

impl RequestOk {
    /// An empty acceptance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify the properties field against the request being answered.
    ///
    /// `answers_track_status` is supplied by the caller because the correlation
    /// lives in the request stream's state, not in this message.
    ///
    /// # Errors
    /// [`DecodeError::Invalid`] if properties are present on a response to
    /// anything but `TRACK_STATUS`.
    pub fn check_properties(&self, answers_track_status: bool) -> Result<(), DecodeError> {
        if !answers_track_status && !self.properties.is_empty() {
            return Err(DecodeError::Invalid(
                "track properties are only valid in a TRACK_STATUS response",
            ));
        }
        Ok(())
    }

    /// Encoded size of the message body.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.parameters.encoded_len_counted() + self.properties.encoded_len()
    }

    /// Append the message body to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        self.parameters.encode_counted(buf);
        self.properties.encode(buf);
    }

    /// Read a message body.
    ///
    /// `buf` must hold exactly one body, since properties run to its end.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] if
    /// malformed.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        Ok(Self {
            parameters: Parameters::decode_counted(buf)?,
            properties: Properties::decode_to_end(buf)?,
        })
    }
}

/// Rejects any request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestError {
    /// Why the request failed.
    pub code: RequestErrorCode,
    /// Milliseconds before retrying, **plus one**.
    ///
    /// Zero means do not retry, and 1 means retry immediately. Storing the
    /// wire value rather than a duration keeps that offset in one place; use
    /// [`Self::retry_after_ms`] to get the actual delay.
    pub retry_interval: VarInt,
    /// Diagnostic text.
    pub reason: ReasonPhrase,
    /// Present exactly when `code` is [`RequestErrorCode::REDIRECT`].
    pub redirect: Option<Redirect>,
}

impl RequestError {
    /// A rejection that should not be retried.
    #[must_use]
    pub fn new(code: RequestErrorCode, reason: ReasonPhrase) -> Self {
        Self {
            code,
            retry_interval: VarInt::ZERO,
            reason,
            redirect: None,
        }
    }

    /// A rejection the peer may retry after `after_ms` milliseconds.
    ///
    /// # Errors
    /// [`crate::BoundsExceeded`] if the encoded interval leaves varint range.
    pub fn retryable(
        code: RequestErrorCode,
        reason: ReasonPhrase,
        after_ms: u64,
    ) -> Result<Self, crate::BoundsExceeded> {
        let retry_interval = VarInt::new(after_ms.saturating_add(1))?;
        Ok(Self {
            code,
            retry_interval,
            reason,
            redirect: None,
        })
    }

    /// A REDIRECT rejection.
    #[must_use]
    pub fn redirect(reason: ReasonPhrase, redirect: Redirect) -> Self {
        Self {
            code: RequestErrorCode::REDIRECT,
            retry_interval: VarInt::ZERO,
            reason,
            redirect: Some(redirect),
        }
    }

    /// Milliseconds to wait before retrying, or `None` if the request should
    /// not be retried.
    #[must_use]
    pub const fn retry_after_ms(&self) -> Option<u64> {
        match self.retry_interval.get() {
            0 => None,
            n => Some(n - 1),
        }
    }

    /// Encoded size of the message body.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        VarInt::new(self.code.0).map_or(8, VarInt::size)
            + self.retry_interval.size()
            + self.reason.encoded_len()
            + self.redirect.as_ref().map_or(0, Redirect::encoded_len)
    }

    /// Append the message body to `buf`.
    ///
    /// # Panics
    /// Panics if `code` is outside varint range, which no registered or greased
    /// code is.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        VarInt::new(self.code.0)
            .expect("error code within varint range")
            .encode(buf);
        self.retry_interval.encode(buf);
        self.reason.encode(buf);
        if let Some(redirect) = &self.redirect {
            redirect.encode(buf);
        }
    }

    /// Read a message body.
    ///
    /// Whether a Redirect follows is determined entirely by the error code, so
    /// a peer sending one under any other code desynchronises this decode. That
    /// is why the trailing-bytes check below is fatal rather than ignored.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] if
    /// malformed or if bytes remain after the message.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        let code = RequestErrorCode(VarInt::decode(buf)?.get());
        let retry_interval = VarInt::decode(buf)?;
        let reason = ReasonPhrase::decode(buf)?;

        let redirect = if code == RequestErrorCode::REDIRECT {
            Some(Redirect::decode(buf)?)
        } else {
            None
        };

        if buf.has_remaining() {
            return Err(DecodeError::Invalid("trailing bytes after REQUEST_ERROR"));
        }

        Ok(Self {
            code,
            retry_interval,
            reason,
            redirect,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::params::Parameter;
    use crate::model::TrackNamespace;

    fn track() -> FullTrackName {
        FullTrackName::new(
            TrackNamespace::from_parts([&b"moqom"[..], &b"room-1"[..]]).unwrap(),
            bytes::Bytes::from_static(b"audio"),
        )
        .unwrap()
    }

    fn reason() -> ReasonPhrase {
        ReasonPhrase::truncating("no such track")
    }

    #[test]
    fn error_codes_match_the_registry() {
        assert_eq!(RequestErrorCode::INTERNAL_ERROR.0, 0x0);
        assert_eq!(RequestErrorCode::GOING_AWAY.0, 0x6);
        assert_eq!(RequestErrorCode::EXCESSIVE_LOAD.0, 0x9);
        assert_eq!(RequestErrorCode::DOES_NOT_EXIST.0, 0x10);
        assert_eq!(RequestErrorCode::UNINTERESTED.0, 0x20);
        assert_eq!(RequestErrorCode::PREFIX_OVERLAP.0, 0x30);
        assert_eq!(RequestErrorCode::REDIRECT.0, 0x34);
        assert_eq!(RequestErrorCode::INVALID_FILTER.0, 0x36);
    }

    /// The registry is extensible and reserves a greasing range, so a code this
    /// build has never heard of must survive rather than fail the session.
    #[test]
    fn unknown_codes_are_preserved() {
        let unknown = RequestErrorCode(0x9D);
        assert_eq!(unknown.name(), None);
        assert_eq!(unknown.to_string(), "unknown(0x9d)");

        let msg = RequestError::new(unknown, reason());
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        let mut cursor = buf.as_slice();
        assert_eq!(RequestError::decode(&mut cursor).unwrap().code, unknown);
    }

    #[test]
    fn named_codes_display_by_name() {
        assert_eq!(
            RequestErrorCode::DOES_NOT_EXIST.to_string(),
            "DOES_NOT_EXIST"
        );
        assert_eq!(RequestErrorCode::REDIRECT.name(), Some("REDIRECT"));
    }

    fn round_trip_error(msg: &RequestError) {
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        assert_eq!(buf.len(), msg.encoded_len());

        let mut cursor = buf.as_slice();
        assert_eq!(&RequestError::decode(&mut cursor).unwrap(), msg);
    }

    #[test]
    fn request_error_round_trips() {
        round_trip_error(&RequestError::new(
            RequestErrorCode::DOES_NOT_EXIST,
            reason(),
        ));
        round_trip_error(
            &RequestError::retryable(RequestErrorCode::EXCESSIVE_LOAD, reason(), 2500).unwrap(),
        );
        round_trip_error(&RequestError::new(
            RequestErrorCode::UNAUTHORIZED,
            ReasonPhrase::empty(),
        ));
    }

    /// Retry Interval is the delay *plus one*, so a value of 1 means retry now
    /// and 0 means never. Dropping the offset turns "retry immediately" into
    /// "do not retry", which is a silent availability bug.
    #[test]
    fn retry_interval_carries_a_plus_one_offset() {
        let never = RequestError::new(RequestErrorCode::UNAUTHORIZED, reason());
        assert_eq!(never.retry_interval.get(), 0);
        assert_eq!(never.retry_after_ms(), None);

        let now = RequestError::retryable(RequestErrorCode::TIMEOUT, reason(), 0).unwrap();
        assert_eq!(now.retry_interval.get(), 1, "wire value is delay + 1");
        assert_eq!(now.retry_after_ms(), Some(0));

        let later = RequestError::retryable(RequestErrorCode::TIMEOUT, reason(), 5000).unwrap();
        assert_eq!(later.retry_interval.get(), 5001);
        assert_eq!(later.retry_after_ms(), Some(5000));
    }

    /// The Redirect field has no discriminator of its own — its presence is
    /// implied by the error code, so the two must never disagree.
    #[test]
    fn redirect_is_present_exactly_for_the_redirect_code() {
        let msg = RequestError::redirect(reason(), Redirect::to_track(track()));
        assert_eq!(msg.code, RequestErrorCode::REDIRECT);
        round_trip_error(&msg);

        let plain = RequestError::new(RequestErrorCode::TIMEOUT, reason());
        assert!(plain.redirect.is_none());
        round_trip_error(&plain);
    }

    #[test]
    fn a_redirect_body_under_another_code_is_rejected() {
        // Encode a REDIRECT, then rewrite the code so the trailing redirect
        // becomes unexplained. A decoder that ignores trailing bytes would
        // accept this and silently lose the redirect target.
        let msg = RequestError::redirect(reason(), Redirect::to_track(track()));
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        buf[0] = 0x02; // TIMEOUT

        let mut cursor = buf.as_slice();
        assert!(RequestError::decode(&mut cursor).unwrap_err().is_fatal());
    }

    #[test]
    fn redirect_round_trips_in_every_shape() {
        for redirect in [
            Redirect::to_track(track()),
            Redirect::to_uri(&b"moqt://eu.moqom.dev/"[..]).unwrap(),
            Redirect::default(),
        ] {
            let mut buf = Vec::new();
            redirect.encode(&mut buf);
            assert_eq!(buf.len(), redirect.encoded_len());

            let mut cursor = buf.as_slice();
            assert_eq!(Redirect::decode(&mut cursor).unwrap(), redirect);
            assert!(cursor.is_empty());
        }
    }

    /// "Both zero length" means reuse the original track, so an empty
    /// namespace and empty name is a meaningful encoding rather than an error.
    #[test]
    fn an_empty_redirect_track_means_reuse() {
        let reuse = Redirect::to_uri(&b"moqt://x/"[..]).unwrap();
        assert!(!reuse.replaces_track());

        assert!(Redirect::to_track(track()).replaces_track());

        let namespace_only = Redirect::to_track(
            FullTrackName::new(
                TrackNamespace::from_parts([&b"ns"[..]]).unwrap(),
                bytes::Bytes::new(),
            )
            .unwrap(),
        );
        assert!(
            namespace_only.replaces_track(),
            "a namespace alone still replaces"
        );
    }

    #[test]
    fn request_ok_round_trips() {
        let mut msg = RequestOk::new();
        msg.parameters
            .push(Parameter::varint(2, VarInt::from_u32(1)).unwrap());
        msg.properties
            .push(Parameter::bytes(0x4001, &b"p"[..]).unwrap());

        let mut buf = Vec::new();
        msg.encode(&mut buf);
        assert_eq!(buf.len(), msg.encoded_len());

        let mut cursor = buf.as_slice();
        assert_eq!(RequestOk::decode(&mut cursor).unwrap(), msg);
        assert!(cursor.is_empty());
    }

    #[test]
    fn empty_request_ok_is_a_single_zero_byte() {
        let msg = RequestOk::new();
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        assert_eq!(buf, vec![0x00]);
    }

    /// Properties are legal only in a `TRACK_STATUS` response, and this message
    /// cannot tell which request it answers, so the caller must supply that.
    #[test]
    fn properties_are_restricted_to_track_status_responses() {
        let mut with_props = RequestOk::new();
        with_props
            .properties
            .push(Parameter::varint(2, VarInt::ZERO).unwrap());

        assert!(with_props.check_properties(true).is_ok());
        assert!(with_props.check_properties(false).unwrap_err().is_fatal());

        let empty = RequestOk::new();
        assert!(empty.check_properties(false).is_ok());
        assert!(empty.check_properties(true).is_ok());
    }

    #[test]
    fn truncation_is_short() {
        let msg =
            RequestError::retryable(RequestErrorCode::EXCESSIVE_LOAD, reason(), 1000).unwrap();
        let mut buf = Vec::new();
        msg.encode(&mut buf);

        for cut in 0..buf.len() {
            let mut cursor = &buf[..cut];
            let err = RequestError::decode(&mut cursor).unwrap_err();
            assert!(!err.is_fatal(), "cut at {cut}: {err:?}");
        }
    }
}
