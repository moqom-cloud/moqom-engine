//! The SETUP message, per draft-19 §10.3.
//!
//! ```text
//! SETUP Message {
//!   Type (vi64) = 0x2F00,
//!   Length (16),
//!   Setup Options (..) ...,
//! }
//! ```
//!
//! # There is no version field
//!
//! Draft-19 has one symmetric SETUP with no version list, where earlier drafts
//! had `CLIENT_SETUP` carrying supported versions and `SERVER_SETUP` selecting
//! one. Version selection now happens entirely in ALPN, before any MOQT byte is
//! sent, so a version mismatch is a failed connection rather than a failed
//! handshake. Anything reaching this decoder has already agreed on a version.
//!
//! That is also why [`crate::control::MessageType::from_u64`] distinguishes
//! reserved codes: an old peer sends `CLIENT_SETUP` at `0x20` and the useful
//! diagnostic is "wrong draft", not "unknown message".
//!
//! # Setup Options are their own namespace
//!
//! Option types are numbered independently of message parameters, and that
//! numbering is constant across MOQT versions while message parameters are not.
//! The two share an encoding but nothing else, so [`SetupOptions`] wraps
//! [`Parameters`] rather than aliasing it — passing one where the other is
//! expected should not compile.

use bytes::{Buf, BufMut, Bytes};

use crate::control::params::{ParamError, Parameter, Parameters};
use crate::control::request_id::Role;
use crate::error::DecodeError;
use crate::varint::VarInt;

/// Setup Option type codes, per draft-19 §15.4.
///
/// Parity follows the Key-Value-Pair rule: even types carry a varint, odd types
/// carry bytes. The registry is consistent with that, so the value shape of an
/// option is readable from its number.
pub mod option_type {
    use super::PRIVATE_USE;

    /// URI path, native QUIC only. Client only.
    pub const PATH: u64 = 0x01;
    /// One or more session authorization tokens. May repeat.
    pub const AUTHORIZATION_TOKEN: u64 = 0x03;
    /// Bytes of registered auth tokens the sender will cache. Default 0.
    pub const MAX_AUTH_TOKEN_CACHE_SIZE: u64 = 0x04;
    /// URI authority, native QUIC only. Client only.
    pub const AUTHORITY: u64 = 0x05;
    /// Concurrent range filters the peer may use. Default 0.
    pub const MAX_FILTER_RANGES: u64 = 0x06;
    /// Implementation name and version, for debugging.
    pub const MOQT_IMPLEMENTATION: u64 = 0x07;
    /// Unacknowledged `REQUEST_UPDATE`s allowed per stream. Default 0.
    pub const MAX_REQUEST_UPDATES: u64 = 0x08;

    /// A proof that the sender holds the key its token is bound to. Not in any
    /// draft registry: see [`super::PRIVATE_USE`].
    ///
    /// Odd, so it carries bytes, which is the parity rule and not a choice. The
    /// value is a compact JWS the relay checks against the token's `cnf.jkt`;
    /// without it a token is a bearer credential and works for whoever holds it.
    pub const AUTHORIZATION_PROOF: u64 = PRIVATE_USE;
}

/// Where this implementation numbers an extension of its own.
///
/// `0x4D51` is "MQ", picked to be recognisable in a packet capture, and it is
/// odd because the parity rule makes odd types the ones that carry bytes. It
/// sits far above draft-19's assignments and outside the greasing sequence, so
/// a future draft would have to travel a long way to collide with it.
///
/// Private use rather than an extension code point, because draft-19 has no
/// registry for one and the alternative was worse. An unknown *option* must be
/// ignored, which is exactly the behaviour wanted here: a peer that does not
/// know about proofs skips this and is told by the relay's close reason why its
/// session ended. Had this needed a new message type instead, the draft requires
/// an unknown type to close the session, and a private extension would have been
/// a code every other implementation must fail on.
pub const PRIVATE_USE: u64 = 0x4D51;

/// The three properties [`PRIVATE_USE`] must not lose, checked where losing one
/// costs nothing to catch: the build.
///
/// None of them fails loudly at runtime. Wrong parity is a value read as the
/// wrong shape, a collision with the greasing sequence is an option peers are
/// entitled to discard, and a collision with a draft assignment is a proof
/// parsed as something else — all three would present as an authentication
/// failure a long way from the cause.
const _: () = assert!(!PRIVATE_USE.is_multiple_of(2), "must carry bytes, so odd");
const _: () = assert!(!is_grease(PRIVATE_USE), "greased options may be ignored");
const _: () = assert!(
    PRIVATE_USE > option_type::MAX_REQUEST_UPDATES,
    "must sit above the draft's own assignments"
);

/// Where this implementation numbers an extension whose value is a number.
///
/// The even neighbour of [`PRIVATE_USE`], for the same reasons and with the same
/// three properties, differing only in parity: the Key-Value-Pair rule makes even
/// types carry a varint, so a counted extension cannot share the odd number that
/// carries byte strings. Adjacent so that both read as this implementation's in a
/// capture.
pub const PRIVATE_USE_VARINT: u64 = 0x4D50;

/// As for [`PRIVATE_USE`], checked at build time for the same reasons — save that
/// the parity requirement is inverted, this one carrying a count.
const _: () = assert!(
    PRIVATE_USE_VARINT.is_multiple_of(2),
    "must carry a varint, so even"
);
const _: () = assert!(
    !is_grease(PRIVATE_USE_VARINT),
    "greased options may be ignored"
);
const _: () = assert!(
    PRIVATE_USE_VARINT > option_type::MAX_REQUEST_UPDATES,
    "must sit above the draft's own assignments"
);

/// Base of the reserved greasing sequence, per draft-19 §14.
const GREASE_BASE: u64 = 0x9D;
/// Stride of the reserved greasing sequence.
const GREASE_STRIDE: u64 = 0x7F;

/// Whether a type falls in the reserved greasing sequence `0x7f * N + 0x9D`.
#[must_use]
pub const fn is_grease(type_value: u64) -> bool {
    type_value >= GREASE_BASE && (type_value - GREASE_BASE).is_multiple_of(GREASE_STRIDE)
}

/// The `N`th greasing type.
///
/// Sending one of these is the only reliable way to find out whether a peer
/// actually ignores unknown options, rather than assuming it does until a
/// future extension breaks it in production.
#[must_use]
pub const fn grease(n: u64) -> Option<u64> {
    match GREASE_STRIDE.checked_mul(n) {
        Some(offset) => offset.checked_add(GREASE_BASE),
        None => None,
    }
}

/// Which transport carries the session. Some options are legal on only one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// Native QUIC, where the `MoQ` URI is conveyed in SETUP.
    Quic,
    /// WebTransport, where the URL already carries authority and path.
    WebTransport,
}

/// A SETUP message violated a rule the specification makes mandatory.
///
/// Each variant corresponds to a named session error in the draft; every one of
/// them terminates the session, so these are reported separately from decoding
/// failures rather than folded into [`DecodeError`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SetupError {
    /// AUTHORITY from a server, or on WebTransport. `INVALID_AUTHORITY`.
    #[error("AUTHORITY is not valid from a {role:?} over {transport:?}")]
    InvalidAuthority {
        /// The sender.
        role: Role,
        /// The transport in use.
        transport: Transport,
    },
    /// PATH from a server, or on WebTransport. `INVALID_PATH`.
    #[error("PATH is not valid from a {role:?} over {transport:?}")]
    InvalidPath {
        /// The sender.
        role: Role,
        /// The transport in use.
        transport: Transport,
    },
    /// A known single-valued option appeared more than once.
    #[error("setup option {type_value:#x} appears more than once")]
    RepeatedOption {
        /// The repeated type.
        type_value: u64,
    },
}

/// The Setup Options carried by a SETUP message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetupOptions(Parameters);

impl SetupOptions {
    /// An empty option set.
    #[must_use]
    pub const fn new() -> Self {
        Self(Parameters::new())
    }

    /// The underlying parameters, including options this build does not know.
    #[must_use]
    pub const fn as_parameters(&self) -> &Parameters {
        &self.0
    }

    /// Add a raw option, including unknown or greasing types.
    pub fn push(&mut self, option: Parameter) {
        self.0.push(option);
    }

    /// Set an option whose value is a varint.
    ///
    /// # Errors
    /// [`ParamError::ParityMismatch`] if `type_value` is odd.
    pub fn set_varint(&mut self, type_value: u64, value: u64) -> Result<(), ParamError> {
        let value = VarInt::new(value).map_err(|_| ParamError::ValueTooLong { len: 0 })?;
        self.0.push(Parameter::varint(type_value, value)?);
        Ok(())
    }

    /// Set an option whose value is a byte string.
    ///
    /// # Errors
    /// [`ParamError`] if the type parity is wrong or the value is oversized.
    pub fn set_bytes(
        &mut self,
        type_value: u64,
        value: impl Into<Bytes>,
    ) -> Result<(), ParamError> {
        self.0.push(Parameter::bytes(type_value, value)?);
        Ok(())
    }

    fn varint_or(&self, type_value: u64, default: u64) -> u64 {
        self.0
            .get(type_value)
            .and_then(Parameter::as_varint)
            .map_or(default, VarInt::get)
    }

    fn bytes_of(&self, type_value: u64) -> Option<&Bytes> {
        self.0.get(type_value).and_then(Parameter::as_bytes)
    }

    /// The URI path, if present.
    #[must_use]
    pub fn path(&self) -> Option<&Bytes> {
        self.bytes_of(option_type::PATH)
    }

    /// The URI authority, if present.
    #[must_use]
    pub fn authority(&self) -> Option<&Bytes> {
        self.bytes_of(option_type::AUTHORITY)
    }

    /// The implementation identifier, if present.
    #[must_use]
    pub fn moqt_implementation(&self) -> Option<&Bytes> {
        self.bytes_of(option_type::MOQT_IMPLEMENTATION)
    }

    /// Every authorization token, in the order sent. This option may repeat.
    pub fn authorization_tokens(&self) -> impl Iterator<Item = &Bytes> {
        self.0
            .as_slice()
            .iter()
            .filter(|p| p.type_value() == option_type::AUTHORIZATION_TOKEN)
            .filter_map(Parameter::as_bytes)
    }

    /// The proof of possession, if the peer sent one.
    ///
    /// Singular where [`Self::authorization_tokens`] is plural, and the
    /// asymmetry is deliberate. Tokens may repeat because a peer can offer
    /// several and let the relay pick the one it can verify; a proof is bound to
    /// one token, so a second would be a proof of something the relay is not
    /// asking about. Where more than one arrives this yields the first, which is
    /// the same rule [`Parameters::get`] applies everywhere else.
    #[must_use]
    pub fn authorization_proof(&self) -> Option<&Bytes> {
        self.bytes_of(option_type::AUTHORIZATION_PROOF)
    }

    /// Auth token cache budget in bytes.
    ///
    /// Defaults to zero, which prohibits token aliases entirely. Reading this
    /// as "unset, so unlimited" is the wrong way round and would overflow a
    /// peer's cache on the first registration.
    #[must_use]
    pub fn max_auth_token_cache_size(&self) -> u64 {
        self.varint_or(option_type::MAX_AUTH_TOKEN_CACHE_SIZE, 0)
    }

    /// Concurrent range filters the peer may use.
    ///
    /// Defaults to zero, meaning the peer must send none at all.
    #[must_use]
    pub fn max_filter_ranges(&self) -> u64 {
        self.varint_or(option_type::MAX_FILTER_RANGES, 0)
    }

    /// Unacknowledged `REQUEST_UPDATE`s permitted per request stream.
    ///
    /// Defaults to zero, which here means *unlimited* rather than none — the
    /// opposite sense to the other two limits, and worth reading twice.
    #[must_use]
    pub fn max_request_updates(&self) -> u64 {
        self.varint_or(option_type::MAX_REQUEST_UPDATES, 0)
    }
}

/// A SETUP message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Setup {
    /// The Setup Options, spanning the whole message body.
    pub options: SetupOptions,
}

impl Setup {
    /// A SETUP with no options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            options: SetupOptions::new(),
        }
    }

    /// Check the rules that depend on who sent this and over what.
    ///
    /// Unknown options are deliberately not checked: draft-19 requires
    /// receivers to ignore them, and to tolerate duplicates of them. Only
    /// registered single-valued options are constrained.
    ///
    /// # Errors
    /// [`SetupError`] for a misplaced or repeated option.
    pub fn validate(&self, sender: Role, transport: Transport) -> Result<(), SetupError> {
        let uri_options_allowed = sender == Role::Client && transport == Transport::Quic;

        if self.options.authority().is_some() && !uri_options_allowed {
            return Err(SetupError::InvalidAuthority {
                role: sender,
                transport,
            });
        }
        if self.options.path().is_some() && !uri_options_allowed {
            return Err(SetupError::InvalidPath {
                role: sender,
                transport,
            });
        }

        // AUTHORIZATION_TOKEN is the one registered option defined to repeat.
        let single_valued = [
            option_type::PATH,
            option_type::MAX_AUTH_TOKEN_CACHE_SIZE,
            option_type::AUTHORITY,
            option_type::MAX_FILTER_RANGES,
            option_type::MOQT_IMPLEMENTATION,
            option_type::MAX_REQUEST_UPDATES,
        ];
        for type_value in single_valued {
            let count = self
                .options
                .0
                .as_slice()
                .iter()
                .filter(|p| p.type_value() == type_value)
                .count();
            if count > 1 {
                return Err(SetupError::RepeatedOption { type_value });
            }
        }

        Ok(())
    }

    /// Encoded size of the message body, excluding the envelope.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.options.0.encoded_len()
    }

    /// Append the message body to `buf`, excluding the envelope.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        self.options.0.encode(buf);
    }

    /// Decode a message body of exactly `byte_len` bytes.
    ///
    /// The length comes from the envelope; options have no terminator, so the
    /// body cannot be parsed without it.
    ///
    /// # Errors
    /// Propagates [`DecodeError`] from the option sequence. Role and transport
    /// rules are not applied here — see [`Self::validate`].
    pub fn decode<B: Buf>(buf: &mut B, byte_len: usize) -> Result<Self, DecodeError> {
        Ok(Self {
            options: SetupOptions(Parameters::decode(buf, byte_len)?),
        })
    }
}

impl crate::control::frame::MessageBody for Setup {
    const MESSAGE_TYPE: crate::control::MessageType = crate::control::MessageType::Setup;

    fn encoded_len(&self) -> usize {
        Self::encoded_len(self)
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        Self::encode(self, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::frame::ControlFrame;
    use crate::control::message_type::MessageType;

    fn client_setup() -> Setup {
        let mut setup = Setup::new();
        setup
            .options
            .set_bytes(option_type::PATH, &b"/live"[..])
            .unwrap();
        setup
            .options
            .set_bytes(option_type::AUTHORITY, &b"relay.moqom.dev"[..])
            .unwrap();
        setup
            .options
            .set_bytes(option_type::MOQT_IMPLEMENTATION, &b"moqom/0.0.0"[..])
            .unwrap();
        setup
            .options
            .set_varint(option_type::MAX_AUTH_TOKEN_CACHE_SIZE, 8192)
            .unwrap();
        setup
            .options
            .set_varint(option_type::MAX_REQUEST_UPDATES, 4)
            .unwrap();
        setup
    }

    fn round_trip(setup: &Setup) {
        let mut buf = Vec::new();
        setup.encode(&mut buf);
        assert_eq!(buf.len(), setup.encoded_len());

        let mut cursor = buf.as_slice();
        assert_eq!(&Setup::decode(&mut cursor, buf.len()).unwrap(), setup);
        assert!(cursor.is_empty());
    }

    #[test]
    fn empty_setup_round_trips() {
        round_trip(&Setup::new());
        assert_eq!(Setup::new().encoded_len(), 0);
    }

    #[test]
    fn populated_setup_round_trips() {
        let setup = client_setup();
        round_trip(&setup);

        let decoded = {
            let mut buf = Vec::new();
            setup.encode(&mut buf);
            Setup::decode(&mut buf.as_slice(), buf.len()).unwrap()
        };
        assert_eq!(decoded.options.path().unwrap().as_ref(), b"/live");
        assert_eq!(
            decoded.options.authority().unwrap().as_ref(),
            b"relay.moqom.dev"
        );
        assert_eq!(
            decoded.options.moqt_implementation().unwrap().as_ref(),
            b"moqom/0.0.0"
        );
        assert_eq!(decoded.options.max_auth_token_cache_size(), 8192);
        assert_eq!(decoded.options.max_request_updates(), 4);
    }

    #[test]
    fn fits_in_a_control_frame() {
        let setup = client_setup();
        let mut body = Vec::new();
        setup.encode(&mut body);

        let frame = ControlFrame::new(MessageType::Setup, body).unwrap();
        let mut wire = Vec::new();
        frame.encode(&mut wire);

        let mut cursor = wire.as_slice();
        let decoded = ControlFrame::decode(&mut cursor).unwrap();
        assert_eq!(decoded.message_type, MessageType::Setup);

        let mut body = decoded.body.clone();
        let len = body.len();
        assert_eq!(Setup::decode(&mut body, len).unwrap(), setup);
    }

    /// Every default is zero, but zero means "none permitted" for two of them
    /// and "no limit" for the third. Treating them uniformly is a real bug in
    /// either direction.
    #[test]
    fn absent_limits_take_their_specified_defaults() {
        let setup = Setup::new();
        assert_eq!(
            setup.options.max_auth_token_cache_size(),
            0,
            "aliases prohibited"
        );
        assert_eq!(
            setup.options.max_filter_ranges(),
            0,
            "no range filters permitted"
        );
        assert_eq!(setup.options.max_request_updates(), 0, "unlimited updates");
    }

    #[test]
    fn authorization_tokens_may_repeat() {
        let mut setup = Setup::new();
        setup
            .options
            .set_bytes(option_type::AUTHORIZATION_TOKEN, &b"first"[..])
            .unwrap();
        setup
            .options
            .set_bytes(option_type::AUTHORIZATION_TOKEN, &b"second"[..])
            .unwrap();

        let tokens: Vec<_> = setup.options.authorization_tokens().collect();
        assert_eq!(tokens.len(), 2);
        assert!(setup.validate(Role::Client, Transport::Quic).is_ok());
        round_trip(&setup);
    }

    #[test]
    fn single_valued_options_may_not_repeat() {
        let mut setup = Setup::new();
        setup
            .options
            .set_varint(option_type::MAX_FILTER_RANGES, 1)
            .unwrap();
        setup
            .options
            .set_varint(option_type::MAX_FILTER_RANGES, 2)
            .unwrap();

        assert_eq!(
            setup.validate(Role::Client, Transport::Quic),
            Err(SetupError::RepeatedOption {
                type_value: option_type::MAX_FILTER_RANGES
            })
        );
    }

    /// PATH and AUTHORITY convey the `MoQ` URI, which WebTransport already has in
    /// its URL and a server never supplies at all.
    #[test]
    fn uri_options_are_client_and_quic_only() {
        let setup = client_setup();
        assert!(setup.validate(Role::Client, Transport::Quic).is_ok());

        assert!(matches!(
            setup.validate(Role::Server, Transport::Quic),
            Err(SetupError::InvalidAuthority {
                role: Role::Server,
                ..
            })
        ));
        assert!(matches!(
            setup.validate(Role::Client, Transport::WebTransport),
            Err(SetupError::InvalidAuthority {
                transport: Transport::WebTransport,
                ..
            })
        ));

        let mut path_only = Setup::new();
        path_only
            .options
            .set_bytes(option_type::PATH, &b"/x"[..])
            .unwrap();
        assert!(matches!(
            path_only.validate(Role::Server, Transport::Quic),
            Err(SetupError::InvalidPath { .. })
        ));
    }

    #[test]
    fn a_server_setup_without_uri_options_is_valid_on_both_transports() {
        let mut setup = Setup::new();
        setup
            .options
            .set_bytes(option_type::MOQT_IMPLEMENTATION, &b"moqom-relay/0.0.0"[..])
            .unwrap();
        setup
            .options
            .set_varint(option_type::MAX_FILTER_RANGES, 16)
            .unwrap();

        assert!(setup.validate(Role::Server, Transport::Quic).is_ok());
        assert!(
            setup
                .validate(Role::Server, Transport::WebTransport)
                .is_ok()
        );
        assert_eq!(setup.options.max_filter_ranges(), 16);
    }

    /// Unknown options must survive a decode and must not trip validation, or
    /// the first extension anyone deploys breaks the handshake.
    #[test]
    fn unknown_options_are_preserved_and_ignored() {
        let mut setup = Setup::new();
        setup
            .options
            .set_varint(option_type::MAX_FILTER_RANGES, 3)
            .unwrap();
        setup.options.set_varint(0x1000, 1).unwrap();
        setup.options.set_bytes(0x1001, &b"future"[..]).unwrap();
        setup.options.set_bytes(0x1001, &b"duplicate"[..]).unwrap();

        assert!(
            setup.validate(Role::Client, Transport::Quic).is_ok(),
            "unknown dupes allowed"
        );
        round_trip(&setup);
        assert_eq!(setup.options.as_parameters().len(), 4);
    }

    #[test]
    fn grease_types_are_generated_and_recognised() {
        assert_eq!(grease(0), Some(0x9D));
        assert_eq!(grease(1), Some(0x9D + 0x7F));
        assert_eq!(grease(2), Some(0x9D + 0x7F * 2));

        for n in 0..64 {
            assert!(is_grease(grease(n).unwrap()), "N={n}");
        }
        for t in [
            option_type::PATH,
            option_type::MAX_REQUEST_UPDATES,
            0x9C,
            0x9E,
        ] {
            assert!(!is_grease(t), "{t:#x}");
        }
        assert_eq!(grease(u64::MAX), None);
    }

    /// The number's own properties are asserted at compile time beside its
    /// definition. What is left to check here is that it survives the wire, which
    /// for a type this far above its neighbours is a question about delta
    /// encoding rather than about the number.
    #[test]
    fn a_proof_rides_beside_the_token_it_belongs_to() {
        let mut setup = Setup::new();
        setup
            .options
            .set_bytes(option_type::AUTHORIZATION_TOKEN, &b"token"[..])
            .unwrap();
        setup
            .options
            .set_bytes(option_type::AUTHORIZATION_PROOF, &b"proof"[..])
            .unwrap();
        round_trip(&setup);
        assert_eq!(
            setup.options.authorization_proof().map(Bytes::as_ref),
            Some(&b"proof"[..])
        );
        assert_eq!(
            setup.options.authorization_tokens().count(),
            1,
            "the proof must not read as another token"
        );
    }

    /// Greasing only proves anything if the grease actually rides the wire, so
    /// check a greased option survives a full round trip untouched.
    #[test]
    fn greased_options_round_trip_and_pass_validation() {
        let mut setup = Setup::new();
        setup
            .options
            .set_bytes(grease(0).unwrap(), &b"ignore me"[..])
            .unwrap();
        setup.options.set_varint(grease(1).unwrap(), 42).unwrap();

        assert!(setup.validate(Role::Client, Transport::Quic).is_ok());
        round_trip(&setup);
    }

    #[test]
    fn grease_parity_alternates_so_both_value_shapes_get_exercised() {
        // 0x9D is odd and 0x11C is even, so consecutive grease types cover the
        // byte-valued and varint-valued paths without any special handling.
        assert_eq!(grease(0).unwrap() % 2, 1);
        assert_eq!(grease(1).unwrap() % 2, 0);
    }
}
