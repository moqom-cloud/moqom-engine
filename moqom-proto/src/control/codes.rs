//! Draft-22's error registries, §12.2–12.5, and how MOQOM's draft-19 codes
//! map onto them.
//!
//! Request error codes ([`RequestErrorCode`](crate::control::RequestErrorCode))
//! and `PUBLISH_DONE` statuses ([`PublishDoneStatus`](crate::control::PublishDoneStatus))
//! keep their own types, since they travel inside messages; draft-22 changed
//! each of them by one removal, handled where the type is defined. Session
//! termination and stream reset codes travel in QUIC or WebTransport frames
//! as bare integers, so they are plain constants here.
//!
//! MOQOM's draft-19 sessions close with codes of MOQOM's own numbering
//! (`0x01` protocol violation, `0x02` internal, `0x03` unauthorized, `0x04`
//! over limit), which every deployed client has seen. Draft-22 sessions use
//! §12.2's numbers; [`session_close`] translates.

use crate::draft::Draft;

/// Session termination codes, draft-22 §12.2.
pub mod session {
    /// Terminated without an error.
    pub const NO_ERROR: u32 = 0x0;
    /// An implementation-specific error.
    pub const INTERNAL_ERROR: u32 = 0x1;
    /// The client is not authorized to establish a session.
    pub const UNAUTHORIZED: u32 = 0x2;
    /// The peer broke a protocol rule, including an unknown Message
    /// Parameter or Type Flags bit.
    pub const PROTOCOL_VIOLATION: u32 = 0x3;
    /// A Request ID out of sequence or over the limit.
    pub const INVALID_REQUEST_ID: u32 = 0x4;
    /// A Track Alias already in use.
    pub const DUPLICATE_TRACK_ALIAS: u32 = 0x5;
    /// A key-value pair that does not match its type's serialization.
    pub const KEY_VALUE_FORMATTING_ERROR: u32 = 0x6;
    /// PATH from a server, or over WebTransport, or one the server lacks.
    pub const INVALID_PATH: u32 = 0x8;
    /// PATH that is not a valid URI path.
    pub const MALFORMED_PATH: u32 = 0x9;
    /// The peer did not close after GOAWAY in time.
    pub const GOAWAY_TIMEOUT: u32 = 0x10;
    /// A control message was not answered in time.
    pub const CONTROL_MESSAGE_TIMEOUT: u32 = 0x11;
    /// A data stream made no progress in time.
    pub const DATA_STREAM_TIMEOUT: u32 = 0x12;
    /// Registered tokens exceed `MAX_AUTH_TOKEN_CACHE_SIZE`.
    pub const AUTH_TOKEN_CACHE_OVERFLOW: u32 = 0x13;
    /// A token alias registered twice.
    pub const DUPLICATE_AUTH_TOKEN_ALIAS: u32 = 0x14;
    /// A token that does not parse.
    pub const MALFORMED_AUTH_TOKEN: u32 = 0x16;
    /// A token alias that was never registered.
    pub const UNKNOWN_AUTH_TOKEN_ALIAS: u32 = 0x17;
    /// The session's token expired.
    pub const EXPIRED_AUTH_TOKEN: u32 = 0x18;
    /// AUTHORITY the server does not serve.
    pub const INVALID_AUTHORITY: u32 = 0x19;
    /// AUTHORITY that does not parse.
    pub const MALFORMED_AUTHORITY: u32 = 0x1A;
    /// More outstanding `REQUEST_UPDATE`s than `MAX_REQUEST_UPDATES`.
    pub const TOO_MANY_REQUEST_UPDATES: u32 = 0x1B;
}

/// Stream reset codes, draft-22 §12.5.
pub mod reset {
    /// An implementation-specific error.
    pub const INTERNAL_ERROR: u32 = 0x0;
    /// Cancelled by either endpoint.
    pub const CANCELLED: u32 = 0x1;
    /// A delivery timeout expired.
    pub const DELIVERY_TIMEOUT: u32 = 0x2;
    /// The session is closing.
    pub const SESSION_CLOSED: u32 = 0x3;
    /// The endpoint is going away.
    pub const GOING_AWAY: u32 = 0x4;
    /// The subscription fell too far behind.
    pub const TOO_FAR_BEHIND: u32 = 0x5;
    /// A fetch reached objects whose status the publisher cannot determine.
    pub const UNKNOWN_OBJECT_STATUS: u32 = 0x6;
    /// The request's authorization token expired.
    pub const EXPIRED_AUTH_TOKEN: u32 = 0x7;
    /// The endpoint is overloaded.
    pub const EXCESSIVE_LOAD: u32 = 0x9;
    /// A relay found the track malformed.
    pub const MALFORMED_TRACK: u32 = 0x12;
}

/// MOQOM's draft-19 session close codes, by meaning.
pub mod moqom_d19 {
    /// The peer broke a protocol rule.
    pub const PROTOCOL_VIOLATION: u32 = 0x01;
    /// The relay failed.
    pub const INTERNAL: u32 = 0x02;
    /// The credential did not verify.
    pub const UNAUTHORIZED: u32 = 0x03;
    /// The peer is over a limit.
    pub const EXCESSIVE_LOAD: u32 = 0x04;
}

/// The code to close a `draft` session with, given MOQOM's draft-19 code
/// for the reason.
///
/// Draft-22 has no session-level code for "over a limit"; it becomes
/// `INTERNAL_ERROR`, and the reason phrase carries the distinction. Codes
/// MOQOM does not define pass through unchanged.
#[must_use]
pub const fn session_close(draft: Draft, moqom_code: u32) -> u32 {
    match draft {
        Draft::D22 => match moqom_code {
            0 => session::NO_ERROR,
            moqom_d19::PROTOCOL_VIOLATION => session::PROTOCOL_VIOLATION,
            moqom_d19::INTERNAL | moqom_d19::EXCESSIVE_LOAD => session::INTERNAL_ERROR,
            moqom_d19::UNAUTHORIZED => session::UNAUTHORIZED,
            other => other,
        },
        _ => moqom_code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft19_codes_are_unchanged_and_draft22_follows_section_12_2() {
        for code in 0..8 {
            assert_eq!(session_close(Draft::D19, code), code);
        }
        assert_eq!(
            session_close(Draft::D22, moqom_d19::PROTOCOL_VIOLATION),
            0x3
        );
        assert_eq!(session_close(Draft::D22, moqom_d19::UNAUTHORIZED), 0x2);
        assert_eq!(session_close(Draft::D22, moqom_d19::INTERNAL), 0x1);
        assert_eq!(session_close(Draft::D22, 0), 0x0);
    }
}
