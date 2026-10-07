//! Sans-io codec for Media over QUIC Transport.
//!
//! Speaks three drafts of `draft-ietf-moq-transport`, chosen per session by
//! [`Draft`]: 22, 19 in the form MOQOM deployed it, and the subset of 16
//! Cloudflare's relays implement. This crate performs no I/O and owns no state
//! machine beyond parsing: it turns bytes into messages and back, so it can be
//! driven identically by the relay, the client core, the CLI, and a fuzz
//! harness.
//!
//! # Layout
//!
//! - [`draft`] — which draft a call encodes in, and how that reaches the
//!   leaves. Read this before calling any codec from session code.
//! - [`varint`] — variable-length integers, the base of every field.
//! - [`coding`] — the [`Encode`]/[`Decode`] traits and the streaming-decode
//!   contract, which is worth reading before writing a decoder.
//! - [`error`] — the short-read versus malformed distinction that decides
//!   whether a session survives.
//! - [`model`] — the object data model: tracks, groups, subgroups, objects.
//! - [`control`] — the control message envelope, type registry, request
//!   identity, and parameter encoding.
//!
//! # Drafts
//!
//! Most of the difference between drafts is below the message layer — the
//! integer encoding and how parameters are typed — and is resolved at the
//! leaves from the ambient [`Draft`]. The messages whose layout differs
//! consult it directly. Draft-16's control plane is a different grammar
//! altogether (one control stream, setup messages of its own) and lives in
//! [`control::d16`].

#![forbid(unsafe_code)]

pub mod coding;
pub mod control;
pub mod data;
pub mod draft;
pub mod error;
pub mod model;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod varint;

pub use coding::{Decode, Encode};
pub use control::{
    ControlFrame, MessageType, ParamValue, Parameter, Parameters, RequestId, RequestIdGenerator,
    Role,
};
pub use draft::Draft;
pub use error::{BoundsExceeded, DecodeError};
pub use model::{
    FullTrackName, GroupId, Location, NameError, ObjectId, ObjectSeq, ObjectStatus, SubgroupId,
    TrackAlias, TrackNamespace,
};
pub use varint::VarInt;
