//! Sans-io codec for Media over QUIC Transport.
//!
//! Targets `draft-ietf-moq-transport-19`. This crate performs no I/O and owns
//! no state machine beyond parsing: it turns bytes into messages and back, so
//! it can be driven identically by the relay, the client core, the CLI, and a
//! fuzz harness.
//!
//! # Layout
//!
//! - [`varint`] — QUIC variable-length integers, the base of every field.
//! - [`coding`] — the [`Encode`]/[`Decode`] traits and the streaming-decode
//!   contract, which is worth reading before writing a decoder.
//! - [`error`] — the short-read versus malformed distinction that decides
//!   whether a session survives.
//! - [`model`] — the object data model: tracks, groups, subgroups, objects.
//! - [`control`] — the control message envelope, type registry, request
//!   identity, and parameter encoding.
//!
//! # On a second dialect
//!
//! Cloudflare's relay speaks `moqt-16`, and interoperating later means encoding
//! the same semantics with different request identity and a different setup
//! handshake. The seam for that lives in [`control`], where the two dialects
//! actually differ; below it a varint is a varint, so nothing is abstracted.

#![forbid(unsafe_code)]

pub mod coding;
pub mod control;
pub mod data;
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
pub use error::{BoundsExceeded, DecodeError};
pub use model::{
    FullTrackName, GroupId, Location, NameError, ObjectId, ObjectSeq, ObjectStatus, SubgroupId,
    TrackAlias, TrackNamespace,
};
pub use varint::VarInt;
