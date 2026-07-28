//! Control message bodies.
//!
//! Each type here encodes and decodes a message body only — the envelope is
//! [`crate::control::ControlFrame`]. Several bodies end in Track Properties,
//! which are defined as "the remaining bytes of the message", so their decoders
//! require a buffer holding exactly one body. The frame layer produces exactly
//! that, which is why the split is worth keeping.

pub mod fetch;
pub mod goaway;
pub mod namespace;
pub mod publish;
pub mod request;
pub mod subscribe;

pub use fetch::{Fetch, FetchKind, FetchOk};
pub use goaway::{Goaway, GoawayError};
pub use namespace::{
    DoneReason, Namespace, NamespaceDone, PublishNamespace, PublishSkipped, SubscribeNamespace,
    SubscribeTracks,
};
pub use publish::{Publish, PublishDone, PublishDoneStatus, RequestUpdate, StreamCount};
pub use request::{Redirect, RequestError, RequestErrorCode, RequestOk};
pub use subscribe::{Subscribe, SubscribeOk, TrackStatus};
