//! Control messages, per draft-19 §10.
//!
//! # Layering
//!
//! [`ControlFrame`] handles the envelope — type, length, opaque body — and
//! knows nothing about any particular message. Bodies are parsed separately.
//! The split matters because the two failures are different: a body that
//! disagrees with its declared length has desynchronised the stream and the
//! session is over, whereas a body that parses badly is one message's problem.
//!
//! # Where the dialect seam is
//!
//! Draft-19 puts each request on its own bidirectional stream and correlates
//! responses by that stream, so only requests carry a [`RequestId`] and
//! cancellation is a stream reset rather than an `UNSUBSCRIBE` message.
//! Cloudflare's deployed `moqt-16` instead multiplexes everything over one
//! control stream with an identifier in every message.
//!
//! Both models are expressible over the same envelope and the same parameter
//! encoding. Keeping request identity ([`RequestId`]) separate from stream
//! identity, rather than assuming one implies the other, is what keeps a second
//! dialect to a mapping layer. That layer is [`d16`].
//!
//! Draft-22 keeps draft-19's message set and stream model, and differs in
//! the integer encoding, the parameter registry ([`typed`]), FETCH's layout,
//! one new message (`PUBLISH_STATE_NOTIFY`) and its error registries
//! ([`codes`]). Message types that differ read [`Draft::current`](crate::Draft::current).

pub mod codes;
pub mod d16;
pub mod frame;
pub mod message_type;
pub mod messages;
pub mod params;
pub mod properties;
pub mod reason;
pub mod request_id;
pub mod setup;
pub mod tokens;
pub mod typed;

pub use frame::{
    BodyTooLong, ControlFrame, MAX_BODY_LEN, MessageBody, write_message, write_message_in,
};
pub use message_type::{MessageType, StreamKind};
pub use messages::{
    DoneReason, Fetch, FetchKind, FetchOk, Goaway, GoawayError, Namespace, NamespaceDone, Publish,
    PublishDone, PublishDoneStatus, PublishNamespace, PublishSkipped, PublishStateNotify, Redirect,
    RequestError, RequestErrorCode, RequestOk, RequestUpdate, StreamCount, Subscribe,
    SubscribeNamespace, SubscribeOk, SubscribeTracks, TrackStatus,
};
pub use params::{MAX_VALUE_LEN, ParamError, ParamValue, Parameter, Parameters};
pub use properties::Properties;
pub use reason::ReasonPhrase;
pub use request_id::{RequestId, RequestIdGenerator, Role};
pub use setup::{Setup, SetupError, SetupOptions, Transport};
