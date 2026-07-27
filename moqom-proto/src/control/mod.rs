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
//! dialect to a mapping layer.

pub mod frame;
pub mod message_type;
pub mod params;
pub mod request_id;

pub use frame::{BodyTooLong, ControlFrame, MAX_BODY_LEN};
pub use message_type::{MessageType, StreamKind};
pub use params::{MAX_VALUE_LEN, ParamError, ParamValue, Parameter, Parameters};
pub use request_id::{RequestId, RequestIdGenerator, Role};
