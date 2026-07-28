//! The data plane: objects on datagrams and on subgroup streams.
//!
//! Where the control plane negotiates, this moves media, and the difference
//! shows in the encoding. Control messages are self-delimiting and bounded at
//! 64 KiB; data framing pushes fields into type-code bits and elides anything
//! derivable, because these bytes are on every frame of every stream and a byte
//! saved is a byte times the whole fan-out.
//!
//! Two mappings exist, and choosing between them is a latency decision rather
//! than a formatting one:
//!
//! - **Datagrams** ([`datagram`]) carry one object with no retransmission. A
//!   loss costs exactly that object. Right for anything where arriving late is
//!   worse than not arriving: audio, control-rate telemetry, small video
//!   frames.
//! - **Subgroup streams** ([`subgroup`]) carry many objects in order with QUIC
//!   reliability. A loss blocks everything behind it on that stream, but only
//!   on that stream, which is why subgroup granularity is the lever — one
//!   stream per subgroup means head-of-line blocking is scoped to media that
//!   was already useless without its predecessor.
//!
//! A third mapping exists for objects that are already in the past. Fetch
//! streams ([`fetch`]) answer one request rather than carrying a track, so they
//! span groups, and their framing is delta-coded against the previous record
//! instead of against a header. They also carry gap markers, because a relay
//! answering from a bounded cache has to be able to say which part of the range
//! it does not hold.

pub mod datagram;
pub mod fetch;
pub mod flags;
pub mod object;
pub mod subgroup;

pub use datagram::{
    DatagramContent, NonEmptyPayload, ObjectDatagram, PADDING_DATAGRAM_TYPE, PADDING_STREAM_TYPE,
};
pub use fetch::{
    FETCH_HEADER_TYPE, FetchError, FetchHeader, FetchObject, FetchReader, FetchRecord, FetchWriter,
    GroupOrder,
};
pub use flags::{DatagramType, SubgroupIdMode, SubgroupType};
pub use object::TerminalStatus;
pub use subgroup::{
    SubgroupContent, SubgroupError, SubgroupHeader, SubgroupObject, SubgroupReader, SubgroupSource,
    SubgroupWriter,
};
