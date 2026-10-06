//! A MOQT client: subscribe to tracks, announce namespaces, publish objects.
//!
//! This is the crate a recorder or classifier links. It is not the admin SDK —
//! minting tokens and kicking people out of rooms is [`moqom-sdk`](https://github.com/moqom-cloud/moqom-rust),
//! which deliberately has no QUIC in its dependency graph. Receiving frames is
//! this crate.
//!
//! The protocol sequence is the same one the relay's test harness speaks:
//! raw QUIC with the `moqt-19` ALPN, `Session::raw`, client-opened control
//! stream, SETUP, then request streams for `PUBLISH_NAMESPACE` and `SUBSCRIBE`.
//! Objects arrive on unidirectional streams as subgroups.

#![forbid(unsafe_code)]

pub mod device;
pub mod direct;
mod error;
pub mod properties;
mod session;
pub mod tls;
mod watch;

pub use device::{Credentials, DeviceKey, DeviceKeyError};
pub use error::Error;
pub use properties::ObjectProperties;
pub use session::{
    Announcement, GroupWriter, Metadata, Object, OutgoingObject, Session, Subscription,
};
pub use watch::{NamespaceEvent, NamespaceWatch};

pub use bytes::Bytes;
pub use moqom_proto::model::{FullTrackName, GroupId, NameError, TrackAlias, TrackNamespace};
