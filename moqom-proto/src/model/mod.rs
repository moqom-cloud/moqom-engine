//! The MOQT object data model, per draft-19 §2.
//!
//! Four nested concepts, from the outside in:
//!
//! - A **track** ([`FullTrackName`]) is what a subscriber subscribes to: a
//!   namespace tuple plus a name.
//! - A **group** ([`GroupId`]) is an independently useful unit within a track,
//!   typically a GOP. Groups are the join points, so a late subscriber starts
//!   at a group boundary rather than mid-picture.
//! - A **subgroup** ([`SubgroupId`]) collects objects within a group that share
//!   a dependency and priority relationship, and therefore a stream. Subgroup
//!   IDs are scoped to their group and imply nothing across groups.
//! - An **object** ([`ObjectId`], [`ObjectStatus`]) is the addressable unit.
//!   Immutable: identified by namespace, name, group, and object ID, and
//!   required to be the same bytes wherever it is retrieved from.
//!
//! That immutability is what makes relay caching, deduplication, and recording
//! straightforward rather than a consistency problem — and it is why recording
//! is persisting a cache rather than building a pipeline.
//!
//! Every object belongs to exactly one subgroup *or* is a datagram, in which
//! case it has no subgroup at all.
//!
//! [`layout`] is the exception to all of this: it is MOQOM's own convention for
//! what goes in which namespace field, not anything draft-19 defines. It lives
//! here because it is the inverse of the tuples the client builds, and both
//! sides have to agree.

pub mod ids;
pub mod layout;
pub mod name;
pub mod object;

pub use ids::{FetchEnd, GroupId, Location, ObjectId, ObjectSeq, SubgroupId, TrackAlias};
pub use layout::{Kind, Participant, Scope};
pub use name::{FullTrackName, NameError, TrackNamespace};
pub use object::ObjectStatus;
