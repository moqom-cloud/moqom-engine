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

pub mod ids;
pub mod name;
pub mod object;

pub use ids::{GroupId, Location, ObjectId, SubgroupId, TrackAlias};
pub use name::{FullTrackName, NameError, TrackNamespace};
pub use object::ObjectStatus;
