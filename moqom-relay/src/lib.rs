//! A MOQT relay.
//!
//! `moqom-transport` gets a session established; this is the first thing above
//! it that speaks MOQT. Until it existed the protocol implementation had a hole
//! in the middle: the codec was tested against itself, the Swift client was
//! tested against an in-memory loopback, and no two independent implementations
//! had ever exchanged a byte.
//!
//! # What a relay is, structurally
//!
//! Not a proxy. A proxy would terminate a subscription and re-issue it, copying
//! payloads through a decode and re-encode. A relay forwards *objects*, and the
//! only thing it must rewrite is the track alias in a subgroup header, because
//! aliases are assigned per session and the number a publisher chose means
//! something else downstream. Everything after that header is copied through
//! untouched.
//!
//! That is a deliberate design constraint rather than an optimisation. The
//! payload may be end-to-end encrypted, in which case the relay *cannot* read
//! it; a relay that needed to would be a relay that broke E2EE. Forwarding at
//! the subgroup level means scheduling, dropping, and fan-out all work on
//! ciphertext, which is what makes the two features compatible at all.
//!
//! # Scope of this implementation
//!
//! A vertical slice, and the boundaries are worth stating because the shape
//! looks complete:
//!
//! - SETUP, `PUBLISH_NAMESPACE`, `SUBSCRIBE_NAMESPACE`, and SUBSCRIBE are
//!   implemented, along with subgroup fan-out.
//! - Upstream subscriptions are deduplicated: however many people watch one
//!   track, the publisher is asked for it once and every copy after the first
//!   is made here. That is the arithmetic the whole thing is for, and
//!   `moqom_relay_subscriptions_total` reports it directly — `established`
//!   counts the copies the publisher paid for and `shared` the ones it did not.
//! - Recent objects are retained ([`cache`]) and FETCH is served from them, so a
//!   late joiner can warm-start on the group in progress and a client that
//!   dropped its connection can ask for what it missed. Retention is bounded, so
//!   an outage longer than the window is answered with the gap markers that say
//!   so rather than with silence.
//! - Subscribers are isolated from each other and shed rather than queue. Each
//!   copy of a subgroup is written by its own task with a short bounded queue,
//!   so a viewer that cannot keep up is abandoned for that subgroup — stream
//!   reset, `moqom_relay_subgroups_shed_total` incremented — instead of holding
//!   up the room or backing pressure up into the publisher's phone.
//!
//!   What the relay does *not* do is choose a smaller rung on that viewer's
//!   behalf. It cannot: the layers are the publisher's, the choice belongs to
//!   the subscriber, and a relay that guessed would be overriding a decision
//!   made with information it does not have. Shedding is what turns the
//!   condition into something the subscriber can see and act on. Scheduling
//!   between rungs of one broadcast — sending base layers before enhancement
//!   ones under pressure — is still to come, in `moqom-cc`.
//! - Subscriptions end at both ends. A subscriber closing its request stream is
//!   how this protocol spells unsubscribe, and when the last one watching a
//!   track does it the relay stops pulling that track — which is the saving
//!   made real, since the publisher is usually a phone spending its uplink and
//!   its battery on the room it is in. In the other direction a publisher that
//!   stops is announced to every viewer with `PUBLISH_DONE`, because objects
//!   merely ceasing is what a bad network looks like too, and a player is right
//!   to wait that out.
//! - Sessions are authenticated by [`identity`] and authorised by [`scope`]: a
//!   token's tenant, room, and grants are compared against the namespace every
//!   request names, so a holder may publish only as themselves, in the room
//!   they were admitted to, and may reach only what that room contains. What is
//!   still missing on a relay that has not attached is revocation — a ban is
//!   then enforced when the next token is minted rather than against the
//!   session already open. A relay that *has* attached (`MOQOM_CONTROL_ENDPOINT`)
//!   closes the session when the control plane ejects it; that is the path
//!   `interop_link` and the admin CLIs exercise.
//!
//!   Note the shape of the default: with no keys configured there is no
//!   verified tenant to compare anything against, and such a relay authorises
//!   nothing at all. That is the mode the benches and the two-phone rig run in,
//!   and it is the mode this warning is about.
//! - Datagrams are not forwarded. Only subgroup streams are.
//!
//! Anything on that list is a thing to build, not a thing to be surprised by.
//! In particular, none of it is safe to expose to the internet yet.

// `deny` rather than `forbid`, which is a weaker statement and a deliberate one.
// `forbid` cannot be lifted by an inner `allow`, and there is exactly one place
// that needs to: reading the kernel's own opinion of its clock means calling
// `adjtimex`, and there is no way to that number in std. See [`clock`], where
// the exception is scoped to the single function and argued for.
//
// The property worth keeping is that unsafe cannot appear by accident, and
// `deny` keeps it: adding a block anywhere fails the build until somebody writes
// an `allow` and, being visible in review, says why.
#![deny(unsafe_code)]

pub mod admin;
pub mod cache;
pub mod catalog;
pub mod clock;
pub mod fabric;
pub mod identity;
pub mod link;
pub mod media;
pub mod metrics;
pub mod policy;
pub mod possession;
pub mod quota;
pub mod roster;
pub mod scope;
pub mod session;

mod generated;

pub use cache::{Cache, Limits};
pub use fabric::Fabric;
pub use identity::{Admission, AuthError, Authenticator, VerificationKey};
pub use link::{Link, Supervisor};
pub use metrics::Metrics;
pub use policy::{Ban, Banned, Policy, Rules};
pub use quota::{Governor, Principal, Quotas, Refusal};
pub use roster::{Presence, Roster};
pub use scope::{Denial, Permission, Publish, Scope};
pub use session::{Session, SessionError};
