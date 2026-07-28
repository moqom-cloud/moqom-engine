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
//! - Upstream subscriptions are **not** deduplicated. Two subscribers for one
//!   track cause two SUBSCRIBEs to the publisher, which is the opposite of what
//!   a relay is for: the bandwidth saving from fanning out one copy is most of
//!   the point. Fixing it means a per-track record between the fabric and the
//!   route table, and it is the next thing to do here.
//! - Recent objects are retained ([`cache`]) and FETCH is served from them, so a
//!   late joiner can warm-start on the group in progress and a client that
//!   dropped its connection can ask for what it missed. Retention is bounded, so
//!   an outage longer than the window is answered with the gap markers that say
//!   so rather than with silence.
//! - There is no congestion-aware scheduling. Objects go out in the order they
//!   arrive, and a subscriber that cannot keep up applies back pressure to the
//!   publisher, which is the wrong direction — one slow viewer should be dropped
//!   down a layer, not allowed to slow the broadcast. `moqom-cc` is where that
//!   is fixed.
//! - There is no authorisation. Tokens in Setup Options are parsed and ignored,
//!   so anyone who can reach the port can publish under any namespace.
//! - Datagrams are not forwarded. Only subgroup streams are.
//!
//! Anything on that list is a thing to build, not a thing to be surprised by.
//! In particular, none of it is safe to expose to the internet yet.

#![forbid(unsafe_code)]

pub mod admin;
pub mod cache;
pub mod fabric;
pub mod metrics;
pub mod session;

pub use cache::{Cache, Limits};
pub use fabric::Fabric;
pub use metrics::Metrics;
pub use session::{Session, SessionError};
