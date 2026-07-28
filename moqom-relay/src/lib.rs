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
//! - Sessions are *authenticated* but not *authorised*. [`identity`] checks the
//!   signature on the token in Setup Options, so the relay knows which user on
//!   which device it is talking to; [`quota`] uses that to charge rate and
//!   concurrency limits to a person rather than to a connection. What no part of
//!   this does yet is check that the holder may publish under the namespace it
//!   announces, belongs to the room it names, or has not been banned. Anyone
//!   with any valid token can still publish under any namespace.
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
pub mod clock;
pub mod fabric;
pub mod identity;
pub mod metrics;
pub mod quota;
pub mod session;

pub use cache::{Cache, Limits};
pub use fabric::Fabric;
pub use identity::{Admission, AuthError, Authenticator, VerificationKey};
pub use metrics::Metrics;
pub use quota::{Governor, Principal, Quotas, Refusal};
pub use session::{Session, SessionError};
