//! Which MOQT draft a session speaks, and how that reaches the codec.
//!
//! Drafts differ at every layer: the integer encoding under every field, how
//! Message Parameters are typed, which control messages exist, and what a few
//! layouts look like. A session learns its draft once, from the negotiated
//! ALPN, and every byte it reads or writes afterwards has to agree with it.
//!
//! # How the draft reaches a leaf
//!
//! Almost every field bottoms out in [`VarInt::encode`](crate::VarInt::encode)
//! or [`VarInt::decode`](crate::VarInt::decode), a few hundred call sites deep
//! in nested structures. Threading a parameter through all of them would make
//! every signature in the crate draft-aware for the sake of one branch at the
//! bottom. Instead the draft is ambient: [`Draft::scope`] sets it for the
//! duration of one synchronous call, and the leaves consult [`Draft::current`].
//!
//! The constraint that makes this sound is that a scope never spans an
//! `.await`: it wraps a single encode or decode of a buffer already in memory,
//! so a task switch cannot observe another session's draft. Session code never
//! calls the leaves outside a scope it opened itself; the readers and writers
//! that live across awaits ([`SubgroupReader`](crate::data::SubgroupReader),
//! [`FetchReader`](crate::data::FetchReader) and their writers) store their
//! draft and re-open the scope on every call.
//!
//! A session task can instead be wrapped whole in [`Draft::bind`], which
//! opens the scope around each poll of its future and closes it before the
//! poll returns. That keeps the same guarantee — no other task on the thread
//! ever runs inside it — while letting session code call the codec anywhere
//! without naming the draft.
//!
//! Outside any scope the draft is [`Draft::D19`], which is what every call
//! site that predates this module was written against.
//!
//! # What each draft means here
//!
//! - [`Draft::D19`] is the wire format MOQOM deployed as `moqt-19`: QUIC
//!   varints, Message Parameters typed by parity like Setup Options, and one
//!   bidirectional control stream. It is not byte-compatible with
//!   draft-ietf-moq-transport-19 as published, which uses the leading-ones
//!   `vi64`, per-parameter types and a pair of unidirectional control streams;
//!   it is kept as it is because every deployed MOQOM client speaks it.
//! - [`Draft::D22`] is draft-ietf-moq-transport-22 as written: `vi64`
//!   integers, the §9.3 parameter registry, the unidirectional control-stream
//!   pair and the §12 error registries.
//! - [`Draft::D16`] is draft-ietf-moq-transport-16, client side only, for the
//!   subset Cloudflare's relays implement. Its control messages are a separate
//!   grammar in [`control::d16`](crate::control::d16); this crate only needs
//!   the draft here so that the integer encoding and the data-plane type codes
//!   agree with it.
//!
//! Adding a draft means a variant here, its answers to the three questions
//! below, and its message grammar where it differs. Draft-18 would answer
//! `vi64` and request streams like draft-22, with typed parameters and its
//! own message layouts.

use std::cell::Cell;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A MOQT draft this crate can encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Draft {
    /// `moqt-16`: Cloudflare's relays.
    D16,
    /// `moqt-19` as MOQOM deployed it.
    D19,
    /// `moqt-22`.
    D22,
}

thread_local! {
    static CURRENT: Cell<Draft> = const { Cell::new(Draft::D19) };
}

impl Draft {
    /// Every draft, newest first — the order a client offers them in.
    pub const ALL: &'static [Self] = &[Self::D22, Self::D19, Self::D16];

    /// The ALPN token that selects this draft over raw QUIC, and the
    /// WebTransport protocol token that selects it over HTTP/3.
    #[must_use]
    pub const fn alpn(self) -> &'static [u8] {
        match self {
            Self::D16 => b"moqt-16",
            Self::D19 => b"moqt-19",
            Self::D22 => b"moqt-22",
        }
    }

    /// The draft an ALPN or WebTransport protocol token names.
    #[must_use]
    pub fn from_alpn(token: &[u8]) -> Option<Self> {
        Self::ALL.iter().copied().find(|d| d.alpn() == token)
    }

    /// Whether integers use draft-17's leading-ones `vi64` (1–9 bytes, the
    /// full 64-bit range) rather than RFC 9000's two-bit-prefix varint.
    #[must_use]
    pub const fn uses_vi64(self) -> bool {
        matches!(self, Self::D22)
    }

    /// Whether Message Parameters are typed by a per-parameter registry
    /// entry, and an unknown one is a protocol violation; otherwise they are
    /// key-value pairs typed by parity and an unknown one is skipped.
    #[must_use]
    pub const fn typed_parameters(self) -> bool {
        matches!(self, Self::D22)
    }

    /// Whether the control channel is a pair of unidirectional streams, one
    /// each way, with every request on its own bidirectional stream. Otherwise
    /// it is one bidirectional stream the client opens.
    #[must_use]
    pub const fn unidirectional_control(self) -> bool {
        matches!(self, Self::D22)
    }

    /// The draft the calling thread is encoding in.
    ///
    /// [`Draft::D19`] outside any [`Draft::scope`].
    #[must_use]
    pub fn current() -> Self {
        CURRENT.with(Cell::get)
    }

    /// Run `f` with `self` as the ambient draft, restoring the previous one
    /// afterwards, including on unwind.
    ///
    /// `f` must not await: the scope is thread-local, and a task resumed on
    /// another thread would see that thread's draft instead.
    pub fn scope<R>(self, f: impl FnOnce() -> R) -> R {
        struct Restore(Draft);
        impl Drop for Restore {
            fn drop(&mut self) {
                CURRENT.with(|c| c.set(self.0));
            }
        }
        let _restore = Restore(CURRENT.with(|c| c.replace(self)));
        f()
    }

    /// `future`, with `self` as the ambient draft whenever it is polled.
    ///
    /// Each poll is a [`Draft::scope`], so the draft is in force for exactly
    /// the synchronous stretches of the future and never leaks to whatever
    /// the executor runs next. A future spawned from inside is a separate task
    /// and must be bound itself.
    pub fn bind<F: Future>(self, future: F) -> Bound<F> {
        Bound {
            draft: self,
            future: Box::pin(future),
        }
    }
}

/// A future running in a draft. See [`Draft::bind`].
#[must_use = "futures do nothing unless polled"]
pub struct Bound<F> {
    draft: Draft,
    future: Pin<Box<F>>,
}

impl<F: Future> Future for Bound<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = self.get_mut();
        this.draft.scope(|| this.future.as_mut().poll(cx))
    }
}

impl<F> fmt::Debug for Bound<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bound")
            .field("draft", &self.draft)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for Draft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::D16 => "moqt-16",
            Self::D19 => "moqt-19",
            Self::D22 => "moqt-22",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_round_trips() {
        for &draft in Draft::ALL {
            assert_eq!(Draft::from_alpn(draft.alpn()), Some(draft));
            assert_eq!(draft.to_string().as_bytes(), draft.alpn());
        }
        assert_eq!(Draft::from_alpn(b"moqt-20"), None);
    }

    #[test]
    fn scope_nests_and_restores() {
        assert_eq!(Draft::current(), Draft::D19);
        Draft::D22.scope(|| {
            assert_eq!(Draft::current(), Draft::D22);
            Draft::D16.scope(|| assert_eq!(Draft::current(), Draft::D16));
            assert_eq!(Draft::current(), Draft::D22);
        });
        assert_eq!(Draft::current(), Draft::D19);
    }

    #[test]
    fn bind_scopes_each_poll() {
        use std::task::Waker;
        let mut seen = Vec::new();
        let mut future = Draft::D22.bind(async {
            seen.push(Draft::current());
        });
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut future).poll(&mut cx).is_ready());
        drop(future);
        assert_eq!(seen, [Draft::D22]);
        assert_eq!(Draft::current(), Draft::D19);
    }

    #[test]
    fn scope_restores_on_unwind() {
        let result = std::panic::catch_unwind(|| Draft::D22.scope(|| panic!("inside")));
        assert!(result.is_err());
        assert_eq!(Draft::current(), Draft::D19);
    }
}
