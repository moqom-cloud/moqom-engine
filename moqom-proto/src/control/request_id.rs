//! Request identifiers, per draft-19 §10.1.
//!
//! # Why this is a separate type rather than a varint field
//!
//! Draft-19 correlates a response to its request by the **bidirectional stream
//! they share** — only requests carry an explicit Request ID, and responses
//! carry none. Earlier drafts, and Cloudflare's production `moqt-16`, put the
//! identifier in every message on one shared control stream instead.
//!
//! Those are different correlation models, and code that assumes either one is
//! painful to retrofit. Keeping request identity as its own value, distinct
//! from whatever stream carried it, is what makes a second dialect a mapping
//! layer rather than a rewrite.

use crate::error::DecodeError;
use crate::varint::VarInt;

/// Which side of the session an endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The endpoint that initiated the session. Generates even request IDs.
    Client,
    /// The endpoint that accepted it. Generates odd request IDs.
    Server,
}

impl Role {
    /// The other side.
    #[must_use]
    pub const fn peer(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }

    /// The first request ID this role emits: 0 for a client, 1 for a server.
    #[must_use]
    pub const fn first_request_id(self) -> RequestId {
        RequestId(match self {
            Self::Client => 0,
            Self::Server => 1,
        })
    }
}

/// Identifies a request within a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(u64);

impl RequestId {
    /// Construct from a raw value.
    ///
    /// # Errors
    /// [`crate::BoundsExceeded`] if outside varint range, since request IDs are
    /// encoded as variable-length integers.
    pub const fn new(value: u64) -> Result<Self, crate::BoundsExceeded> {
        match VarInt::new(value) {
            Ok(v) => Ok(Self(v.get())),
            Err(e) => Err(e),
        }
    }

    /// The raw value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The role that must have generated this ID, determined by its parity.
    #[must_use]
    pub const fn originator(self) -> Role {
        if self.0.is_multiple_of(2) {
            Role::Client
        } else {
            Role::Server
        }
    }

    /// Whether `sender` is permitted to have generated this ID.
    ///
    /// A mismatch is not a soft error: draft-19 §10.1 requires closing the
    /// session with `INVALID_REQUEST_ID`.
    #[must_use]
    pub const fn is_valid_from(self, sender: Role) -> bool {
        matches!(
            (self.originator(), sender),
            (Role::Client, Role::Client) | (Role::Server, Role::Server)
        )
    }

    /// Encode as a variable-length integer.
    ///
    /// # Panics
    /// Cannot panic: the constructor guarantees varint range.
    pub fn encode<B: bytes::BufMut>(self, buf: &mut B) {
        VarInt::new(self.0)
            .expect("request id validated at construction")
            .encode(buf);
    }

    /// Encoded size in bytes.
    ///
    /// # Panics
    /// Cannot panic: the constructor guarantees varint range.
    #[must_use]
    pub fn encoded_len(self) -> usize {
        VarInt::new(self.0)
            .expect("request id validated at construction")
            .size()
    }

    /// Decode a variable-length integer as a request ID.
    ///
    /// Does **not** check parity, because that requires knowing which peer sent
    /// it — see [`Self::is_valid_from`]. Nor does it check for duplicates,
    /// which is session state rather than a codec concern.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete.
    pub fn decode<B: bytes::Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        Ok(Self(VarInt::decode(buf)?.get()))
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Allocates request IDs for one endpoint.
///
/// Each endpoint increments by two so the parity that identifies the
/// originator is preserved for the life of the session.
#[derive(Debug, Clone)]
pub struct RequestIdGenerator {
    role: Role,
    next: u64,
}

impl RequestIdGenerator {
    /// Start allocating for `role`, from its first legal value.
    #[must_use]
    pub const fn new(role: Role) -> Self {
        Self {
            role,
            next: role.first_request_id().get(),
        }
    }

    /// The role this generator allocates for.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Allocate the next request ID.
    ///
    /// Returns `None` once the varint space is exhausted. That is not a
    /// realistic outcome — 2^61 requests on one session — but silently wrapping
    /// would reissue live IDs, so exhaustion is surfaced rather than ignored.
    pub fn allocate(&mut self) -> Option<RequestId> {
        let id = RequestId::new(self.next).ok()?;
        self.next = self.next.checked_add(2)?;
        Some(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_identifies_the_originator() {
        assert_eq!(RequestId::new(0).unwrap().originator(), Role::Client);
        assert_eq!(RequestId::new(2).unwrap().originator(), Role::Client);
        assert_eq!(RequestId::new(1).unwrap().originator(), Role::Server);
        assert_eq!(RequestId::new(3).unwrap().originator(), Role::Server);
    }

    /// A peer using the wrong parity is a session error, not something to
    /// tolerate, so the check needs to be available at every receive site.
    #[test]
    fn wrong_parity_is_detectable() {
        let client_id = RequestId::new(4).unwrap();
        assert!(client_id.is_valid_from(Role::Client));
        assert!(!client_id.is_valid_from(Role::Server));

        let server_id = RequestId::new(5).unwrap();
        assert!(server_id.is_valid_from(Role::Server));
        assert!(!server_id.is_valid_from(Role::Client));
    }

    #[test]
    fn generators_start_correctly_and_step_by_two() {
        let mut client = RequestIdGenerator::new(Role::Client);
        assert_eq!(client.allocate().unwrap().get(), 0);
        assert_eq!(client.allocate().unwrap().get(), 2);
        assert_eq!(client.allocate().unwrap().get(), 4);

        let mut server = RequestIdGenerator::new(Role::Server);
        assert_eq!(server.allocate().unwrap().get(), 1);
        assert_eq!(server.allocate().unwrap().get(), 3);
    }

    #[test]
    fn generated_ids_always_validate_against_their_own_role() {
        for role in [Role::Client, Role::Server] {
            let mut ids = RequestIdGenerator::new(role);
            for _ in 0..100 {
                let id = ids.allocate().unwrap();
                assert!(id.is_valid_from(role));
                assert!(!id.is_valid_from(role.peer()));
            }
        }
    }

    #[test]
    fn exhaustion_is_reported_rather_than_wrapping() {
        let mut ids = RequestIdGenerator {
            role: Role::Client,
            next: crate::varint::MAX - 1,
        };
        assert!(ids.allocate().is_some(), "MAX-1 is even and in range");
        assert!(ids.allocate().is_none(), "next step leaves varint range");
    }

    #[test]
    fn round_trips() {
        for raw in [0u64, 1, 2, 63, 64, 16_384, crate::varint::MAX - 1] {
            let id = RequestId::new(raw).unwrap();
            let mut buf = Vec::new();
            id.encode(&mut buf);
            assert_eq!(buf.len(), id.encoded_len());

            let mut cursor = buf.as_slice();
            assert_eq!(RequestId::decode(&mut cursor).unwrap(), id);
        }
    }

    #[test]
    fn rejects_values_outside_varint_range() {
        assert!(RequestId::new(crate::varint::MAX).is_ok());
        assert!(RequestId::new(crate::varint::MAX + 1).is_err());
    }

    #[test]
    fn roles_are_symmetric() {
        assert_eq!(Role::Client.peer(), Role::Server);
        assert_eq!(Role::Server.peer(), Role::Client);
        assert_eq!(Role::Client.peer().peer(), Role::Client);
    }
}
