//! What the control plane has told this relay about the rooms it serves.
//!
//! Bans, closures and ceilings, held locally and consulted during a handshake.
//! The point is what does *not* happen: no call to the control plane, ever, on
//! the path a session takes to join. A relay that asked would put a second
//! service — and its outage, and its tail latency — between a phone and the room
//! it is trying to enter, and would make joining a room slower than joining an
//! Agora one for no benefit anybody can see.
//!
//! So the state arrives beforehand, by [`crate::link`], and this is where it
//! sits. The cost of that choice is staleness, and the shape of the staleness is
//! the reason the control plane sends whole snapshots rather than deltas: a
//! missed delta leaves a relay permissive, which is the wrong way to be wrong,
//! and a missed snapshot leaves it a snapshot behind.
//!
//! # Being unreachable is not being permissive, and not being useless either
//!
//! A relay that has lost the control plane keeps enforcing what it already
//! knows. What it can miss is a *new* ban, not an existing one. Refusing
//! everybody the moment the link breaks would turn a control-plane deploy into a
//! total outage, so instead the link has a grace period, and when it lapses the
//! relay stops accepting *new* sessions while keeping the ones it has. Ejecting a
//! room full of people because a gRPC stream broke is a worse answer than serving
//! them slightly stale policy — and the people already in the room were admitted
//! against state that was fresh at the time.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crate::scope::Scope;

/// A room, named the way everything upstream names one.
pub type Where = (Arc<str>, Arc<str>);

/// Who a ban applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Banned {
    /// Everybody signed in as this person.
    User(String),
    /// One device of one person, for the compromised-laptop case.
    Device {
        /// The account.
        user: String,
        /// The device identifier, as the token's thumbprint derives it.
        device: String,
    },
    /// An address range, which is the only key that survives a new account.
    Address {
        /// The network address.
        network: IpAddr,
        /// How many leading bits must match.
        bits: u8,
    },
}

impl Banned {
    /// An address ban from `203.0.113.0/24` or a bare address.
    ///
    /// Returns `None` for anything that does not parse. A prefix this relay
    /// cannot read is dropped rather than guessed at, and counted where it is
    /// applied: the alternative is a ban that silently matches everybody or
    /// nobody, and both are worse than a visible gap.
    #[must_use]
    pub fn address(prefix: &str) -> Option<Self> {
        let (address, bits) = match prefix.split_once('/') {
            Some((address, bits)) => (address, bits.parse::<u8>().ok()?),
            None => (prefix, u8::MAX),
        };
        let network: IpAddr = address.parse().ok()?;
        let width = if network.is_ipv4() { 32 } else { 128 };
        let bits = if bits == u8::MAX { width } else { bits };
        if bits > width {
            return None;
        }
        Some(Self::Address { network, bits })
    }

    /// Whether this ban catches a session.
    #[must_use]
    pub fn catches(&self, user: &str, device: &str, address: IpAddr) -> bool {
        match self {
            Self::User(banned) => banned == user,
            Self::Device {
                user: banned,
                device: which,
            } => banned == user && which == device,
            Self::Address { network, bits } => within(*network, *bits, address),
        }
    }
}

/// Whether `address` is inside `network/bits`.
fn within(network: IpAddr, bits: u8, address: IpAddr) -> bool {
    fn covered(network: &[u8], address: &[u8], bits: u8) -> bool {
        let whole = usize::from(bits / 8);
        let spare = bits % 8;
        if network[..whole] != address[..whole] {
            return false;
        }
        if spare == 0 {
            return true;
        }
        let mask = 0xFFu8 << (8 - spare);
        network[whole] & mask == address[whole] & mask
    }

    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            covered(&network.octets(), &address.octets(), bits)
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            covered(&network.octets(), &address.octets(), bits)
        }
        // A v4 ban and a v6 session, or the reverse. Not matched, and not
        // mapped: a relay that decided ::ffff:203.0.113.4 was the same host as
        // 203.0.113.4 would be right about the packet and wrong about the ban
        // the moderator wrote, and the two disagree often enough that guessing
        // is worse than the miss.
        _ => false,
    }
}

/// One ban, and when it stops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ban {
    /// Who it applies to.
    pub who: Banned,
    /// When it lifts. `None` is permanent.
    pub until: Option<SystemTime>,
}

impl Ban {
    /// Whether this ban still applies at `now`.
    #[must_use]
    pub fn holds(&self, now: SystemTime) -> bool {
        self.until.is_none_or(|until| now < until)
    }
}

/// Everything the relay must know to serve one room without asking again.
#[derive(Debug, Clone, Default)]
pub struct Rules {
    /// A closed room refuses new sessions.
    pub closed: bool,
    /// Bans in force, including the tenant-wide ones that reach this room.
    pub bans: Vec<Ban>,
    /// How many sessions the room may hold. Zero means no ceiling.
    pub ceiling: u32,
}

/// Why a session was not let in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The person, the device, or the address is banned.
    #[error("banned from this room")]
    Banned,
    /// The room is closed.
    #[error("this room is closed")]
    Closed,
    /// The room is at its participant ceiling.
    #[error("this room is full")]
    Full,
    /// This relay has been out of touch with the control plane for longer than
    /// it is willing to admit people on stale policy.
    #[error("this relay is not currently supervised")]
    Unsupervised,
}

impl Refusal {
    /// A stable, low-cardinality name for metrics and logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Banned => "banned",
            Self::Closed => "closed",
            Self::Full => "full",
            Self::Unsupervised => "unsupervised",
        }
    }
}

/// Whether anybody is supervising this relay, and since when.
#[derive(Debug, Clone, Copy)]
enum Supervision {
    /// No control plane is configured. Nothing to be out of touch with, and
    /// nothing to enforce: this is the mode the benches and the two-phone rig
    /// run in.
    None,
    /// Attached, with policy as fresh as the last thing that arrived.
    Attached,
    /// The link is down. New sessions are admitted until `grace` has passed.
    Detached { since: Instant, grace: Duration },
}

#[derive(Debug)]
struct Inner {
    rooms: HashMap<Where, Rules>,
    supervision: Supervision,
    /// Bans the control plane sent that this relay could not read.
    ///
    /// Counted rather than ignored. A prefix in a form this build does not
    /// understand is a ban that is not being enforced, and the only place that
    /// fact can be noticed is here.
    unreadable: u64,
}

/// The rooms this relay serves, and the terms it serves them on.
///
/// Cheap to clone; all clones see the same rules.
#[derive(Debug, Clone)]
pub struct Policy {
    inner: Arc<Mutex<Inner>>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                rooms: HashMap::new(),
                supervision: Supervision::None,
                unreadable: 0,
            })),
        }
    }
}

impl Policy {
    /// A policy with no rules and no control plane.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Note that the link is up.
    pub fn attached(&self) {
        self.lock().supervision = Supervision::Attached;
    }

    /// Note that the link is down, and for how long that is tolerable.
    ///
    /// Idempotent: a link that fails repeatedly while retrying must not restart
    /// its own grace period, which would make the period unbounded exactly when
    /// the control plane is having the worst time.
    pub fn detached(&self, grace: Duration) {
        let mut inner = self.lock();
        if matches!(inner.supervision, Supervision::Detached { .. }) {
            return;
        }
        inner.supervision = Supervision::Detached {
            since: Instant::now(),
            grace,
        };
    }

    /// Whether the link is currently down.
    ///
    /// Distinct from [`Self::supervised`], which asks whether that has gone on
    /// long enough to matter. A relay that is out of touch and still admitting
    /// is the normal state during a control-plane deploy; one that stays there
    /// is the thing to alert on.
    #[must_use]
    pub fn out_of_touch(&self) -> bool {
        matches!(self.lock().supervision, Supervision::Detached { .. })
    }

    /// Whether new sessions are being admitted at all.
    #[must_use]
    pub fn supervised(&self) -> bool {
        match self.lock().supervision {
            Supervision::None | Supervision::Attached => true,
            Supervision::Detached { since, grace } => since.elapsed() < grace,
        }
    }

    /// Replace everything known about one room.
    pub fn describe(&self, room: Where, rules: Rules) {
        self.lock().rooms.insert(room, rules);
    }

    /// Add or remove one ban without disturbing the rest of the room.
    pub fn revise(&self, room: Where, ban: Ban, active: bool) {
        let mut inner = self.lock();
        let rules = inner.rooms.entry(room).or_default();
        rules.bans.retain(|held| held.who != ban.who);
        if active {
            rules.bans.push(ban);
        }
    }

    /// Open or close a room.
    pub fn close(&self, room: Where, closed: bool) {
        self.lock().rooms.entry(room).or_default().closed = closed;
    }

    /// Note a ban that arrived in a form this relay could not read.
    pub fn unreadable(&self) {
        self.lock().unreadable += 1;
    }

    /// How many of those there have been.
    #[must_use]
    pub fn unreadable_bans(&self) -> u64 {
        self.lock().unreadable
    }

    /// Forget a room, for one this relay no longer serves.
    pub fn forget(&self, room: &Where) {
        self.lock().rooms.remove(room);
    }

    /// Everybody in `room` this policy would now refuse.
    ///
    /// For applying a ban that arrived after the session it catches. Returns the
    /// bans rather than acting, because acting means closing connections and
    /// that is the roster's business.
    #[must_use]
    pub fn catches(&self, room: &Where, user: &str, device: &str, address: IpAddr) -> bool {
        let now = SystemTime::now();
        let inner = self.lock();
        inner.rooms.get(room).is_some_and(|rules| {
            rules
                .bans
                .iter()
                .any(|ban| ban.holds(now) && ban.who.catches(user, device, address))
        })
    }

    /// Whether a session holding `scope` may join from `address`.
    ///
    /// `occupancy` is how many sessions the room already holds, passed in rather
    /// than looked up so that this type owes nothing to the roster and can be
    /// reasoned about — and tested — on its own.
    ///
    /// # Errors
    /// [`Refusal`] saying which rule refused, which goes in the connection's
    /// close reason and into a counter.
    pub fn admits(&self, scope: &Scope, address: IpAddr, occupancy: usize) -> Result<(), Refusal> {
        let Some(room) = &scope.room else {
            // No room to have a policy about. Personal channels are governed by
            // the token alone, which is what lets a broadcaster be followed
            // outside a call.
            return Ok(());
        };

        let now = SystemTime::now();
        let inner = self.lock();

        match inner.supervision {
            Supervision::None | Supervision::Attached => {}
            Supervision::Detached { since, grace } => {
                if since.elapsed() >= grace {
                    return Err(Refusal::Unsupervised);
                }
            }
        }

        let key = (Arc::clone(&scope.tenant), Arc::clone(room));
        let Some(rules) = inner.rooms.get(&key) else {
            // Nothing known about this room. Permissive on purpose and only
            // reachable before the first snapshot for it has arrived, which is
            // the first session in a room the control plane has not yet been
            // told about: it cannot have sent a ban for a room it does not know
            // this relay is serving.
            return Ok(());
        };

        if rules.closed {
            return Err(Refusal::Closed);
        }
        if rules
            .bans
            .iter()
            .any(|ban| ban.holds(now) && ban.who.catches(&scope.user, &scope.device, address))
        {
            return Err(Refusal::Banned);
        }
        // The owner is never refused for capacity. A room whose host cannot
        // rejoin after a dropped connection is a room nobody can moderate, and
        // the ceiling exists to bound cost rather than to keep anybody out in
        // particular.
        if rules.ceiling > 0 && occupancy >= rules.ceiling as usize && !scope.owner {
            return Err(Refusal::Full);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::Publish;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn scope(user: &str) -> Scope {
        Scope {
            tenant: "acme".into(),
            user: user.into(),
            device: "phone".into(),
            room: Some("r1".into()),
            publish: Publish::AUDIO,
            capabilities: 0,
            owner: false,
            backstage: false,
        }
    }

    fn room() -> Where {
        ("acme".into(), "r1".into())
    }

    fn address(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    #[test]
    fn an_unknown_room_is_not_a_refusal() {
        let policy = Policy::new();
        assert!(policy.admits(&scope("ada"), address(4), 0).is_ok());
    }

    #[test]
    fn a_banned_person_is_refused_and_a_namesake_is_not() {
        let policy = Policy::new();
        policy.revise(
            room(),
            Ban {
                who: Banned::User("ada".into()),
                until: None,
            },
            true,
        );

        assert_eq!(
            policy.admits(&scope("ada"), address(4), 0),
            Err(Refusal::Banned)
        );
        assert!(policy.admits(&scope("adam"), address(4), 0).is_ok());
    }

    #[test]
    fn a_lifted_ban_lets_them_back_in() {
        let policy = Policy::new();
        let ban = Ban {
            who: Banned::User("ada".into()),
            until: None,
        };
        policy.revise(room(), ban.clone(), true);
        policy.revise(room(), ban, false);
        assert!(policy.admits(&scope("ada"), address(4), 0).is_ok());
    }

    #[test]
    fn an_expired_ban_is_no_ban() {
        let policy = Policy::new();
        policy.revise(
            room(),
            Ban {
                who: Banned::User("ada".into()),
                until: Some(SystemTime::now() - Duration::from_secs(1)),
            },
            true,
        );
        assert!(policy.admits(&scope("ada"), address(4), 0).is_ok());
    }

    #[test]
    fn an_address_ban_covers_its_prefix_and_stops_there() {
        let ban = Banned::address("203.0.113.0/24").expect("a prefix");
        assert!(ban.catches("ada", "phone", address(4)));
        assert!(ban.catches("bea", "laptop", address(250)));
        assert!(!ban.catches("ada", "phone", IpAddr::V4(Ipv4Addr::new(203, 0, 114, 4))));

        // A bare address is a ban on one host.
        let one = Banned::address("203.0.113.4").expect("an address");
        assert!(one.catches("ada", "phone", address(4)));
        assert!(!one.catches("ada", "phone", address(5)));

        // Bits that are not whole bytes.
        let half = Banned::address("203.0.113.0/28").expect("a prefix");
        assert!(half.catches("ada", "phone", address(15)));
        assert!(!half.catches("ada", "phone", address(16)));

        // Families do not cross.
        assert!(!ban.catches("ada", "phone", IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(Banned::address("nonsense/24").is_none());
        assert!(Banned::address("203.0.113.0/48").is_none());
    }

    #[test]
    fn a_device_ban_reaches_one_device() {
        let ban = Banned::Device {
            user: "ada".into(),
            device: "phone".into(),
        };
        assert!(ban.catches("ada", "phone", address(4)));
        assert!(!ban.catches("ada", "laptop", address(4)));
    }

    #[test]
    fn a_closed_room_refuses_before_it_counts_anybody() {
        let policy = Policy::new();
        policy.close(room(), true);
        assert_eq!(
            policy.admits(&scope("ada"), address(4), 0),
            Err(Refusal::Closed)
        );
        policy.close(room(), false);
        assert!(policy.admits(&scope("ada"), address(4), 0).is_ok());
    }

    #[test]
    fn the_ceiling_holds_for_everybody_except_the_owner() {
        let policy = Policy::new();
        policy.describe(
            room(),
            Rules {
                ceiling: 2,
                ..Rules::default()
            },
        );
        assert!(policy.admits(&scope("ada"), address(4), 1).is_ok());
        assert_eq!(
            policy.admits(&scope("ada"), address(4), 2),
            Err(Refusal::Full)
        );

        let mut host = scope("ada");
        host.owner = true;
        assert!(policy.admits(&host, address(4), 9).is_ok());
    }

    #[test]
    fn a_relay_out_of_touch_admits_until_the_grace_lapses() {
        let policy = Policy::new();
        policy.detached(Duration::from_secs(30));
        assert!(policy.supervised());
        assert!(policy.admits(&scope("ada"), address(4), 0).is_ok());

        policy.detached(Duration::ZERO);
        // Still the first grace, because a retry loop must not extend it.
        assert!(policy.supervised());

        let lapsed = Policy::new();
        lapsed.detached(Duration::ZERO);
        assert!(!lapsed.supervised());
        assert_eq!(
            lapsed.admits(&scope("ada"), address(4), 0),
            Err(Refusal::Unsupervised)
        );

        lapsed.attached();
        assert!(lapsed.supervised());
        assert!(lapsed.admits(&scope("ada"), address(4), 0).is_ok());
    }

    #[test]
    fn describing_a_room_replaces_what_was_known_about_it() {
        let policy = Policy::new();
        policy.revise(
            room(),
            Ban {
                who: Banned::User("ada".into()),
                until: None,
            },
            true,
        );
        // A snapshot without that ban is the control plane saying it is gone.
        policy.describe(room(), Rules::default());
        assert!(policy.admits(&scope("ada"), address(4), 0).is_ok());
    }

    #[test]
    fn a_ban_that_arrives_late_still_names_who_it_catches() {
        let policy = Policy::new();
        policy.revise(
            room(),
            Ban {
                who: Banned::User("ada".into()),
                until: None,
            },
            true,
        );
        assert!(policy.catches(&room(), "ada", "phone", address(4)));
        assert!(!policy.catches(&room(), "bea", "phone", address(4)));
    }
}
