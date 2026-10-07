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

use crate::media::Kinds;
use crate::scope::{Ceiling, Scope};

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

/// One force-mute, as the control plane issued it.
///
/// Separate from a ban rather than folded into it because the two answer
/// different questions at different moments: a ban is asked about once, when
/// somebody tries to join, and a mute is asked about on every subscription to
/// the person it names, for as long as it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mute {
    /// The account.
    pub user: String,
    /// Which device, or empty for every device they are signed in on — the
    /// same convention `ParticipantRef` uses, and the one a moderator means
    /// when they mute a person rather than a phone.
    pub device: String,
    /// What is stopped.
    pub media: Kinds,
    /// Whether hosts and cohosts still receive it.
    pub audience_only: bool,
    /// When it lifts. `None` holds until somebody lifts it.
    pub until: Option<SystemTime>,
}

impl Mute {
    /// Whether this mute still applies at `now`.
    #[must_use]
    pub fn holds(&self, now: SystemTime) -> bool {
        self.until.is_none_or(|until| now < until)
    }

    /// Whether this mute names that person, and that device if it names one.
    #[must_use]
    pub fn catches(&self, user: &str, device: &str) -> bool {
        self.user == user && (self.device.is_empty() || self.device == device)
    }
}

/// What one participant may not publish, and to whom.
///
/// Two sets rather than one because they are enforced in different places and
/// mean different things to the person holding the phone. `everyone` stops the
/// track at its source and darkens the hardware indicator; `audience` only
/// narrows who the relay will forward it to, and the camera stays on because
/// the hosts are still watching through it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Silence {
    /// Stopped for everybody, including the hosts.
    pub everyone: Kinds,
    /// Stopped for the audience, while hosts and cohosts still receive it.
    pub audience: Kinds,
}

impl Silence {
    /// Whether anything at all is muted.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.everyone.is_empty() && self.audience.is_empty()
    }

    /// What a subscriber is not allowed to receive.
    ///
    /// `privileged` is whether the subscriber runs the room, which is the only
    /// thing that distinguishes the two scopes on the receiving side.
    #[must_use]
    pub const fn withheld_from(self, privileged: bool) -> Kinds {
        if privileged {
            self.everyone
        } else {
            self.everyone.union(self.audience)
        }
    }
}

/// The most one participant may hold, as a moderator last set it.
///
/// Kept per room, beside the mutes, rather than on the session it was aimed at,
/// and for the reason a mute is: a demotion has to outlive the connection it
/// was applied to. Somebody demoted who reconnects with the token they held
/// before must come back demoted, or reconnecting would be the way to undo it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {
    /// The account.
    pub user: String,
    /// Which device, or empty for every device — the `ParticipantRef`
    /// convention again.
    pub device: String,
    /// What they may hold, at most.
    pub ceiling: Ceiling,
}

impl Override {
    /// Whether this names that person, and that device if it names one.
    #[must_use]
    pub fn catches(&self, user: &str, device: &str) -> bool {
        self.user == user && (self.device.is_empty() || self.device == device)
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
    /// Force-mutes in force.
    pub mutes: Vec<Mute>,
    /// Grant ceilings in force. See [`Override`].
    pub grants: Vec<Override>,
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
    /// Billing has told this self-hosted relay that its tenant may not admit
    /// new sessions. See [`crate::usage::Usage::admitting`].
    #[error("this account is not admitting new sessions")]
    NotAdmitting,
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
            Self::NotAdmitting => "billing",
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

    /// Add or lift one force-mute without disturbing the rest of the room.
    ///
    /// Keyed by who it names, its scope, *and* the media it names. The scope
    /// matters because a participant can be under an everyone-mute and an
    /// audience-mute at once; the media matters for the same reason one step
    /// down, and it is the part this used to get wrong. Replacing everything
    /// held against a person made the second mute lift the first: mute their
    /// microphone, then mute their camera, and the microphone came back on.
    ///
    /// So an arriving directive takes its kinds away from whatever is already
    /// held and then states its own. The kinds it does not name are left where
    /// they are, with the expiry they were given — which is the other thing a
    /// single row could not hold, since a ten-minute mute of audio and an
    /// indefinite mute of video have nothing to merge into.
    pub fn mute(&self, room: Where, mute: Mute, active: bool) {
        let mut inner = self.lock();
        let rules = inner.rooms.entry(room).or_default();
        for held in &mut rules.mutes {
            if held.user == mute.user
                && held.device == mute.device
                && held.audience_only == mute.audience_only
            {
                held.media = held.media.without(mute.media);
            }
        }
        rules.mutes.retain(|held| !held.media.is_empty());
        if active && !mute.media.is_empty() {
            rules.mutes.push(mute);
        }
    }

    /// What one participant is currently forbidden to publish.
    ///
    /// Empty for a room this relay knows nothing about, which is the same
    /// permissive answer [`Self::admits`] gives and for the same reason: the
    /// control plane cannot have muted somebody in a room it does not yet know
    /// this relay is serving.
    #[must_use]
    pub fn silenced(&self, room: &Where, user: &str, device: &str) -> Silence {
        let now = SystemTime::now();
        let inner = self.lock();
        let Some(rules) = inner.rooms.get(room) else {
            return Silence::default();
        };
        let mut silence = Silence::default();
        for mute in &rules.mutes {
            if !mute.holds(now) || !mute.catches(user, device) {
                continue;
            }
            if mute.audience_only {
                silence.audience = silence.audience.union(mute.media);
            } else {
                silence.everyone = silence.everyone.union(mute.media);
            }
        }
        silence
    }

    /// Set the most one participant may hold, replacing what was set before.
    ///
    /// One aimed at a whole person replaces the per-device ones for them as
    /// well. Otherwise a cohost demoted on their phone and then promoted as a
    /// person would stay demoted on the phone, because [`Self::ceiling`] takes
    /// the lower of everything that names a device — which is the right answer
    /// when two rules genuinely disagree, and the wrong one when the later rule
    /// was meant to supersede the earlier.
    pub fn regrant(&self, room: Where, grant: Override) {
        let mut inner = self.lock();
        let rules = inner.rooms.entry(room).or_default();
        rules.grants.retain(|held| {
            held.user != grant.user || !(grant.device.is_empty() || held.device == grant.device)
        });
        rules.grants.push(grant);
    }

    /// The most one participant may hold, or `None` when no moderator has said.
    ///
    /// `None` is not "nothing": it is the ordinary case, a token that governs on
    /// its own. When more than one rule names the device — one for the person,
    /// one for this device — the lower of them holds, because a policy store
    /// that disagrees with itself should fail towards less.
    #[must_use]
    pub fn ceiling(&self, room: &Where, user: &str, device: &str) -> Option<Ceiling> {
        let inner = self.lock();
        inner
            .rooms
            .get(room)?
            .grants
            .iter()
            .filter(|grant| grant.catches(user, device))
            .map(|grant| grant.ceiling)
            .reduce(Ceiling::meet)
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
        // particular. Nor is the hosted recorder, which is not a participant:
        // a room someone asked to record is recorded however full it is, and
        // `occupancy` does not count it, so it never takes a person's place.
        if rules.ceiling > 0
            && occupancy >= rules.ceiling as usize
            && !scope.owner
            && !scope.is_recorder()
        {
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
            relay: false,
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
    fn a_full_room_still_admits_its_recorder_and_only_a_viewing_one() {
        let policy = Policy::new();
        policy.describe(
            room(),
            Rules {
                ceiling: 2,
                ..Rules::default()
            },
        );
        let mut recorder = scope(crate::scope::RECORDER_SUBJECT);
        recorder.publish = Publish::NONE;
        assert!(recorder.is_recorder());
        assert!(policy.admits(&recorder, address(4), 2).is_ok());
        assert!(policy.admits(&recorder, address(4), 50).is_ok());

        // The reserved name with anything beyond viewing is not the recorder
        // the control plane mints, and gets no seat beyond the ceiling.
        let publishing = scope(crate::scope::RECORDER_SUBJECT);
        assert!(!publishing.is_recorder());
        assert_eq!(
            policy.admits(&publishing, address(4), 2),
            Err(Refusal::Full)
        );

        // Nor does it get past anything else.
        policy.close(room(), true);
        assert_eq!(
            policy.admits(&recorder, address(4), 0),
            Err(Refusal::Closed)
        );
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
    fn a_mute_names_a_person_or_one_of_their_devices() {
        let policy = Policy::new();
        policy.mute(
            room(),
            Mute {
                user: "ada".into(),
                device: String::new(),
                media: Kinds::AUDIO,
                audience_only: false,
                until: None,
            },
            true,
        );

        assert_eq!(
            policy.silenced(&room(), "ada", "phone").everyone,
            Kinds::AUDIO
        );
        assert_eq!(
            policy.silenced(&room(), "ada", "laptop").everyone,
            Kinds::AUDIO
        );
        assert!(policy.silenced(&room(), "adam", "phone").is_empty());

        // A device mute reaches one device.
        let policy = Policy::new();
        policy.mute(
            room(),
            Mute {
                user: "ada".into(),
                device: "phone".into(),
                media: Kinds::VIDEO,
                audience_only: false,
                until: None,
            },
            true,
        );
        assert_eq!(
            policy.silenced(&room(), "ada", "phone").everyone,
            Kinds::VIDEO
        );
        assert!(policy.silenced(&room(), "ada", "laptop").is_empty());
    }

    #[test]
    fn the_two_scopes_are_held_apart_and_lifted_apart() {
        let policy = Policy::new();
        let everyone = Mute {
            user: "ada".into(),
            device: String::new(),
            media: Kinds::AUDIO,
            audience_only: false,
            until: None,
        };
        let audience = Mute {
            audience_only: true,
            media: Kinds::VIDEO,
            ..everyone.clone()
        };
        policy.mute(room(), everyone.clone(), true);
        policy.mute(room(), audience, true);

        let silence = policy.silenced(&room(), "ada", "phone");
        assert_eq!(silence.everyone, Kinds::AUDIO);
        assert_eq!(silence.audience, Kinds::VIDEO);

        // What a host receives, and what everybody else does.
        assert_eq!(silence.withheld_from(true), Kinds::AUDIO);
        assert_eq!(
            silence.withheld_from(false),
            Kinds::AUDIO.union(Kinds::VIDEO)
        );

        // Lifting the everyone-mute leaves the audience-mute standing, which is
        // the mistake the two keys exist to prevent.
        policy.mute(room(), everyone, false);
        let silence = policy.silenced(&room(), "ada", "phone");
        assert!(silence.everyone.is_empty());
        assert_eq!(silence.audience, Kinds::VIDEO);
    }

    #[test]
    fn a_second_mute_of_another_kind_does_not_lift_the_first() {
        let policy = Policy::new();
        let mute = Mute {
            user: "ada".into(),
            device: String::new(),
            media: Kinds::AUDIO,
            audience_only: false,
            until: None,
        };
        policy.mute(room(), mute.clone(), true);
        policy.mute(
            room(),
            Mute {
                media: Kinds::VIDEO,
                ..mute.clone()
            },
            true,
        );
        assert_eq!(
            policy.silenced(&room(), "ada", "phone").everyone,
            Kinds::AUDIO.union(Kinds::VIDEO)
        );

        // And each lifts on its own. Narrowing a mute is lifting the kinds no
        // longer meant, not restating the ones that are.
        policy.mute(
            room(),
            Mute {
                media: Kinds::VIDEO,
                ..mute
            },
            false,
        );
        assert_eq!(
            policy.silenced(&room(), "ada", "phone").everyone,
            Kinds::AUDIO
        );
    }

    #[test]
    fn restating_a_kind_replaces_its_expiry_rather_than_holding_two() {
        let policy = Policy::new();
        let mute = Mute {
            user: "ada".into(),
            device: String::new(),
            media: Kinds::AUDIO,
            audience_only: false,
            until: Some(SystemTime::now() + Duration::from_mins(10)),
        };
        policy.mute(room(), mute.clone(), true);

        // The same kind again, this time already lapsed. One entry per kind, so
        // the new expiry is the one that counts and the microphone is free.
        policy.mute(
            room(),
            Mute {
                until: Some(SystemTime::now() - Duration::from_secs(1)),
                ..mute
            },
            true,
        );
        assert!(policy.silenced(&room(), "ada", "phone").is_empty());
    }

    #[test]
    fn kinds_muted_for_different_lengths_expire_on_their_own_schedules() {
        let policy = Policy::new();
        let mute = Mute {
            user: "ada".into(),
            device: String::new(),
            media: Kinds::AUDIO,
            audience_only: false,
            until: Some(SystemTime::now() - Duration::from_secs(1)),
        };
        policy.mute(room(), mute.clone(), true);
        policy.mute(
            room(),
            Mute {
                media: Kinds::VIDEO,
                until: None,
                ..mute
            },
            true,
        );

        // The timed one has lapsed; the indefinite one has not. A single row
        // per participant could not have said this.
        assert_eq!(
            policy.silenced(&room(), "ada", "phone").everyone,
            Kinds::VIDEO
        );
    }

    #[test]
    fn an_expired_mute_is_no_mute() {
        let policy = Policy::new();
        policy.mute(
            room(),
            Mute {
                user: "ada".into(),
                device: String::new(),
                media: Kinds::AUDIO,
                audience_only: false,
                until: Some(SystemTime::now() - Duration::from_secs(1)),
            },
            true,
        );
        assert!(policy.silenced(&room(), "ada", "phone").is_empty());
    }

    #[test]
    fn a_snapshot_replaces_the_mutes_it_does_not_mention() {
        let policy = Policy::new();
        policy.mute(
            room(),
            Mute {
                user: "ada".into(),
                device: String::new(),
                media: Kinds::AUDIO,
                audience_only: false,
                until: None,
            },
            true,
        );
        policy.describe(room(), Rules::default());
        assert!(policy.silenced(&room(), "ada", "phone").is_empty());
    }

    fn ceiling(publish: Publish, capabilities: u32) -> Ceiling {
        Ceiling {
            publish,
            capabilities,
        }
    }

    #[test]
    fn a_grant_ceiling_names_a_person_or_one_of_their_devices() {
        let policy = Policy::new();
        assert_eq!(policy.ceiling(&room(), "ada", "phone"), None);

        policy.regrant(
            room(),
            Override {
                user: "ada".into(),
                device: "phone".into(),
                ceiling: ceiling(Publish::NONE, 0),
            },
        );
        assert_eq!(
            policy.ceiling(&room(), "ada", "phone"),
            Some(ceiling(Publish::NONE, 0))
        );
        assert_eq!(policy.ceiling(&room(), "ada", "laptop"), None);

        // A rule for the person, alongside the one for the phone: the phone is
        // held to the lower of the two until something supersedes them.
        policy.regrant(
            room(),
            Override {
                user: "ada".into(),
                device: "laptop".into(),
                ceiling: ceiling(Publish::AUDIO, 0x100),
            },
        );
        assert_eq!(
            policy.ceiling(&room(), "ada", "phone"),
            Some(ceiling(Publish::NONE, 0))
        );

        // Promoting the person replaces both device rules, so the phone is not
        // left behind on its old demotion.
        policy.regrant(
            room(),
            Override {
                user: "ada".into(),
                device: String::new(),
                ceiling: ceiling(Publish::AUDIO, 0x100),
            },
        );
        assert_eq!(
            policy.ceiling(&room(), "ada", "phone"),
            Some(ceiling(Publish::AUDIO, 0x100))
        );
        assert_eq!(policy.ceiling(&room(), "bea", "phone"), None);
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
