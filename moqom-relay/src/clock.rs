//! What time it is here, and how much that is worth.
//!
//! The relay's half of a model that spans three languages: `MoqomCore.Timecode`
//! in Swift and `internal/timecode` in Go are the same type with the same
//! rules, and they are the same on purpose. A room's history is assembled from
//! events recorded on a phone, on this relay, and in the control plane, and
//! stitching those into one order is only honest if each of them says how well
//! it knew the time. Where the three disagree, the Swift type is the reference.
//!
//! # This process does not run NTP
//!
//! Clients do, because a phone's wall clock is a user setting and cannot be
//! believed. A server is the opposite case: it has one system clock,
//! disciplined by one daemon that does the job properly — filtering, drift
//! compensation, slewing rather than stepping — and a second in-process client
//! would be a worse implementation of the same thing, fighting the first, with
//! no authority to correct the clock it disagreed with.
//!
//! So the relay reads the disciplined clock and, more importantly, reads the
//! kernel's own error bound for it. That bound is the whole point. Publishing
//! `SystemTime::now()` and implying nanosecond precision produces an audit log
//! that is confidently wrong for the hours after an NTP outage, and nothing
//! downstream can tell. The dependency on Cloudflare is therefore in the host
//! configuration — `deploy/modules/relay/chrony.conf` — rather than in here.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How much a timecode should be believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Trust {
    /// The local system clock, because the reference could not be reached. No
    /// measurement stands behind the value.
    ///
    /// The default, deliberately. A field nobody filled in should read as "we
    /// do not know", never as "this is good time".
    ///
    /// Named for the clock that produced it rather than the property it lacks,
    /// because that is what a reader finding it in a log needs to know.
    #[default]
    Fallback,

    /// Measured against the reference clock, recently enough to still be tight.
    Synchronised,

    /// Produced by a reference clock itself.
    ///
    /// Nothing in the managed service claims this and that is correct: our
    /// hosts are disciplined by Cloudflare's NTP, which makes them
    /// synchronised clients of an authority rather than authorities. It exists
    /// for a self-hosted deployment with a real local reference.
    Authoritative,
}

impl Trust {
    /// The name used by the Swift and Go types, since these cross the wire.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Fallback => "fallback",
            Self::Synchronised => "synchronised",
            Self::Authoritative => "authoritative",
        }
    }
}

/// An instant, with the width of what is actually known about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timecode {
    /// The best estimate, in nanoseconds since the Unix epoch.
    pub unix_nanos: i64,

    /// Half the width of the interval the true instant lies in.
    pub uncertainty: Duration,

    /// How much the estimate should be believed.
    pub trust: Trust,
}

impl Timecode {
    /// An instant with an explicit error bound.
    #[must_use]
    pub fn new(unix_nanos: i64, uncertainty: Duration, trust: Trust) -> Self {
        Self {
            unix_nanos,
            uncertainty,
            trust,
        }
    }

    /// The earliest this could be.
    #[must_use]
    pub fn earliest(&self) -> i64 {
        self.unix_nanos.saturating_sub(nanos_of(self.uncertainty))
    }

    /// The latest this could be.
    #[must_use]
    pub fn latest(&self) -> i64 {
        self.unix_nanos.saturating_add(nanos_of(self.uncertainty))
    }

    /// Whether this can be placed against another machine's reading.
    #[must_use]
    pub fn is_trusted(&self) -> bool {
        self.trust != Trust::Fallback
    }

    /// Whether this provably happened before `other`.
    ///
    /// Deliberately strict: true only when the intervals do not overlap. Two
    /// events a millisecond apart on machines synced to fifty are not ordered,
    /// and this answers `false` in both directions, which is honest rather than
    /// missing.
    ///
    /// For two entries from the *same* source, use that source's sequence
    /// number. It is exact, and reaching for a timecode discards a certainty
    /// you already had.
    #[must_use]
    pub fn definitely_precedes(&self, other: &Self) -> bool {
        self.is_trusted() && other.is_trusted() && self.latest() < other.earliest()
    }

    /// Whether these two could be the same instant.
    #[must_use]
    pub fn may_coincide(&self, other: &Self) -> bool {
        if !self.is_trusted() || !other.is_trusted() {
            return true;
        }
        self.earliest() <= other.latest() && other.earliest() <= self.latest()
    }

    /// The same estimate, known less precisely.
    ///
    /// Uncertainty only ever grows this way. Nothing here makes a timecode more
    /// certain than it was measured.
    #[must_use]
    pub fn widened(self, extra: Duration) -> Self {
        Self {
            uncertainty: self.uncertainty.saturating_add(extra),
            ..self
        }
    }
}

/// What the kernel says about its own discipline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Health {
    /// Whether a time daemon is currently disciplining the clock.
    ///
    /// False after chrony dies, and false for the first minutes after boot —
    /// both of which are exactly when a naive server lies.
    pub synchronised: bool,

    /// The kernel's own bound on how wrong it might be.
    ///
    /// Grows on its own between corrections, which is what makes it useful: a
    /// host that lost its time source an hour ago reports a wide bound without
    /// anybody having to notice the daemon died.
    pub max_error: Duration,

    /// Whether a leap second lands at the end of the current UTC day.
    ///
    /// Cloudflare does not smear, so this arrives as a real discontinuity.
    pub leap_pending: bool,
}

/// Past this width, a reading stops claiming to be synchronised.
///
/// A healthy machine on a nearby NTP server reports single-digit milliseconds.
/// A hundred is far outside that and far inside the seconds-level errors that
/// make a log meaningless, so it separates "slightly noisy" from "something is
/// wrong" without flapping.
pub const CEILING: Duration = Duration::from_millis(100);

/// How long a health reading is reused.
const POLL: Duration = Duration::from_secs(1);

/// The host's disciplined system clock, with its error bound.
#[derive(Debug)]
pub struct Host {
    ceiling: Duration,
    cached: Mutex<Option<(Instant, Option<Health>)>>,

    /// The trust last announced, so a transition is said once rather than on
    /// every stamp.
    announced: Mutex<Option<Trust>>,

    /// How many timecodes this relay has stamped from local time.
    fallbacks: AtomicU64,
}

impl Default for Host {
    fn default() -> Self {
        Self::new()
    }
}

impl Host {
    /// A clock over this machine's system clock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ceiling: CEILING,
            cached: Mutex::new(None),
            announced: Mutex::new(None),
            fallbacks: AtomicU64::new(0),
        }
    }

    /// The current instant and how well it is known.
    #[must_use]
    pub fn now(&self) -> Timecode {
        let code = self.stamp();
        self.announce(code.trust);
        code
    }

    /// How many timecodes have been stamped from local time.
    ///
    /// Exposed as a metric rather than left to the log, because greppable is
    /// not alarmable: a relay stamping fallback time produces events that
    /// cannot be placed against any other machine's, and an operator wants to
    /// page on that rather than read about it afterwards.
    #[must_use]
    pub fn fallbacks(&self) -> u64 {
        self.fallbacks.load(Ordering::Relaxed)
    }

    /// Say, once, when this clock starts or stops being believable.
    ///
    /// Falling back is invisible to a caller: [`Host::now`] keeps returning a
    /// plausible instant, and everything that does not inspect the trust
    /// carries on unchanged. Without this, the first anyone knows of it is a
    /// relay log that will not line up against the control plane's.
    fn announce(&self, trust: Trust) {
        if trust == Trust::Fallback {
            self.fallbacks.fetch_add(1, Ordering::Relaxed);
        }

        let mut announced = self
            .announced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *announced == Some(trust) {
            return;
        }
        let previous = announced.replace(trust);

        if trust == Trust::Fallback {
            tracing::warn!(
                previously = previous.map_or("never established", Trust::label),
                consequence = "timecodes cannot be ordered against other hosts",
                "clock fell back to local time"
            );
        } else {
            tracing::info!(trust = trust.label(), "clock is disciplined");
        }
    }

    fn stamp(&self) -> Timecode {
        let unix_nanos = wall_clock_nanos();
        let Some(health) = self.health() else {
            return Timecode::new(unix_nanos, UNKNOWN, Trust::Fallback);
        };
        if !health.synchronised {
            return Timecode::new(unix_nanos, UNKNOWN, Trust::Fallback);
        }

        // A pending leap makes UTC itself ambiguous by a second, and no amount
        // of NTP quality changes that. Widening for the rest of the day is
        // heavy-handed, but it is the honest bound, it happens about once a
        // decade, and arithmetic exercised once in ten years at the exact
        // moment the timeline is discontinuous is not the thing to be clever
        // with.
        let mut width = health.max_error;
        if health.leap_pending {
            width = width.saturating_add(Duration::from_secs(1));
        }

        let trust = if width > self.ceiling {
            Trust::Fallback
        } else {
            Trust::Synchronised
        };
        Timecode::new(unix_nanos, width, trust)
    }

    /// The kernel's verdict, cached briefly.
    ///
    /// `None` when it cannot be read at all, which is the case off Linux.
    #[must_use]
    pub fn health(&self) -> Option<Health> {
        // A poisoned lock is not a reason to stop telling the time: the state
        // behind it is a cached reading, and a stale one is better than none.
        let mut cached = self
            .cached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((at, health)) = *cached
            && at.elapsed() < POLL
        {
            return health;
        }
        let health = read_health();
        *cached = Some((Instant::now(), health));
        health
    }
}

/// The width reported when nothing has vouched for the clock.
///
/// A deliberately enormous figure rather than a plausible one: an undisciplined
/// clock can be wrong by a great deal, and a bound implying otherwise is the
/// lie this type exists to prevent.
const UNKNOWN: Duration = Duration::from_hours(24);

fn wall_clock_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_nanos()).unwrap_or(i64::MAX)
        })
}

fn nanos_of(duration: Duration) -> i64 {
    i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
}

#[cfg(target_os = "linux")]
fn read_health() -> Option<Health> {
    // Zeroed, which means mode zero, which means read without adjusting.
    // Getting this wrong would have the relay *setting* the system clock, so
    // it is worth saying out loud: nothing here writes.
    let mut buffer: libc::timex = unsafe { std::mem::zeroed() };

    // SAFETY: `adjtimex` reads and writes only the `timex` it is given, and
    // the modes field is zero, so the call is a query.
    let state = unsafe { libc::adjtimex(&raw mut buffer) };
    if state < 0 {
        return None;
    }

    // Two independent ways the kernel says it is adrift, and both are worth
    // checking. STA_UNSYNC is set by the daemon when it gives up; TIME_ERROR is
    // the call's own verdict. A host whose chrony was killed shows the first
    // without the second for a while.
    let synchronised = state != libc::TIME_ERROR && buffer.status & libc::STA_UNSYNC == 0;

    // Microseconds regardless of STA_NANO, which only changes the units of the
    // offset and precision fields.
    let max_error = Duration::from_micros(buffer.maxerror.try_into().unwrap_or(0));

    Some(Health {
        synchronised,
        max_error,
        leap_pending: state == libc::TIME_INS
            || state == libc::TIME_DEL
            || buffer.status & (libc::STA_INS | libc::STA_DEL) != 0,
    })
}

/// Everywhere that is not a deployment target — in practice, a developer's Mac.
///
/// Reports that it cannot tell rather than guessing, so a relay run locally
/// visibly marks its records as unorderable against anything from elsewhere.
/// That is the correct answer, not a limitation to work around.
#[cfg(not(target_os = "linux"))]
fn read_health() -> Option<Health> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(nanos: i64, uncertainty: Duration, trust: Trust) -> Timecode {
        Timecode::new(nanos, uncertainty, trust)
    }

    #[test]
    fn overlapping_readings_are_not_ordered() {
        // 20ms apart with 50ms of slop each way: the second may well have
        // happened first, and saying otherwise invents the answer.
        let early = at(
            1_000_000_000,
            Duration::from_millis(50),
            Trust::Synchronised,
        );
        let late = at(
            1_020_000_000,
            Duration::from_millis(50),
            Trust::Synchronised,
        );

        assert!(!early.definitely_precedes(&late));
        assert!(!late.definitely_precedes(&early));
        assert!(early.may_coincide(&late));
    }

    #[test]
    fn disjoint_readings_are_ordered() {
        let early = at(1_000_000_000, Duration::from_millis(5), Trust::Synchronised);
        let late = at(1_020_000_000, Duration::from_millis(5), Trust::Synchronised);

        assert!(early.definitely_precedes(&late));
        assert!(!late.definitely_precedes(&early));
        assert!(!early.may_coincide(&late));
    }

    #[test]
    fn a_fallback_reading_never_orders() {
        // Far apart, so the intervals plainly do not overlap. It still must not
        // order them: one machine's unchecked opinion cannot be placed against
        // another's however different the numbers look.
        let adrift = at(1_000_000_000, Duration::from_millis(1), Trust::Fallback);
        let good = at(9_000_000_000, Duration::from_millis(1), Trust::Synchronised);

        assert!(!adrift.definitely_precedes(&good));
        assert!(!good.definitely_precedes(&adrift));
        assert!(adrift.may_coincide(&good));
    }

    #[test]
    fn the_default_trust_is_no_trust() {
        assert_eq!(Trust::default(), Trust::Fallback);
        assert!(!Health::default().synchronised);
    }

    #[test]
    fn widening_only_grows() {
        let code = at(0, Duration::from_millis(10), Trust::Synchronised);
        assert_eq!(
            code.widened(Duration::from_millis(5)).uncertainty,
            Duration::from_millis(15)
        );
    }

    #[test]
    fn labels_match_the_other_two_languages() {
        // These strings appear in the relay's admin JSON next to values the Go
        // and Swift sides produce. Renaming one here alone breaks the join.
        assert_eq!(Trust::Fallback.label(), "fallback");
        assert_eq!(Trust::Synchronised.label(), "synchronised");
        assert_eq!(Trust::Authoritative.label(), "authoritative");
    }

    #[test]
    fn a_host_that_cannot_read_its_clock_says_so() {
        // On a developer's Mac this exercises the real path; on Linux CI the
        // kernel answers and the assertion below still holds unless the runner
        // genuinely has good time, which is why it only checks the invariant
        // that matters.
        let host = Host::new();
        let now = host.now();

        assert!(now.unix_nanos > 0, "the instant is worth having regardless");
        if now.trust == Trust::Fallback {
            assert!(
                now.uncertainty >= CEILING,
                "an untrusted reading must not look tight"
            );
        } else {
            assert!(now.uncertainty <= CEILING);
        }
    }

    #[test]
    fn fallback_stamps_are_counted() {
        // Greppable is not alarmable. A relay writing records nobody can place
        // against another machine's needs a number an operator can page on.
        let host = Host::new();
        let before = host.fallbacks();

        for _ in 0..8 {
            let _ = host.now();
        }

        let produced = host.fallbacks() - before;
        // On a developer's Mac the kernel cannot be read and all eight fall
        // back; on a well-disciplined Linux runner none of them do. Either is
        // correct — what must hold is that the counter tracks the trust rather
        // than counting stamps.
        let expected = if host.now().trust == Trust::Fallback {
            8
        } else {
            0
        };
        assert_eq!(produced, expected);
    }

    #[test]
    fn the_transition_is_announced_once() {
        // A clock that says this on every stamp buries the transition under a
        // line per object relayed.
        let host = Host::new();
        let _ = host.now();
        let first = *host
            .announced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        for _ in 0..100 {
            let _ = host.now();
        }
        let after = *host
            .announced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        assert_eq!(first, after, "the announced state flapped without cause");
        assert!(first.is_some(), "nothing was announced at all");
    }

    #[test]
    fn health_is_cached_between_calls() {
        let host = Host::new();
        let first = host.health();
        let second = host.health();
        assert_eq!(first, second);
    }
}
