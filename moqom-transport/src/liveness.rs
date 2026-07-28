//! How long a silent peer has before the connection is declared dead.
//!
//! # Why there is no heartbeat above this layer
//!
//! The obvious way to notice that a participant's phone went into a tunnel is
//! to make them send a pulse on some track and watch for its absence. It is
//! also the worst way available here, and it is worth writing down why, because
//! it is the design every media stack that is not built on QUIC is forced into.
//!
//! An application heartbeat costs a stream or a datagram that has to be
//! encoded, forwarded, cached, and parsed; it can only report on the interval
//! somebody picked; and it discovers a dead peer no sooner than that interval.
//! QUIC is already doing the same job underneath every byte, with ACKs it was
//! going to send anyway, and its loss detection notices an unresponsive path in
//! a few round trips rather than a few seconds.
//!
//! The stronger argument is about publishers specifically. **The media is the
//! heartbeat.** A broadcaster at thirty frames a second is answering the
//! question thirty times a second, at a granularity no pulse would match. The
//! only connections that carry no such evidence are the ones sending nothing at
//! all — a viewer in a room where nobody has started yet — and those are
//! exactly what [`Liveness::keep_alive`] is for.
//!
//! # What this does not cover
//!
//! A connection being alive is not the same as a track being alive, and the gap
//! between them is a real failure mode rather than a technicality: a publisher
//! whose camera has frozen has a perfectly healthy QUIC connection, ACKs
//! flowing, nothing timing out, and a still image on everybody's screen. No
//! transport-level mechanism can see that, because from the transport's point
//! of view nothing is wrong.
//!
//! That signal is time since the last object on the track, which the relay
//! records on the forwarding path it is already running. It is both cheaper
//! than this and faster, and it is the one the interface should react to.
//! Treat what follows as the backstop that removes a participant, not as the
//! thing that greys out a tile.

use std::time::Duration;

/// Idle and keep-alive timings for a QUIC endpoint.
///
/// The two are a pair and are set together deliberately. Shortening the idle
/// timeout without a keep-alive would disconnect peers who are merely quiet;
/// a keep-alive without a shortened timeout would spend packets to no purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Liveness {
    /// Silence, in both directions, after which the connection is closed.
    ///
    /// Not a budget for a bad network. QUIC retransmits and recovers on its
    /// own, and this timer only runs when *nothing* is arriving — so reaching
    /// it means the peer is gone, not that it is struggling.
    ///
    /// The value that actually applies is the smaller of the two endpoints'
    /// (RFC 9000 §10.1), so a relay setting this shortens it for both sides
    /// whatever the client asked for. That is the intended arrangement: the
    /// operator running the room decides how long a ghost may sit in it.
    pub idle_timeout: Duration,

    /// How often to PING a connection that is otherwise silent.
    ///
    /// Only fires when nothing else is in flight, so a busy session pays
    /// nothing for this. On a quiet one it costs a packet, which buys the right
    /// to set an idle timeout short enough to be useful.
    ///
    /// One-sided on purpose. A PING is ack-eliciting, so the peer must answer
    /// it, and the answer is a packet *we* receive — which means a keep-alive
    /// sent from here resets the idle timer at both ends. The client does not
    /// need to send its own, and configuring one there would only duplicate
    /// traffic.
    pub keep_alive: Duration,
}

impl Liveness {
    /// Ten seconds of silence, pinged every two.
    ///
    /// Five chances to answer before giving up, so it takes sustained loss
    /// rather than a couple of dropped packets to evict anybody.
    ///
    /// Ten is chosen against what it is for. The tile on screen should have
    /// gone grey long before, on track staleness, and this is only the point at
    /// which the participant leaves the roster and their seat is released.
    /// Quinn's default is thirty, which is far too long to hold one of sixteen
    /// video boxes for somebody whose battery died.
    pub const DEFAULT: Self = Self {
        idle_timeout: Duration::from_secs(10),
        keep_alive: Duration::from_secs(2),
    };

    /// Build a pair, checking that the keep-alive is frequent enough to matter.
    ///
    /// # Errors
    /// [`LivenessError`] if the keep-alive is not comfortably inside the idle
    /// timeout, or if either is zero.
    pub const fn new(idle_timeout: Duration, keep_alive: Duration) -> Result<Self, LivenessError> {
        if idle_timeout.is_zero() {
            return Err(LivenessError::NoTimeout);
        }
        if keep_alive.is_zero() {
            return Err(LivenessError::NoKeepAlive);
        }
        // Two must fit, with room over. One would mean a single lost packet
        // ends the connection, which turns ordinary loss into a disconnection
        // and is a worse failure than the long timeout this replaces.
        if keep_alive.as_nanos() * 3 > idle_timeout.as_nanos() {
            return Err(LivenessError::TooSparse);
        }
        Ok(Self {
            idle_timeout,
            keep_alive,
        })
    }

    /// Apply to a transport configuration.
    ///
    /// # Errors
    /// [`LivenessError::Unrepresentable`] if the idle timeout exceeds what a
    /// QUIC transport parameter can carry, which is about 2^62 milliseconds and
    /// therefore only reachable by a caller that meant something else.
    pub fn apply(self, config: &mut quinn::TransportConfig) -> Result<(), LivenessError> {
        let idle = quinn::IdleTimeout::try_from(self.idle_timeout)
            .map_err(|_| LivenessError::Unrepresentable)?;
        config.max_idle_timeout(Some(idle));
        config.keep_alive_interval(Some(self.keep_alive));
        Ok(())
    }
}

impl Default for Liveness {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why a [`Liveness`] pair was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LivenessError {
    /// An idle timeout of zero disables the timeout entirely in QUIC, which is
    /// the opposite of what anybody passing zero means.
    #[error("an idle timeout of zero disables it; omit the setting instead")]
    NoTimeout,

    /// A keep-alive of zero would never fire.
    #[error("a keep-alive interval of zero never fires")]
    NoKeepAlive,

    /// Fewer than three keep-alives fit inside the timeout.
    #[error("the keep-alive interval must be under a third of the idle timeout")]
    TooSparse,

    /// The idle timeout does not fit in a QUIC transport parameter.
    #[error("the idle timeout is too large to encode")]
    Unrepresentable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_internally_consistent() {
        // The constant skips `new`, being a const, so nothing would otherwise
        // hold it to the rule every other value is held to.
        assert!(
            Liveness::new(Liveness::DEFAULT.idle_timeout, Liveness::DEFAULT.keep_alive).is_ok()
        );
    }

    #[test]
    fn a_keep_alive_that_barely_fits_is_refused() {
        // Six seconds inside ten leaves one chance to answer, so a single lost
        // packet would close the connection.
        assert_eq!(
            Liveness::new(Duration::from_secs(10), Duration::from_secs(6)),
            Err(LivenessError::TooSparse)
        );
    }

    #[test]
    fn zero_is_refused_in_both_positions() {
        assert_eq!(
            Liveness::new(Duration::ZERO, Duration::from_secs(1)),
            Err(LivenessError::NoTimeout)
        );
        assert_eq!(
            Liveness::new(Duration::from_secs(10), Duration::ZERO),
            Err(LivenessError::NoKeepAlive)
        );
    }

    #[test]
    fn applying_it_sets_both() {
        let mut config = quinn::TransportConfig::default();
        Liveness::DEFAULT.apply(&mut config).expect("representable");

        // `TransportConfig` exposes no getters, so the check is its `Debug`
        // rendering. Ugly, and still worth having: the failure it catches is
        // setting one of the pair and not the other, which produces either
        // disconnected-but-alive peers or a timeout nobody shortened.
        let rendered = format!("{config:?}");
        assert!(
            rendered.contains("max_idle_timeout: Some(10000)"),
            "idle timeout not applied: {rendered}"
        );
        assert!(
            rendered.contains("keep_alive_interval: Some(2s)"),
            "keep-alive not applied: {rendered}"
        );
    }
}
