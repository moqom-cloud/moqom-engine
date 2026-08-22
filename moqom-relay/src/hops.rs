//! How far a subscription may travel through a fleet of relays.
//!
//! An edge that cannot serve a track asks its parent, and that parent may ask its
//! own. The arrangement is a tree while it is drawn on a whiteboard and a graph as
//! soon as it is configured by hand, and a graph with a cycle in it has no bottom:
//! two relays that each name the other as a parent will ask each other for a track
//! neither holds, forever.
//!
//! Neither relay can see the cycle from its own end. A subscription arriving from a
//! sibling relay is a subscription like any other — the same message on the same
//! kind of session — so there is nothing local to notice. What breaks it is a
//! number that only ever decreases, carried on the subscription itself: each relay
//! spends one before forwarding, and a cycle therefore ends in a refusal instead of
//! in exhaustion.
//!
//! The budget is deliberately small. The plan's own arithmetic puts ten million
//! viewers at a depth of three, because fan-out multiplies and depth only adds, so
//! a budget generous enough to be safe is also generous enough to be useless as a
//! bound. A misconfiguration should be a track that does not resolve, which is
//! visible and cheap; the failure this replaces was every relay in a cycle busy
//! forwarding the same request.

use moqom_proto::control::params::{Parameter, Parameters, param_type};
use moqom_proto::varint::VarInt;

/// How many relays a fresh subscription may be forwarded through.
///
/// Three, to match the depth the fan-out arithmetic asks for: one origin, one
/// interior tier, one edge. A deployment needing more should change the topology
/// rather than this number, because a deeper tree adds latency to every viewer to
/// spare the interior a fraction of its bandwidth.
pub const BUDGET: u64 = 3;

/// How many further relays may be asked for a track.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hops(u64);

impl Hops {
    /// The budget a subscription carries, or a fresh one if it names none.
    ///
    /// A subscription with no budget came from a client: clients do not forward
    /// anything, so there is nothing for them to have spent, and treating the
    /// absence as zero would stop an edge serving its own viewers at all.
    #[must_use]
    pub fn asked_for(parameters: &Parameters) -> Self {
        parameters
            .get(param_type::RELAY_HOPS)
            .and_then(Parameter::as_varint)
            .map_or(Self(BUDGET), |hops| Self(hops.get().min(BUDGET)))
    }

    /// Whether another relay may be asked.
    #[must_use]
    pub const fn may_forward(self) -> bool {
        self.0 > 0
    }

    /// The budget to put on the subscription this relay sends onwards.
    #[must_use]
    pub const fn spent(self) -> Self {
        Self(self.0.saturating_sub(1))
    }

    /// How many hops are left.
    #[must_use]
    pub const fn remaining(self) -> u64 {
        self.0
    }

    /// Record this budget on an outgoing subscription.
    ///
    /// Silently does nothing if the number will not fit a varint, which it cannot:
    /// the budget is clamped to [`BUDGET`] on the way in. Written as a fallible
    /// conversion handled rather than an unwrap so that raising `BUDGET` past the
    /// varint maximum is a subscription without a budget rather than a panic.
    pub fn note(self, parameters: &mut Parameters) {
        if let Ok(hops) = VarInt::try_from(self.0)
            && let Ok(parameter) = Parameter::varint(param_type::RELAY_HOPS, hops)
        {
            parameters.push(parameter);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_subscription_from_a_client_starts_a_full_budget() {
        let hops = Hops::asked_for(&Parameters::new());
        assert_eq!(hops.remaining(), BUDGET);
        assert!(hops.may_forward());
    }

    #[test]
    fn a_budget_survives_the_round_trip_through_parameters() {
        let mut parameters = Parameters::new();
        Hops::asked_for(&Parameters::new())
            .spent()
            .note(&mut parameters);
        assert_eq!(Hops::asked_for(&parameters).remaining(), BUDGET - 1);
    }

    /// The property the whole module is for: forwarding strictly decreases, so a
    /// cycle cannot continue indefinitely however it is wired.
    #[test]
    fn forwarding_always_runs_out() {
        let mut hops = Hops::asked_for(&Parameters::new());
        let mut forwards = 0;
        while hops.may_forward() {
            hops = hops.spent();
            forwards += 1;
            assert!(forwards <= BUDGET, "the budget must not be able to grow");
        }
        assert_eq!(forwards, BUDGET);
        assert!(!hops.may_forward());
    }

    /// A peer that asks for more hops than this relay allows gets this relay's
    /// answer. Otherwise the bound would be the caller's to choose, and a cycle
    /// between two cooperating misconfigured relays could restate a full budget on
    /// every pass and never terminate.
    #[test]
    fn a_budget_larger_than_this_relay_allows_is_clamped() {
        let mut parameters = Parameters::new();
        parameters.push(
            Parameter::varint(
                param_type::RELAY_HOPS,
                VarInt::try_from(BUDGET + 100).expect("a varint"),
            )
            .expect("a parameter"),
        );
        assert_eq!(Hops::asked_for(&parameters).remaining(), BUDGET);
    }

    #[test]
    fn an_exhausted_budget_refuses_to_forward() {
        let mut parameters = Parameters::new();
        Hops(0).note(&mut parameters);
        let hops = Hops::asked_for(&parameters);
        assert!(!hops.may_forward());
        assert_eq!(hops.spent().remaining(), 0, "spending must not wrap");
    }
}
