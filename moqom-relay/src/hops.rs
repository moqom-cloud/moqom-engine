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
//!
//! # Two carriers for one number
//!
//! The number travels as `HOP_LIMIT` from draft-elliottwave-moq-hop-limit on a
//! draft-22 session where both ends sent `HOP_LIMIT_SUPPORTED`, and as MOQOM's own
//! `RELAY_HOPS` everywhere it travelled before: draft-19, and draft-22 with
//! `MOQOM_PARAMETERS`. Both mean the same thing and are read the same way — absent
//! is the maximum, present is clamped to it — so a fleet part way through moving
//! from one to the other keeps its bound across the seam.

use moqom_proto::control::params::{Parameter, Parameters, param_type};
use moqom_proto::varint::VarInt;

/// How many relays a fresh subscription may be forwarded through: the draft's
/// `MAX_HOP_LIMIT`, at its recommended default.
///
/// Three, to match the depth the fan-out arithmetic asks for: one origin, one
/// interior tier, one edge. A deployment needing more should change the topology
/// rather than this number, because a deeper tree adds latency to every viewer to
/// spare the interior a fraction of its bandwidth. Configurable per relay with
/// [`Fabric::with_hop_limit`](crate::Fabric::with_hop_limit).
pub const BUDGET: u64 = 3;

/// Which parameter a session carries the budget in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carriage {
    /// `HOP_LIMIT`, negotiated by both ends sending `HOP_LIMIT_SUPPORTED`.
    HopLimit,
    /// MOQOM's `RELAY_HOPS`, which the session filters out for a draft-22 peer
    /// that did not send `MOQOM_PARAMETERS`.
    RelayHops,
}

/// How many further relays may be asked for a track.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hops(u64);

impl Hops {
    /// The budget a subscription carries, or a fresh one if it names none.
    ///
    /// Reads `RELAY_HOPS` only, with [`BUDGET`] as the maximum.
    #[must_use]
    pub fn asked_for(parameters: &Parameters) -> Self {
        Self::relayed(parameters, BUDGET)
    }

    /// The budget a draft-19 request carries in `RELAY_HOPS`, clamped to `max`.
    ///
    /// Draft-19 skips parameters it does not know, so `HOP_LIMIT` there is not a
    /// violation, just unread.
    #[must_use]
    pub fn relayed(parameters: &Parameters, max: u64) -> Self {
        let remaining = parameters
            .as_slice()
            .iter()
            .filter(|parameter| parameter.type_value() == param_type::RELAY_HOPS)
            .filter_map(Parameter::as_varint)
            .fold(max, |remaining, value| remaining.min(value.get()));
        Self(remaining)
    }

    /// The remaining hop limit of a request that arrived carrying `parameters`.
    ///
    /// A request with no budget came from a client: clients do not forward
    /// anything, so there is nothing for them to have spent, and treating the
    /// absence as zero would stop an edge serving its own viewers at all. A budget
    /// that is present is clamped to `max`, so a peer cannot raise this relay's
    /// bound and a cycle through relays with different maximums is bounded by the
    /// smallest. Where both carriers are present the smaller wins.
    ///
    /// # Errors
    /// A reason phrase for `PROTOCOL_VIOLATION`: `HOP_LIMIT` on a session that
    /// did not negotiate it (`negotiated` false), or more than once.
    pub fn received(
        parameters: &Parameters,
        negotiated: bool,
        max: u64,
    ) -> Result<Self, &'static str> {
        let mut remaining = max;
        let mut seen = false;
        for parameter in parameters.as_slice() {
            match parameter.type_value() {
                param_type::HOP_LIMIT => {
                    if !negotiated {
                        return Err("HOP_LIMIT on a session that did not negotiate it");
                    }
                    if seen {
                        return Err("more than one HOP_LIMIT");
                    }
                    seen = true;
                    let value = parameter.as_varint().ok_or("HOP_LIMIT is not a varint")?;
                    remaining = remaining.min(value.get());
                }
                param_type::RELAY_HOPS => {
                    if let Some(value) = parameter.as_varint() {
                        remaining = remaining.min(value.get());
                    }
                }
                _ => {}
            }
        }
        Ok(Self(remaining))
    }

    /// Whether another relay may be asked.
    #[must_use]
    pub const fn may_forward(self) -> bool {
        self.0 > 0
    }

    /// The budget to put on the request this relay sends onwards: one less.
    #[must_use]
    pub const fn spent(self) -> Self {
        Self(self.0.saturating_sub(1))
    }

    /// How many hops are left.
    #[must_use]
    pub const fn remaining(self) -> u64 {
        self.0
    }

    /// Record this budget on an outgoing request, in `carriage`.
    ///
    /// Silently does nothing if the number will not fit a varint, which it cannot:
    /// the budget is clamped on the way in. Written as a fallible conversion
    /// handled rather than an unwrap so that a maximum past the varint range is a
    /// request without a budget rather than a panic.
    pub fn note(self, parameters: &mut Parameters, carriage: Carriage) {
        let type_value = match carriage {
            Carriage::HopLimit => param_type::HOP_LIMIT,
            Carriage::RelayHops => param_type::RELAY_HOPS,
        };
        if let Ok(hops) = VarInt::try_from(self.0)
            && let Ok(parameter) = Parameter::varint(type_value, hops)
        {
            parameters.push(parameter);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn carrying(type_value: u64, value: u64) -> Parameters {
        let mut parameters = Parameters::new();
        parameters.push(
            Parameter::varint(type_value, VarInt::try_from(value).expect("a varint"))
                .expect("a parameter"),
        );
        parameters
    }

    #[test]
    fn a_subscription_from_a_client_starts_a_full_budget() {
        let hops = Hops::asked_for(&Parameters::new());
        assert_eq!(hops.remaining(), BUDGET);
        assert!(hops.may_forward());
        let hops = Hops::received(&Parameters::new(), true, 5).expect("valid");
        assert_eq!(hops.remaining(), 5, "absent is this relay's maximum");
    }

    #[test]
    fn a_budget_survives_the_round_trip_through_parameters() {
        for (carriage, negotiated) in [(Carriage::RelayHops, false), (Carriage::HopLimit, true)] {
            let mut parameters = Parameters::new();
            Hops::asked_for(&Parameters::new())
                .spent()
                .note(&mut parameters, carriage);
            assert_eq!(
                Hops::received(&parameters, negotiated, BUDGET)
                    .expect("valid")
                    .remaining(),
                BUDGET - 1,
                "{carriage:?}"
            );
        }
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
        let parameters = carrying(param_type::RELAY_HOPS, BUDGET + 100);
        assert_eq!(Hops::asked_for(&parameters).remaining(), BUDGET);
        let parameters = carrying(param_type::HOP_LIMIT, BUDGET + 100);
        assert_eq!(
            Hops::received(&parameters, true, BUDGET)
                .expect("valid")
                .remaining(),
            BUDGET
        );
    }

    #[test]
    fn an_exhausted_budget_refuses_to_forward() {
        let mut parameters = Parameters::new();
        Hops(0).note(&mut parameters, Carriage::RelayHops);
        let hops = Hops::asked_for(&parameters);
        assert!(!hops.may_forward());
        assert_eq!(hops.spent().remaining(), 0, "spending must not wrap");
    }

    /// The draft's negotiation rule: a receiver of `HOP_LIMIT` on a session that
    /// did not negotiate it closes the session, as for any undefined parameter.
    #[test]
    fn hop_limit_without_negotiation_is_a_protocol_violation() {
        let parameters = carrying(param_type::HOP_LIMIT, 1);
        assert!(Hops::received(&parameters, false, BUDGET).is_err());
    }

    #[test]
    fn two_hop_limits_are_a_protocol_violation() {
        let mut parameters = carrying(param_type::HOP_LIMIT, 1);
        parameters.push(Parameter::varint(param_type::HOP_LIMIT, VarInt::from_u32(2)).unwrap());
        assert!(Hops::received(&parameters, true, BUDGET).is_err());
    }

    /// A draft-22 peer that negotiated both carriers and sent both is held to the
    /// smaller, so neither can be used to restate a budget the other spent.
    #[test]
    fn the_smaller_of_two_carriers_wins() {
        let mut parameters = carrying(param_type::RELAY_HOPS, 2);
        parameters.push(Parameter::varint(param_type::HOP_LIMIT, VarInt::from_u32(1)).unwrap());
        assert_eq!(
            Hops::received(&parameters, true, BUDGET)
                .expect("valid")
                .remaining(),
            1
        );
    }
}
