//! Draft-22 Message Parameters, per §9.20.
//!
//! Draft-22 stops typing Message Parameters by parity. Each type has its own
//! value encoding — `uint8`, varint, Location, length-prefixed, Track
//! Namespace, or a structure of its own — and nothing on the wire says which,
//! so a receiver can only parse a parameter it knows. That is why an unknown
//! one closes the session with `PROTOCOL_VIOLATION` (§9.20) rather than being
//! skipped, and why the block is bounded by a count instead of a length.
//!
//! The registry here is the whole of draft-22's, plus the two parameters of
//! MOQOM's own ([`param_type::AUTHORIZATION_PROOF`], [`param_type::RELAY_HOPS`]).
//! The decoder accepts those so that one parse serves every peer; a session
//! that has not seen [`MOQOM_PARAMETERS`](crate::control::setup::option_type::MOQOM_PARAMETERS)
//! in the peer's SETUP must neither send them nor accept them, because a
//! peer that does not know them is entitled to close the session on sight.
//!
//! [`Parameters`] stays the container: types are still delta-encoded in
//! ascending order, exactly as before, and only the value encoding differs.
//! [`Parameters::encode_counted`] and [`Parameters::decode_counted`] switch
//! to this module when the ambient [`Draft`](crate::Draft) has typed
//! parameters. SETUP options are not Message Parameters and keep the
//! parity rule in every draft.

use bytes::{Buf, BufMut, Bytes};

use crate::coding::{decode_bytes, encode_bytes, encoded_bytes_len};
use crate::control::params::{
    MAX_VALUE_LEN, ParamError, ParamValue, Parameter, Parameters, param_type,
};
use crate::error::DecodeError;
use crate::model::{GroupId, Location, ObjectId, TrackNamespace};
use crate::varint::{self, VarInt};

/// How a parameter's value is laid out on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// One byte, 0–255. Held as [`ParamValue::VarInt`].
    Uint8,
    /// One varint. Held as [`ParamValue::VarInt`].
    VarInt,
    /// Two varints, Group then Object, no length. [`ParamValue::Location`].
    Location,
    /// A varint length and that many bytes. [`ParamValue::Bytes`].
    LengthPrefixed,
    /// A length-prefixed Token structure (§8.9). Held as the Token Value
    /// alone, in [`ParamValue::Bytes`]; see [`Token`].
    Token,
    /// A Track Namespace. [`ParamValue::Namespace`].
    Namespace,
    /// A Location Filter Type and the fields it selects, no length.
    /// [`ParamValue::LocationFilter`].
    LocationFilter,
    /// A length-prefixed, count-prefixed parameter block in its own scope.
    /// [`ParamValue::Nested`].
    Fill,
}

/// The registry: the value encoding of every Message Parameter draft-22
/// defines, and of MOQOM's two. `None` is an unknown parameter.
#[must_use]
pub const fn encoding(type_value: u64) -> Option<Encoding> {
    use param_type as p;
    Some(match type_value {
        p::OBJECT_DELIVERY_TIMEOUT
        | p::RENDEZVOUS_TIMEOUT
        | p::SUBGROUP_DELIVERY_TIMEOUT
        | p::EXPIRES
        | p::FILL_TIMEOUT
        | p::NEW_GROUP_REQUEST
        | p::RELAY_HOPS => Encoding::VarInt,
        p::FORWARD | p::SUBSCRIBER_PRIORITY | p::GROUP_ORDER | p::INCLUDE_PROPERTIES => {
            Encoding::Uint8
        }
        p::AUTHORIZATION_TOKEN => Encoding::Token,
        p::LARGEST_OBJECT => Encoding::Location,
        p::LOCATION_FILTER => Encoding::LocationFilter,
        p::FILL_PARAMETERS => Encoding::Fill,
        p::SUBGROUP_FILTER
        | p::OBJECTID_FILTER
        | p::PRIORITY_FILTER
        | p::OBJECT_PROPERTY_FILTER
        | p::TRACK_PROPERTY_FILTER
        | p::AUTHORIZATION_PROOF => Encoding::LengthPrefixed,
        p::TRACK_NAMESPACE_PREFIX => Encoding::Namespace,
        _ => return None,
    })
}

/// Whether a parameter is MOQOM's own rather than the draft's.
#[must_use]
pub const fn is_private(type_value: u64) -> bool {
    matches!(
        type_value,
        param_type::AUTHORIZATION_PROOF | param_type::RELAY_HOPS
    )
}

/// Per-message parameter lists for [`Context::allowed`].
mod allow {
    use super::param_type as p;

    pub(super) const SUBSCRIBE: &[u64] = &[
        p::OBJECT_DELIVERY_TIMEOUT,
        p::AUTHORIZATION_TOKEN,
        p::RENDEZVOUS_TIMEOUT,
        p::SUBGROUP_DELIVERY_TIMEOUT,
        p::FORWARD,
        p::SUBSCRIBER_PRIORITY,
        p::LOCATION_FILTER,
        p::GROUP_ORDER,
        p::FILL_PARAMETERS,
        p::SUBGROUP_FILTER,
        p::OBJECTID_FILTER,
        p::PRIORITY_FILTER,
        p::OBJECT_PROPERTY_FILTER,
        p::NEW_GROUP_REQUEST,
        p::INCLUDE_PROPERTIES,
        p::RELAY_HOPS,
        p::AUTHORIZATION_PROOF,
    ];
    pub(super) const SUBSCRIBE_OK: &[u64] = &[p::EXPIRES, p::LARGEST_OBJECT];
    pub(super) const FETCH: &[u64] = &[
        p::AUTHORIZATION_TOKEN,
        p::FILL_TIMEOUT,
        p::SUBSCRIBER_PRIORITY,
        p::LOCATION_FILTER,
        p::GROUP_ORDER,
        p::SUBGROUP_FILTER,
        p::OBJECTID_FILTER,
        p::PRIORITY_FILTER,
        p::OBJECT_PROPERTY_FILTER,
        p::INCLUDE_PROPERTIES,
        p::RELAY_HOPS,
        p::AUTHORIZATION_PROOF,
    ];
    pub(super) const FETCH_OK: &[u64] = &[];
    pub(super) const PUBLISH: &[u64] = &[
        p::OBJECT_DELIVERY_TIMEOUT,
        p::AUTHORIZATION_TOKEN,
        p::SUBGROUP_DELIVERY_TIMEOUT,
        p::EXPIRES,
        p::LARGEST_OBJECT,
        p::FORWARD,
        p::SUBSCRIBER_PRIORITY,
        p::LOCATION_FILTER,
        p::GROUP_ORDER,
        p::AUTHORIZATION_PROOF,
    ];
    pub(super) const PUBLISH_STATE_NOTIFY: &[u64] =
        &[p::LARGEST_OBJECT, p::FORWARD, p::LOCATION_FILTER];
    pub(super) const UPDATE_SUBSCRIPTION: &[u64] = &[
        p::OBJECT_DELIVERY_TIMEOUT,
        p::AUTHORIZATION_TOKEN,
        p::SUBGROUP_DELIVERY_TIMEOUT,
        p::FORWARD,
        p::SUBSCRIBER_PRIORITY,
        p::LOCATION_FILTER,
        p::FILL_PARAMETERS,
        p::SUBGROUP_FILTER,
        p::OBJECTID_FILTER,
        p::PRIORITY_FILTER,
        p::OBJECT_PROPERTY_FILTER,
        p::NEW_GROUP_REQUEST,
        p::AUTHORIZATION_PROOF,
    ];
    pub(super) const UPDATE_FETCH: &[u64] = &[
        p::AUTHORIZATION_TOKEN,
        p::SUBSCRIBER_PRIORITY,
        p::AUTHORIZATION_PROOF,
    ];
    pub(super) const UPDATE_SUBSCRIBE_TRACKS: &[u64] = &[
        p::AUTHORIZATION_TOKEN,
        p::FORWARD,
        p::TRACK_PROPERTY_FILTER,
        p::TRACK_NAMESPACE_PREFIX,
        p::AUTHORIZATION_PROOF,
    ];
    pub(super) const UPDATE_SUBSCRIBE_NAMESPACE: &[u64] = &[
        p::AUTHORIZATION_TOKEN,
        p::TRACK_NAMESPACE_PREFIX,
        p::AUTHORIZATION_PROOF,
    ];
    pub(super) const UPDATE_PUBLISH_NAMESPACE: &[u64] =
        &[p::AUTHORIZATION_TOKEN, p::AUTHORIZATION_PROOF];
    pub(super) const REQUEST_UPDATE: &[u64] = &[
        p::OBJECT_DELIVERY_TIMEOUT,
        p::AUTHORIZATION_TOKEN,
        p::SUBGROUP_DELIVERY_TIMEOUT,
        p::FORWARD,
        p::SUBSCRIBER_PRIORITY,
        p::LOCATION_FILTER,
        p::FILL_PARAMETERS,
        p::SUBGROUP_FILTER,
        p::OBJECTID_FILTER,
        p::PRIORITY_FILTER,
        p::OBJECT_PROPERTY_FILTER,
        p::TRACK_PROPERTY_FILTER,
        p::NEW_GROUP_REQUEST,
        p::TRACK_NAMESPACE_PREFIX,
        p::AUTHORIZATION_PROOF,
    ];
    pub(super) const TRACK_STATUS: &[u64] = &[
        p::AUTHORIZATION_TOKEN,
        p::INCLUDE_PROPERTIES,
        p::RELAY_HOPS,
        p::AUTHORIZATION_PROOF,
    ];
    pub(super) const PUBLISH_NAMESPACE: &[u64] = &[p::AUTHORIZATION_TOKEN, p::AUTHORIZATION_PROOF];
    pub(super) const SUBSCRIBE_TRACKS: &[u64] = &[
        p::AUTHORIZATION_TOKEN,
        p::FORWARD,
        p::GROUP_ORDER,
        p::SUBGROUP_FILTER,
        p::OBJECTID_FILTER,
        p::PRIORITY_FILTER,
        p::OBJECT_PROPERTY_FILTER,
        p::TRACK_PROPERTY_FILTER,
        p::INCLUDE_PROPERTIES,
        p::AUTHORIZATION_PROOF,
    ];
    pub(super) const FILL: &[u64] = &[
        p::FILL_TIMEOUT,
        p::SUBSCRIBER_PRIORITY,
        p::LOCATION_FILTER,
        p::GROUP_ORDER,
        p::SUBGROUP_FILTER,
        p::OBJECTID_FILTER,
        p::PRIORITY_FILTER,
        p::OBJECT_PROPERTY_FILTER,
    ];
}

/// The message a parameter block belongs to, which decides what it may hold
/// (§9.20.1: anything else is a `PROTOCOL_VIOLATION`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    /// SUBSCRIBE.
    Subscribe,
    /// `SUBSCRIBE_OK`.
    SubscribeOk,
    /// FETCH.
    Fetch,
    /// `FETCH_OK`, which takes none.
    FetchOk,
    /// PUBLISH.
    Publish,
    /// `PUBLISH_STATE_NOTIFY`.
    PublishStateNotify,
    /// `REQUEST_UPDATE` of a subscription (SUBSCRIBE or PUBLISH).
    UpdateSubscription,
    /// `REQUEST_UPDATE` of a FETCH.
    UpdateFetch,
    /// `REQUEST_UPDATE` of a `SUBSCRIBE_TRACKS`.
    UpdateSubscribeTracks,
    /// `REQUEST_UPDATE` of a `SUBSCRIBE_NAMESPACE`.
    UpdateSubscribeNamespace,
    /// `REQUEST_UPDATE` of a `PUBLISH_NAMESPACE`.
    UpdatePublishNamespace,
    /// A `REQUEST_UPDATE` before its target is known: the union of the above.
    RequestUpdate,
    /// `REQUEST_OK` in any of its roles; the union of what each allows.
    RequestOk,
    /// `TRACK_STATUS`.
    TrackStatus,
    /// `PUBLISH_NAMESPACE`.
    PublishNamespace,
    /// `SUBSCRIBE_NAMESPACE`.
    SubscribeNamespace,
    /// `SUBSCRIBE_TRACKS`.
    SubscribeTracks,
    /// Inside `FILL_PARAMETERS` (§9.20.15).
    Fill,
}

impl Context {
    /// The parameter types the message allows, private ones included.
    #[must_use]
    pub const fn allowed(self) -> &'static [u64] {
        match self {
            Self::Subscribe => allow::SUBSCRIBE,
            Self::SubscribeOk | Self::RequestOk => allow::SUBSCRIBE_OK,
            Self::Fetch => allow::FETCH,
            Self::FetchOk => allow::FETCH_OK,
            Self::Publish => allow::PUBLISH,
            Self::PublishStateNotify => allow::PUBLISH_STATE_NOTIFY,
            Self::UpdateSubscription => allow::UPDATE_SUBSCRIPTION,
            Self::UpdateFetch => allow::UPDATE_FETCH,
            Self::UpdateSubscribeTracks => allow::UPDATE_SUBSCRIBE_TRACKS,
            Self::UpdateSubscribeNamespace => allow::UPDATE_SUBSCRIBE_NAMESPACE,
            Self::UpdatePublishNamespace => allow::UPDATE_PUBLISH_NAMESPACE,
            Self::RequestUpdate => allow::REQUEST_UPDATE,
            Self::TrackStatus => allow::TRACK_STATUS,
            Self::PublishNamespace | Self::SubscribeNamespace => allow::PUBLISH_NAMESPACE,
            Self::SubscribeTracks => allow::SUBSCRIBE_TRACKS,
            Self::Fill => allow::FILL,
        }
    }

    /// Check a decoded block against this message's list.
    ///
    /// # Errors
    /// [`DecodeError::Invalid`], which the session turns into
    /// `PROTOCOL_VIOLATION`, naming the first parameter out of place.
    pub fn check(self, params: &Parameters) -> Result<(), DecodeError> {
        let allowed = self.allowed();
        if params
            .as_slice()
            .iter()
            .any(|p| !allowed.contains(&p.type_value()))
        {
            return Err(DecodeError::Invalid(
                "message parameter is not allowed in this message",
            ));
        }
        Ok(())
    }
}

/// A Location Filter, per §9.20.9.
///
/// Group and object numbers are carried as they are on the wire; what they
/// resolve to depends on the Largest Object at the time, which the codec does
/// not know. [`Self::resolve_subscribe`] and [`Self::resolve_fetch`] apply the
/// two sets of rules — the same filter means different ranges on a
/// subscription and on a fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationFilter {
    /// `0x00`: no filter.
    None,
    /// `0x01`: start at `{Largest Object.Group + 1 - groups, 0}`, open-ended.
    /// `groups` of 0 is the Next Group, 1 the current group.
    RelativeStart {
        /// The `StartGroup` field.
        groups: u64,
    },
    /// `0x02`: start at an absolute Location, open-ended.
    AbsoluteStart(Location),
    /// `0x03`: from `start` to the last object of group
    /// `start.group + end_group_delta`.
    GroupEnd {
        /// First Location.
        start: Location,
        /// `EndGroupDelta`.
        end_group_delta: u64,
    },
    /// `0x04`: from `start` through `{start.group + end_group_delta,
    /// end_object}`, inclusive.
    Range {
        /// First Location.
        start: Location,
        /// `EndGroupDelta`.
        end_group_delta: u64,
        /// `EndObject`.
        end_object: u64,
    },
    /// `0x05`: start at the Next Object, open-ended.
    NextObject,
}

/// Where a resolved filter ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterEnd {
    /// Open-ended.
    Open,
    /// Through the last object of this group.
    Group(GroupId),
    /// Through this Location, inclusive.
    At(Location),
}

impl FilterEnd {
    /// Whether `location` is at or before the end.
    #[must_use]
    pub fn admits(self, location: Location) -> bool {
        match self {
            Self::Open => true,
            Self::Group(group) => location.group <= group,
            Self::At(end) => location <= end,
        }
    }
}

impl LocationFilter {
    const NONE: u64 = 0x00;
    const RELATIVE_START: u64 = 0x01;
    const ABSOLUTE_START: u64 = 0x02;
    const GROUP_END: u64 = 0x03;
    const RANGE: u64 = 0x04;
    const NEXT_OBJECT: u64 = 0x05;

    /// The Location Filter Type code.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::None => Self::NONE,
            Self::RelativeStart { .. } => Self::RELATIVE_START,
            Self::AbsoluteStart(_) => Self::ABSOLUTE_START,
            Self::GroupEnd { .. } => Self::GROUP_END,
            Self::Range { .. } => Self::RANGE,
            Self::NextObject => Self::NEXT_OBJECT,
        }
    }

    /// An absolute inclusive range from `start` through `end`, the form a
    /// FETCH uses. `None` if `end` precedes `start`.
    #[must_use]
    pub fn between(start: Location, end: Location) -> Option<Self> {
        let delta = end.group.get().checked_sub(start.group.get())?;
        if end < start {
            return None;
        }
        Some(Self::Range {
            start,
            end_group_delta: delta,
            end_object: end.object.get(),
        })
    }

    fn end_group(start: Location, delta: u64) -> Result<GroupId, DecodeError> {
        start
            .group
            .get()
            .checked_add(delta)
            .and_then(|g| VarInt::new(g).ok())
            .map(GroupId::new)
            .ok_or(DecodeError::Invalid(
                "StartGroup + EndGroupDelta exceeds the group range",
            ))
    }

    /// Resolve against `largest` as a subscription filter: `None` means
    /// unfiltered, and the end is open unless the filter names one.
    ///
    /// # Errors
    /// [`DecodeError::Invalid`] if the end group overflows, which §9.20.9
    /// makes a `PROTOCOL_VIOLATION`.
    pub fn resolve_subscribe(
        self,
        largest: Option<Location>,
    ) -> Result<Option<(Location, FilterEnd)>, DecodeError> {
        let next_object = largest.map_or(Location::default(), next_object_after);
        Ok(Some(match self {
            Self::None => return Ok(None),
            Self::NextObject => (next_object, FilterEnd::Open),
            Self::RelativeStart { groups } => (relative_start(largest, groups), FilterEnd::Open),
            Self::AbsoluteStart(start) => (start, FilterEnd::Open),
            Self::GroupEnd {
                start,
                end_group_delta,
            } => (
                start,
                FilterEnd::Group(Self::end_group(start, end_group_delta)?),
            ),
            Self::Range {
                start,
                end_group_delta,
                end_object,
            } => {
                (
                    start,
                    FilterEnd::At(Location::new(
                        Self::end_group(start, end_group_delta)?,
                        ObjectId::new(VarInt::new(end_object).map_err(|_| {
                            DecodeError::Invalid("EndObject exceeds the object range")
                        })?),
                    )),
                )
            }
        }))
    }

    /// Resolve against `largest` as a FETCH range (§3.2): inclusive, never
    /// beyond Largest Object, and an omitted end means Largest Object. `None`
    /// when nothing has been published or the range starts after it.
    ///
    /// # Errors
    /// As for [`Self::resolve_subscribe`].
    pub fn resolve_fetch(
        self,
        largest: Option<Location>,
    ) -> Result<Option<(Location, Location)>, DecodeError> {
        let Some(largest) = largest else {
            return Ok(None);
        };
        let (start, end) = match self.resolve_subscribe(Some(largest))? {
            None => (Location::default(), largest),
            Some((start, FilterEnd::Open)) => (start, largest),
            Some((start, FilterEnd::Group(group))) => (
                start,
                if group >= largest.group {
                    largest
                } else {
                    Location::new(group, ObjectId::new(VarInt::MAX))
                },
            ),
            Some((start, FilterEnd::At(end))) => (start, end.min(largest)),
        };
        Ok((start <= end && start <= largest).then_some((start, end)))
    }

    /// Encoded size.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let mut out = Vec::new();
        self.encode(&mut out);
        out.len()
    }

    /// Append the filter: its type and the fields the type selects.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        VarInt::from_u32(self.code() as u32).encode(buf);
        let raw = |value: u64, buf: &mut B| varint::encode_u64(value, buf);
        match *self {
            Self::None | Self::NextObject => {}
            Self::RelativeStart { groups } => raw(groups, buf),
            Self::AbsoluteStart(start) => start.encode(buf),
            Self::GroupEnd {
                start,
                end_group_delta,
            } => {
                start.encode(buf);
                raw(end_group_delta, buf);
            }
            Self::Range {
                start,
                end_group_delta,
                end_object,
            } => {
                start.encode(buf);
                raw(end_group_delta, buf);
                raw(end_object, buf);
            }
        }
    }

    /// Read a filter.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] for an
    /// undefined Location Filter Type.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        Ok(match VarInt::decode(buf)?.get() {
            Self::NONE => Self::None,
            Self::NEXT_OBJECT => Self::NextObject,
            Self::RELATIVE_START => Self::RelativeStart {
                groups: varint::decode_u64(buf)?,
            },
            Self::ABSOLUTE_START => Self::AbsoluteStart(Location::decode(buf)?),
            Self::GROUP_END => Self::GroupEnd {
                start: Location::decode(buf)?,
                end_group_delta: varint::decode_u64(buf)?,
            },
            Self::RANGE => Self::Range {
                start: Location::decode(buf)?,
                end_group_delta: varint::decode_u64(buf)?,
                end_object: varint::decode_u64(buf)?,
            },
            _ => return Err(DecodeError::Invalid("undefined Location Filter Type")),
        })
    }
}

fn next_object_after(largest: Location) -> Location {
    Location::new(
        largest.group,
        ObjectId::new(VarInt::new(largest.object.get() + 1).unwrap_or(VarInt::MAX)),
    )
}

/// `{Largest Object.Group + 1 - groups, 0}`, clamped at both ends as §9.20.9
/// requires.
fn relative_start(largest: Option<Location>, groups: u64) -> Location {
    let next_group = largest.map_or(0, |l| l.group.get() + 1);
    let group = next_group.saturating_sub(groups).min(varint::MAX);
    Location::new(
        GroupId::new(VarInt::new(group).unwrap_or(VarInt::MAX)),
        ObjectId::new(VarInt::ZERO),
    )
}

/// The Token structure that carries an authorization token, per §8.9.
///
/// MOQOM advertises no token cache (`MAX_AUTH_TOKEN_CACHE_SIZE` absent, so
/// 0), which makes every alias a peer could send one it was not entitled to
/// register. Only the two forms that carry a value are therefore accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// `REGISTER` (0x1): an alias, a type and a value.
    Register {
        /// Token Alias.
        alias: u64,
        /// Token Type.
        token_type: u64,
        /// Token Value.
        value: Bytes,
    },
    /// `USE_VALUE` (0x3): a type and a value.
    UseValue {
        /// Token Type. MOQOM sends 0, "negotiated out of band".
        token_type: u64,
        /// Token Value.
        value: Bytes,
    },
}

impl Token {
    const DELETE: u64 = 0x0;
    const REGISTER: u64 = 0x1;
    const USE_ALIAS: u64 = 0x2;
    const USE_VALUE: u64 = 0x3;

    /// The value a session authorizes with.
    #[must_use]
    pub const fn value(&self) -> &Bytes {
        match self {
            Self::Register { value, .. } | Self::UseValue { value, .. } => value,
        }
    }

    /// Encoded size, without a length prefix.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Register {
                alias,
                token_type,
                value,
            } => 1 + varint::size_u64(*alias) + varint::size_u64(*token_type) + value.len(),
            Self::UseValue { token_type, value } => 1 + varint::size_u64(*token_type) + value.len(),
        }
    }

    /// Append the structure, without a length prefix.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        match self {
            Self::Register {
                alias,
                token_type,
                value,
            } => {
                varint::encode_u64(Self::REGISTER, buf);
                varint::encode_u64(*alias, buf);
                varint::encode_u64(*token_type, buf);
                buf.put_slice(value);
            }
            Self::UseValue { token_type, value } => {
                varint::encode_u64(Self::USE_VALUE, buf);
                varint::encode_u64(*token_type, buf);
                buf.put_slice(value);
            }
        }
    }

    /// Parse a structure occupying all of `bytes`.
    ///
    /// # Errors
    /// [`DecodeError::Invalid`] if it is malformed, or uses an alias this
    /// endpoint cannot have registered.
    pub fn decode(mut bytes: &[u8]) -> Result<Self, DecodeError> {
        let buf = &mut bytes;
        let token = match varint::decode_u64(buf).map_err(DecodeError::in_complete_message)? {
            Self::REGISTER => {
                let alias = varint::decode_u64(buf).map_err(DecodeError::in_complete_message)?;
                let token_type =
                    varint::decode_u64(buf).map_err(DecodeError::in_complete_message)?;
                Self::Register {
                    alias,
                    token_type,
                    value: Bytes::copy_from_slice(buf),
                }
            }
            Self::USE_VALUE => Self::UseValue {
                token_type: varint::decode_u64(buf).map_err(DecodeError::in_complete_message)?,
                value: Bytes::copy_from_slice(buf),
            },
            Self::DELETE | Self::USE_ALIAS => {
                return Err(DecodeError::Invalid(
                    "token alias used, but this endpoint keeps no token cache",
                ));
            }
            _ => return Err(DecodeError::Invalid("undefined token Alias Type")),
        };
        Ok(token)
    }
}

fn uint8_in_range(type_value: u64, value: u8) -> bool {
    use param_type as p;
    match type_value {
        p::FORWARD | p::INCLUDE_PROPERTIES => value <= 1,
        p::GROUP_ORDER => value == 1 || value == 2,
        _ => true,
    }
}

impl Parameter {
    /// Build a parameter in its draft-22 shape, checked against the
    /// registry.
    ///
    /// Unlike [`Self::varint`] and [`Self::bytes`] this ignores parity, which
    /// draft-22 does not use for Message Parameters: `OBJECTID_FILTER` is
    /// even and carries bytes, `LARGEST_OBJECT` is odd and carries a Location.
    ///
    /// # Errors
    /// [`ParamError::Shape`] if the type is unknown or `value` is not the
    /// shape it takes, or a `uint8` is out of the type's range.
    pub fn typed(type_value: u64, value: ParamValue) -> Result<Self, ParamError> {
        let ok = match (encoding(type_value), &value) {
            (Some(Encoding::Uint8), ParamValue::VarInt(v)) => {
                u8::try_from(v.get()).is_ok_and(|b| uint8_in_range(type_value, b))
            }
            (Some(Encoding::VarInt), ParamValue::VarInt(_))
            | (Some(Encoding::Location), ParamValue::Location(_))
            | (Some(Encoding::Namespace), ParamValue::Namespace(_))
            | (Some(Encoding::LocationFilter), ParamValue::LocationFilter(_)) => true,
            (Some(Encoding::LengthPrefixed | Encoding::Token), ParamValue::Bytes(b)) => {
                b.len() <= MAX_VALUE_LEN
            }
            (Some(Encoding::Fill), ParamValue::Nested(inner)) => Context::Fill.check(inner).is_ok(),
            _ => false,
        };
        if !ok {
            return Err(ParamError::Shape { type_value });
        }
        Ok(Self::from_parts(type_value, value))
    }

    pub(crate) fn typed_value_len(&self) -> usize {
        match (encoding(self.type_value()), self.value()) {
            (Some(Encoding::Uint8), ParamValue::VarInt(_)) => 1,
            (Some(Encoding::Token), ParamValue::Bytes(b)) => {
                let len = use_value(b).encoded_len();
                VarInt::new(len as u64).map_or(9, VarInt::size) + len
            }
            (_, ParamValue::VarInt(v)) => v.size(),
            (_, ParamValue::Bytes(b)) => encoded_bytes_len(b.as_ref()),
            (_, ParamValue::Location(l)) => l.encoded_len(),
            (_, ParamValue::Namespace(ns)) => ns.encoded_len(),
            (_, ParamValue::LocationFilter(f)) => f.encoded_len(),
            (_, ParamValue::Nested(inner)) => {
                let len = inner.encoded_len_counted();
                VarInt::new(len as u64).map_or(9, VarInt::size) + len
            }
        }
    }

    pub(crate) fn encode_typed_value<B: BufMut>(&self, buf: &mut B) {
        match (encoding(self.type_value()), self.value()) {
            (Some(Encoding::Uint8), ParamValue::VarInt(v)) => {
                buf.put_u8(u8::try_from(v.get()).unwrap_or(u8::MAX));
            }
            (Some(Encoding::Token), ParamValue::Bytes(b)) => {
                let token = use_value(b);
                VarInt::new(token.encoded_len() as u64)
                    .unwrap_or(VarInt::MAX)
                    .encode(buf);
                token.encode(buf);
            }
            (_, ParamValue::VarInt(v)) => v.encode(buf),
            (_, ParamValue::Bytes(b)) => encode_bytes(buf, b.as_ref()),
            (_, ParamValue::Location(l)) => l.encode(buf),
            (_, ParamValue::Namespace(ns)) => ns.encode(buf),
            (_, ParamValue::LocationFilter(f)) => f.encode(buf),
            (_, ParamValue::Nested(inner)) => {
                VarInt::new(inner.encoded_len_counted() as u64)
                    .unwrap_or(VarInt::MAX)
                    .encode(buf);
                inner.encode_counted(buf);
            }
        }
    }

    pub(crate) fn decode_typed_value<B: Buf>(
        type_value: u64,
        buf: &mut B,
    ) -> Result<ParamValue, DecodeError> {
        let Some(shape) = encoding(type_value) else {
            return Err(DecodeError::Invalid("unknown message parameter"));
        };
        Ok(match shape {
            Encoding::Uint8 => {
                if !buf.has_remaining() {
                    return Err(DecodeError::Short { needed: 1 });
                }
                let value = buf.get_u8();
                if !uint8_in_range(type_value, value) {
                    return Err(DecodeError::Invalid(
                        "message parameter value is outside its range",
                    ));
                }
                ParamValue::VarInt(VarInt::from(value))
            }
            Encoding::VarInt => ParamValue::VarInt(VarInt::decode(buf)?),
            Encoding::Location => ParamValue::Location(Location::decode(buf)?),
            Encoding::LengthPrefixed => {
                ParamValue::Bytes(Bytes::from(decode_bytes(buf, MAX_VALUE_LEN)?))
            }
            Encoding::Token => {
                let raw = decode_bytes(buf, MAX_VALUE_LEN)?;
                ParamValue::Bytes(Token::decode(&raw)?.value().clone())
            }
            Encoding::Namespace => ParamValue::Namespace(TrackNamespace::decode(buf)?),
            Encoding::LocationFilter => ParamValue::LocationFilter(LocationFilter::decode(buf)?),
            Encoding::Fill => {
                let raw = decode_bytes(buf, MAX_VALUE_LEN)?;
                let mut inner = raw.as_slice();
                let params = Parameters::decode_counted(&mut inner)
                    .map_err(DecodeError::in_complete_message)?;
                if !inner.is_empty() {
                    return Err(DecodeError::Invalid(
                        "FILL_PARAMETERS has bytes after its parameters",
                    ));
                }
                Context::Fill.check(&params)?;
                ParamValue::Nested(params)
            }
        })
    }
}

fn use_value(value: &Bytes) -> Token {
    Token::UseValue {
        token_type: 0,
        value: value.clone(),
    }
}

/// [`Context::check`] when the ambient draft types its parameters, for the
/// message decoders to call unconditionally.
pub(crate) fn check_typed(context: Context, params: &Parameters) -> Result<(), DecodeError> {
    if crate::Draft::current().typed_parameters() {
        context.check(params)
    } else {
        Ok(())
    }
}

/// Whether a type may appear more than once in one block. Only the
/// authorization token is defined as repeatable.
pub(crate) const fn repeatable(type_value: u64) -> bool {
    type_value == param_type::AUTHORIZATION_TOKEN
}
