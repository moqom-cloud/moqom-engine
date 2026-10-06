//! Where sessions are, as coarsely as a world map needs.
//!
//! Feeds the console's live connections map. The relay is the only component
//! that sees a client's address, so it is where the address is turned into
//! something that is not one: a country, a subdivision, a city, and a point
//! rounded to whole degrees. Nothing downstream of [`Locator::locate`] holds an
//! address.
//!
//! # What is kept
//!
//! A [`Place`] per live session, keyed by this relay's session number, for as
//! long as the session lives — so a session is looked up once rather than every
//! few seconds. No address, no identity, no history: the cache is pruned to the
//! current roster on every census and nothing here is written anywhere.
//!
//! # What leaves the relay
//!
//! A [`Census`]: per tenant, how many sessions are in each place, and how many
//! are publishing. Counts are exact at this point. The threshold that keeps a
//! small bucket from describing a person ([`Disclosure`]) is applied by whoever
//! shows the numbers to a tenant, after every relay's census has been merged —
//! applying it here would hide a city whose sessions are split across relays.
//! The relay's own admin endpoint applies it too, because an operator does not
//! need individual locations either.
//!
//! # Why the database reader is here rather than a dependency
//!
//! The format (`MaxMind` DB) is a binary search tree over address bits followed by
//! a small self-describing data section, and a lookup needs four fields out of
//! one record. That is a few hundred lines with every read bounds-checked, which
//! is cheaper to audit than a crate and its tree, in a workspace that vendors
//! its QUIC stack to keep that surface small. A malformed database yields no
//! place rather than a panic: see `a_truncated_database_never_panics`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use crate::fabric::{Fabric, SessionId};

/// The environment variable naming a GeoLite2-City compatible database.
pub const DATABASE_ENV: &str = "MOQOM_GEOIP_DB";

/// Where a session is, no more precisely than a city.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Place {
    /// ISO 3166-1 alpha-2.
    pub country: Arc<str>,
    /// ISO 3166-2 subdivision code without the country prefix, or empty.
    pub region: Arc<str>,
    /// English city name, or empty where the database knows only the country.
    pub city: Arc<str>,
    /// Whole degrees.
    pub latitude: i16,
    /// Whole degrees.
    pub longitude: i16,
}

/// Why a database could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum GeoError {
    /// The file could not be read.
    #[error("reading the database: {0}")]
    Io(#[from] std::io::Error),
    /// The bytes are not a database this reader understands.
    #[error("not a usable MaxMind DB: {0}")]
    Format(&'static str),
}

/// An opened GeoLite2-City compatible database.
pub struct Locator {
    bytes: Vec<u8>,
    node_count: u32,
    record_size: u16,
    ip_version: u16,
    data_start: usize,
    ipv4_start: u32,
}

impl std::fmt::Debug for Locator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Locator")
            .field("bytes", &self.bytes.len())
            .field("node_count", &self.node_count)
            .field("record_size", &self.record_size)
            .field("ip_version", &self.ip_version)
            .finish_non_exhaustive()
    }
}

const METADATA_MARKER: &[u8] = b"\xAB\xCD\xEFMaxMind.com";
/// The metadata is at most this far from the end of the file.
const METADATA_WINDOW: usize = 128 * 1024;
/// Deepest nesting a lookup will follow. City records nest three deep.
const MAX_DEPTH: u8 = 16;
/// Longest name kept from the database. Real names are far shorter.
const MAX_NAME: usize = 64;

impl Locator {
    /// Open the database at `path`.
    ///
    /// # Errors
    /// [`GeoError`] if the file cannot be read or is not a `MaxMind` DB.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GeoError> {
        Self::from_bytes(std::fs::read(path)?)
    }

    /// The database named by [`DATABASE_ENV`], opened once per process.
    ///
    /// `None` when the variable is unset or the file is unusable; the second is
    /// logged once. A relay without a database still counts sessions and
    /// reports them all as unlocated.
    #[must_use]
    pub fn shared() -> Option<&'static Self> {
        static SHARED: OnceLock<Option<Locator>> = OnceLock::new();
        SHARED
            .get_or_init(|| {
                let path = std::env::var_os(DATABASE_ENV)?;
                match Self::open(&path) {
                    Ok(locator) => {
                        tracing::info!(path = ?path, ?locator, "geolocation database loaded");
                        Some(locator)
                    }
                    Err(e) => {
                        tracing::warn!(path = ?path, error = %e, "geolocation database unusable; sessions will be unlocated");
                        None
                    }
                }
            })
            .as_ref()
    }

    /// Parse a database held in memory.
    ///
    /// # Errors
    /// [`GeoError::Format`] if the metadata is missing or describes a tree the
    /// file is too short to hold.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, GeoError> {
        let window = bytes.len().saturating_sub(METADATA_WINDOW);
        let marker = bytes[window..]
            .windows(METADATA_MARKER.len())
            .rposition(|w| w == METADATA_MARKER)
            .ok_or(GeoError::Format("no metadata marker"))?;
        let metadata_start = window + marker + METADATA_MARKER.len();
        let metadata = Section {
            bytes: &bytes,
            base: metadata_start,
        };

        let field = |name: &str| {
            metadata
                .find(metadata_start, &[name], 0)
                .and_then(|at| metadata.unsigned(at))
        };
        let node_count = field("node_count").ok_or(GeoError::Format("no node_count"))?;
        let record_size = field("record_size").ok_or(GeoError::Format("no record_size"))?;
        let ip_version = field("ip_version").ok_or(GeoError::Format("no ip_version"))?;

        let node_count =
            u32::try_from(node_count).map_err(|_| GeoError::Format("node_count too large"))?;
        let record_size = match record_size {
            24 => 24,
            28 => 28,
            32 => 32,
            _ => return Err(GeoError::Format("unsupported record_size")),
        };
        let ip_version = match ip_version {
            4 => 4,
            6 => 6,
            _ => return Err(GeoError::Format("unsupported ip_version")),
        };

        let tree_size = (node_count as usize)
            .checked_mul(usize::from(record_size) / 4)
            .ok_or(GeoError::Format("tree size overflows"))?;
        let data_start = tree_size + 16;
        if data_start > metadata_start {
            return Err(GeoError::Format("tree is larger than the file"));
        }

        let mut locator = Self {
            bytes,
            node_count,
            record_size,
            ip_version,
            data_start,
            ipv4_start: 0,
        };
        if ip_version == 6 {
            // IPv4 lives at ::/96 in an IPv6 tree. Walking there once saves
            // ninety-six steps on every IPv4 lookup.
            let mut node = 0;
            for _ in 0..96 {
                if node >= node_count {
                    break;
                }
                node = locator
                    .record(node, false)
                    .ok_or(GeoError::Format("tree is truncated"))?;
            }
            locator.ipv4_start = node;
        }
        Ok(locator)
    }

    /// Where `address` is, coarsely, or `None` if the database does not say.
    ///
    /// Private, loopback, and documentation ranges are absent from real
    /// databases and come back `None`.
    #[must_use]
    pub fn locate(&self, address: IpAddr) -> Option<Place> {
        let record = self.search(address.to_canonical())?;
        let data = Section {
            bytes: &self.bytes,
            base: self.data_start,
        };
        let text = |path: &[&str]| -> Arc<str> {
            data.find(record, path, 0)
                .and_then(|at| data.string(at))
                .map(|s| s.chars().take(MAX_NAME).collect::<String>())
                .unwrap_or_default()
                .into()
        };

        let country = text(&["country", "iso_code"]);
        if country.is_empty() {
            return None;
        }
        let latitude = data
            .find(record, &["location", "latitude"], 0)
            .and_then(|at| data.double(at))?;
        let longitude = data
            .find(record, &["location", "longitude"], 0)
            .and_then(|at| data.double(at))?;

        Some(Place {
            country,
            region: text(&["subdivisions", "0", "iso_code"]),
            city: text(&["city", "names", "en"]),
            latitude: whole_degrees(latitude, 90.0)?,
            longitude: whole_degrees(longitude, 180.0)?,
        })
    }

    /// The data-section offset of the record covering `address`.
    fn search(&self, address: IpAddr) -> Option<usize> {
        let (start, bits): (u32, u128) = match address {
            IpAddr::V4(v4) => (self.ipv4_start, u128::from(u32::from(v4)) << 96),
            IpAddr::V6(v6) if self.ip_version == 6 => (0, u128::from(v6)),
            IpAddr::V6(_) => return None,
        };
        let depth = if address.is_ipv4() { 32 } else { 128 };

        let mut node = start;
        for i in 0..depth {
            if node >= self.node_count {
                break;
            }
            let bit = bits & (1u128 << (127 - i)) != 0;
            node = self.record(node, bit)?;
        }
        if node <= self.node_count {
            // Equal is "no data"; less is a tree that ran out before the
            // address did, which a valid database cannot produce.
            return None;
        }
        let offset = ((node - self.node_count) as usize).checked_sub(16)?;
        self.data_start.checked_add(offset)
    }

    /// One side of one node of the search tree.
    fn record(&self, node: u32, right: bool) -> Option<u32> {
        let node = node as usize;
        let be = |at: usize, n: usize| -> Option<u32> {
            let slice = self.bytes.get(at..at.checked_add(n)?)?;
            Some(slice.iter().fold(0, |acc, b| (acc << 8) | u32::from(*b)))
        };
        match self.record_size {
            24 => be(node.checked_mul(6)? + if right { 3 } else { 0 }, 3),
            28 => {
                let base = node.checked_mul(7)?;
                let middle = u32::from(*self.bytes.get(base + 3)?);
                if right {
                    Some(((middle & 0x0F) << 24) | be(base + 4, 3)?)
                } else {
                    Some(((middle & 0xF0) << 20) | be(base, 3)?)
                }
            }
            _ => be(node.checked_mul(8)? + if right { 4 } else { 0 }, 4),
        }
    }
}

/// Round a coordinate to whole degrees, refusing anything that is not one.
fn whole_degrees(value: f64, limit: f64) -> Option<i16> {
    if !value.is_finite() || value.abs() > limit {
        return None;
    }
    #[allow(clippy::cast_possible_truncation)] // bounded by `limit` above
    Some(value.round() as i16)
}

/// A region of the file that the data-section decoder reads, with the base
/// that pointers inside it are relative to.
struct Section<'a> {
    bytes: &'a [u8],
    base: usize,
}

const POINTER: u8 = 1;
const STRING: u8 = 2;
const DOUBLE: u8 = 3;
const UINT16: u8 = 5;
const UINT32: u8 = 6;
const MAP: u8 = 7;
const UINT64: u8 = 9;
const ARRAY: u8 = 11;
const BOOLEAN: u8 = 14;
const FLOAT: u8 = 15;

impl Section<'_> {
    fn byte(&self, at: usize) -> Option<u8> {
        self.bytes.get(at).copied()
    }

    fn be(&self, at: usize, n: usize) -> Option<u64> {
        let slice = self.bytes.get(at..at.checked_add(n)?)?;
        Some(slice.iter().fold(0, |acc, b| (acc << 8) | u64::from(*b)))
    }

    /// The value at `at`: its type, its size, and where its payload starts.
    ///
    /// For a pointer the size is the five raw bits that encode it.
    fn header(&self, at: usize) -> Option<(u8, usize, usize)> {
        let control = self.byte(at)?;
        let mut kind = control >> 5;
        let mut next = at + 1;
        if kind == POINTER {
            return Some((POINTER, usize::from(control & 0x1F), next));
        }
        if kind == 0 {
            kind = 7u8.checked_add(self.byte(next)?)?;
            next += 1;
        }
        let size = match usize::from(control & 0x1F) {
            short @ 0..=28 => short,
            29 => {
                next += 1;
                29 + usize::from(self.byte(next - 1)?)
            }
            30 => {
                next += 2;
                285 + usize::try_from(self.be(next - 2, 2)?).ok()?
            }
            _ => {
                next += 3;
                65_821 + usize::try_from(self.be(next - 3, 3)?).ok()?
            }
        };
        Some((kind, size, next))
    }

    /// Where a pointer whose control bits are `bits` points, and where it ends.
    fn pointer(&self, bits: usize, at: usize) -> Option<(usize, usize)> {
        let high = (bits & 0x07) as u64;
        let (value, next) = match (bits >> 3) & 0x03 {
            0 => ((high << 8) | self.be(at, 1)?, at + 1),
            1 => (((high << 16) | self.be(at, 2)?) + 2_048, at + 2),
            2 => (((high << 24) | self.be(at, 3)?) + 526_336, at + 3),
            _ => (self.be(at, 4)?, at + 4),
        };
        Some((self.base.checked_add(usize::try_from(value).ok()?)?, next))
    }

    /// Follow `at` if it is a pointer. Once: a pointer to a pointer is invalid,
    /// and whatever reads the result will refuse it.
    fn resolve(&self, at: usize) -> Option<usize> {
        let (kind, size, next) = self.header(at)?;
        if kind == POINTER {
            Some(self.pointer(size, next)?.0)
        } else {
            Some(at)
        }
    }

    /// The offset just past the value at `at`, without decoding it.
    fn skip(&self, at: usize, depth: u8) -> Option<usize> {
        if depth > MAX_DEPTH {
            return None;
        }
        let (kind, size, next) = self.header(at)?;
        let end = match kind {
            POINTER => self.pointer(size, next)?.1,
            MAP => {
                let mut cursor = next;
                for _ in 0..size {
                    cursor = self.skip(cursor, depth + 1)?;
                    cursor = self.skip(cursor, depth + 1)?;
                }
                cursor
            }
            ARRAY => {
                let mut cursor = next;
                for _ in 0..size {
                    cursor = self.skip(cursor, depth + 1)?;
                }
                cursor
            }
            // The size is the value.
            BOOLEAN => next,
            _ => next.checked_add(size)?,
        };
        (end <= self.bytes.len()).then_some(end)
    }

    /// The offset of the value at `path` below the value at `at`.
    ///
    /// Map keys are matched by name and array elements by decimal index.
    fn find(&self, at: usize, path: &[&str], depth: u8) -> Option<usize> {
        if depth > MAX_DEPTH {
            return None;
        }
        let at = self.resolve(at)?;
        let Some((first, rest)) = path.split_first() else {
            return Some(at);
        };
        let (kind, size, next) = self.header(at)?;
        match kind {
            MAP => {
                let mut cursor = next;
                for _ in 0..size {
                    let key = self.string(cursor);
                    let value = self.skip(cursor, depth + 1)?;
                    if key == Some(*first) {
                        return self.find(value, rest, depth + 1);
                    }
                    cursor = self.skip(value, depth + 1)?;
                }
                None
            }
            ARRAY => {
                let index: usize = first.parse().ok()?;
                if index >= size {
                    return None;
                }
                let mut cursor = next;
                for _ in 0..index {
                    cursor = self.skip(cursor, depth + 1)?;
                }
                self.find(cursor, rest, depth + 1)
            }
            _ => None,
        }
    }

    fn string(&self, at: usize) -> Option<&str> {
        let (kind, size, next) = self.header(self.resolve(at)?)?;
        if kind != STRING {
            return None;
        }
        std::str::from_utf8(self.bytes.get(next..next.checked_add(size)?)?).ok()
    }

    fn double(&self, at: usize) -> Option<f64> {
        let (kind, size, next) = self.header(self.resolve(at)?)?;
        match (kind, size) {
            (DOUBLE, 8) => Some(f64::from_bits(self.be(next, 8)?)),
            (FLOAT, 4) => Some(f64::from(f32::from_bits(
                u32::try_from(self.be(next, 4)?).ok()?,
            ))),
            _ => None,
        }
    }

    fn unsigned(&self, at: usize) -> Option<u64> {
        let (kind, size, next) = self.header(self.resolve(at)?)?;
        match kind {
            UINT16 | UINT32 | UINT64 if size <= 8 => self.be(next, size),
            _ => None,
        }
    }
}

/// One tenant's sessions on this relay, by place.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tally {
    /// Sessions that own at least one announced namespace.
    pub publishers: u32,
    /// Every other session.
    pub viewers: u32,
    /// Exact counts per place.
    pub places: BTreeMap<Place, u32>,
    /// Sessions with no place.
    pub unlocated: u32,
}

impl Tally {
    /// Every session counted.
    #[must_use]
    pub const fn sessions(&self) -> u32 {
        self.publishers + self.viewers
    }
}

/// Every tenant's [`Tally`] on this relay.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Census {
    /// Keyed by tenant, ordered so two censuses compare equal when nothing moved.
    pub tenants: BTreeMap<Arc<str>, Tally>,
}

/// One session as the census sees it.
///
/// The address is here only long enough to be placed; [`Surveyor::count`]
/// does not keep it.
#[derive(Debug, Clone)]
pub struct Sighting {
    /// This relay's handle on the session, which is what the place is cached by.
    pub id: SessionId,
    /// The customer.
    pub tenant: Arc<str>,
    /// Where the session connected from.
    pub address: IpAddr,
    /// Whether the session is publishing anything.
    pub publishing: bool,
}

/// Counts sessions by place, looking each one up once.
#[derive(Debug, Default)]
pub struct Surveyor {
    places: HashMap<SessionId, Option<Place>>,
}

impl Surveyor {
    /// A surveyor that has looked nobody up yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Count `sightings`, and forget the places of sessions no longer among them.
    pub fn count(
        &mut self,
        locator: Option<&Locator>,
        sightings: impl IntoIterator<Item = Sighting>,
    ) -> Census {
        let mut census = Census::default();
        let mut present = HashSet::new();
        for sighting in sightings {
            present.insert(sighting.id);
            let place = self
                .places
                .entry(sighting.id)
                .or_insert_with(|| locator.and_then(|l| l.locate(sighting.address)));
            let tally = census.tenants.entry(sighting.tenant).or_default();
            if sighting.publishing {
                tally.publishers += 1;
            } else {
                tally.viewers += 1;
            }
            match place {
                Some(place) => *tally.places.entry(place.clone()).or_default() += 1,
                None => tally.unlocated += 1,
            }
        }
        self.places.retain(|id, _| present.contains(id));
        census
    }

    /// Count everybody on `fabric`'s roster.
    ///
    /// The roster holds only sessions with a verified tenant and room, which is
    /// also the set the control plane is told about.
    pub fn survey(&mut self, fabric: &Fabric, locator: Option<&Locator>) -> Census {
        let publishing: HashSet<SessionId> = fabric
            .announcements()
            .into_iter()
            .map(|(_, owner)| owner)
            .collect();
        let sightings = fabric
            .roster()
            .everybody()
            .into_iter()
            .map(|presence| Sighting {
                id: presence.id,
                tenant: Arc::clone(&presence.tenant),
                address: presence.address,
                publishing: publishing.contains(&presence.id),
            });
        self.count(locator, sightings)
    }

    /// How many sessions have a cached place, for tests.
    #[must_use]
    pub fn remembered(&self) -> usize {
        self.places.len()
    }
}

/// How small a bucket may be before it says too much about who is in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disclosure {
    min_count: u32,
    round_to: u32,
}

/// The smallest threshold a [`Disclosure`] accepts. A bucket of one is a person.
pub const FLOOR: u32 = 2;

impl Default for Disclosure {
    fn default() -> Self {
        Self::new(3, 1)
    }
}

impl Disclosure {
    /// Withhold places with fewer than `min_count` sessions, and round the
    /// counts that are shown to the nearest `round_to`.
    ///
    /// `min_count` below [`FLOOR`] is raised to it; `round_to` of zero is one.
    #[must_use]
    pub const fn new(min_count: u32, round_to: u32) -> Self {
        Self {
            min_count: if min_count < FLOOR { FLOOR } else { min_count },
            round_to: if round_to == 0 { 1 } else { round_to },
        }
    }

    /// From `MOQOM_LIVEMAP_MIN_COUNT` and `MOQOM_LIVEMAP_ROUND_TO`, defaulting
    /// to three and one.
    #[must_use]
    pub fn from_env() -> Self {
        let read = |name: &str, fallback: u32| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(fallback)
        };
        Self::new(
            read("MOQOM_LIVEMAP_MIN_COUNT", 3),
            read("MOQOM_LIVEMAP_ROUND_TO", 1),
        )
    }

    /// The threshold in force.
    #[must_use]
    pub const fn min_count(&self) -> u32 {
        self.min_count
    }

    /// The rounding in force.
    #[must_use]
    pub const fn round_to(&self) -> u32 {
        self.round_to
    }

    /// What may be shown of `tally`.
    ///
    /// A city with at least `min_count` sessions is shown as itself. Cities
    /// below it are pooled per country, and a pool that reaches `min_count` is
    /// shown as the country, placed at the session-weighted centre of all that
    /// country's places. Whatever is left, and every unlocated session, is
    /// counted as withheld with no place at all.
    #[must_use]
    pub fn disclose(&self, tally: &Tally) -> Disclosed {
        #[derive(Default)]
        struct Pool {
            pooled: u32,
            weight: i64,
            latitude: i64,
            longitude: i64,
        }

        let mut shown: BTreeMap<Place, u32> = BTreeMap::new();
        let mut pools: BTreeMap<Arc<str>, Pool> = BTreeMap::new();
        for (place, &count) in &tally.places {
            let pool = pools.entry(Arc::clone(&place.country)).or_default();
            pool.weight += i64::from(count);
            pool.latitude += i64::from(place.latitude) * i64::from(count);
            pool.longitude += i64::from(place.longitude) * i64::from(count);
            if count >= self.min_count {
                *shown.entry(place.clone()).or_default() += count;
            } else {
                pool.pooled += count;
            }
        }

        let mut withheld = tally.unlocated;
        for (country, pool) in pools {
            if pool.pooled == 0 {
                continue;
            }
            if pool.pooled < self.min_count {
                withheld += pool.pooled;
                continue;
            }
            let place = Place {
                country,
                region: Arc::from(""),
                city: Arc::from(""),
                latitude: centre(pool.latitude, pool.weight),
                longitude: centre(pool.longitude, pool.weight),
            };
            *shown.entry(place).or_default() += pool.pooled;
        }

        Disclosed {
            places: shown
                .into_iter()
                .map(|(place, count)| (place, self.round(count)))
                .collect(),
            withheld,
        }
    }

    const fn round(self, count: u32) -> u32 {
        if self.round_to <= 1 {
            return count;
        }
        let rounded = (count + self.round_to / 2) / self.round_to * self.round_to;
        if rounded < self.round_to {
            self.round_to
        } else {
            rounded
        }
    }
}

/// A weighted mean of whole degrees, as whole degrees.
// Degree sums are far below 2^52, and a mean of i16 values is an i16.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
fn centre(sum: i64, weight: i64) -> i16 {
    if weight == 0 {
        return 0;
    }
    (sum as f64 / weight as f64).round() as i16
}

/// The part of a [`Tally`] that may be shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosed {
    /// Places and their counts, each at or above the threshold before rounding.
    pub places: Vec<(Place, u32)>,
    /// Sessions in no shown place: below the threshold, or never located.
    pub withheld: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Just enough of a `MaxMind` DB writer to build a database in a test.
    #[derive(Default)]
    struct Writer {
        out: Vec<u8>,
    }

    impl Writer {
        fn control(&mut self, kind: u8, size: usize) {
            let (bits, extra): (u8, Vec<u8>) = match size {
                0..=28 => (size as u8, vec![]),
                29..=284 => (29, vec![(size - 29) as u8]),
                285..=65_820 => (30, ((size - 285) as u16).to_be_bytes().to_vec()),
                _ => (31, ((size - 65_821) as u32).to_be_bytes()[1..].to_vec()),
            };
            if kind <= 7 {
                self.out.push((kind << 5) | bits);
            } else {
                self.out.push(bits);
                self.out.push(kind - 7);
            }
            self.out.extend_from_slice(&extra);
        }
        fn string(&mut self, s: &str) -> usize {
            let at = self.out.len();
            self.control(STRING, s.len());
            self.out.extend_from_slice(s.as_bytes());
            at
        }
        fn double(&mut self, v: f64) {
            self.control(DOUBLE, 8);
            self.out.extend_from_slice(&v.to_bits().to_be_bytes());
        }
        fn uint(&mut self, kind: u8, v: u32) {
            let bytes = v.to_be_bytes();
            let start = bytes.iter().position(|b| *b != 0).unwrap_or(4);
            self.control(kind, 4 - start);
            self.out.extend_from_slice(&bytes[start..]);
        }
        fn map(&mut self, n: usize) {
            self.control(MAP, n);
        }
        fn array(&mut self, n: usize) {
            self.control(ARRAY, n);
        }
        fn pointer(&mut self, target: usize) {
            if target < 2_048 {
                self.out.push(0x20 | ((target >> 8) as u8 & 0x07));
                self.out.push(target as u8);
            } else {
                let value = target - 2_048;
                self.out.push(0x28 | ((value >> 16) as u8 & 0x07));
                self.out.extend_from_slice(&(value as u16).to_be_bytes());
            }
        }
    }

    /// A city record. The English name is a pointer to the German one, and an
    /// unrelated key comes first, so that both pointers and skipping are used.
    fn city(
        w: &mut Writer,
        country: &str,
        region: Option<&str>,
        name: Option<&str>,
        at: (f64, f64),
    ) -> usize {
        let start = w.out.len();
        let fields = 3 + usize::from(region.is_some()) + usize::from(name.is_some());
        w.map(fields);
        w.string("continent");
        w.map(2);
        w.string("code");
        w.string("EU");
        w.string("names");
        w.map(1);
        w.string("fr");
        w.string("Europe");
        w.string("country");
        w.map(1);
        w.string("iso_code");
        w.string(country);
        if let Some(region) = region {
            w.string("subdivisions");
            w.array(1);
            w.map(1);
            w.string("iso_code");
            w.string(region);
        }
        if let Some(name) = name {
            w.string("city");
            w.map(1);
            w.string("names");
            w.map(2);
            w.string("de");
            let german = w.string(name);
            w.string("en");
            w.pointer(german);
        }
        w.string("location");
        w.map(3);
        w.string("accuracy_radius");
        w.uint(UINT16, 5);
        w.string("latitude");
        w.double(at.0);
        w.string("longitude");
        w.double(at.1);
        start
    }

    #[derive(Clone, Copy)]
    enum Child {
        Empty,
        Node(usize),
        Data(usize),
    }

    fn insert(nodes: &mut Vec<[Child; 2]>, bits: &[bool], data: usize) {
        let mut node = 0;
        for (i, &bit) in bits.iter().enumerate() {
            let side = usize::from(bit);
            if i + 1 == bits.len() {
                nodes[node][side] = Child::Data(data);
                return;
            }
            node = match nodes[node][side] {
                Child::Node(next) => next,
                Child::Empty => {
                    nodes.push([Child::Empty, Child::Empty]);
                    let next = nodes.len() - 1;
                    nodes[node][side] = Child::Node(next);
                    next
                }
                Child::Data(_) => panic!("overlapping prefixes in the fixture"),
            };
        }
    }

    fn v4_bits(address: Ipv4Addr, prefix: usize) -> Vec<bool> {
        let mut bits = vec![false; 96];
        let n = u32::from(address);
        bits.extend((0..prefix).map(|i| n & (1 << (31 - i)) != 0));
        bits
    }

    fn v6_bits(address: Ipv6Addr, prefix: usize) -> Vec<bool> {
        let n = u128::from(address);
        (0..prefix).map(|i| n & (1 << (127 - i)) != 0).collect()
    }

    /// London at `81.2.69.0/24`, a country-only record at `2001:db8::/32`.
    fn database(record_size: u16) -> Vec<u8> {
        let mut data = Writer::default();
        let london = city(
            &mut data,
            "GB",
            Some("ENG"),
            Some("London"),
            (51.5142, -0.0931),
        );
        let japan = city(&mut data, "JP", None, None, (35.69, 139.69));

        let mut nodes = vec![[Child::Empty, Child::Empty]];
        insert(
            &mut nodes,
            &v4_bits(Ipv4Addr::new(81, 2, 69, 0), 24),
            london,
        );
        insert(
            &mut nodes,
            &v6_bits("2001:db8::".parse().unwrap(), 32),
            japan,
        );

        let count = nodes.len() as u32;
        let value = |child: Child| match child {
            Child::Empty => count,
            Child::Node(n) => n as u32,
            Child::Data(offset) => count + 16 + offset as u32,
        };
        let mut file = Vec::new();
        for [left, right] in nodes {
            let (l, r) = (value(left), value(right));
            match record_size {
                24 => {
                    file.extend_from_slice(&l.to_be_bytes()[1..]);
                    file.extend_from_slice(&r.to_be_bytes()[1..]);
                }
                28 => {
                    file.extend_from_slice(&l.to_be_bytes()[1..]);
                    file.push((((l >> 24) & 0x0F) << 4) as u8 | ((r >> 24) & 0x0F) as u8);
                    file.extend_from_slice(&r.to_be_bytes()[1..]);
                }
                _ => {
                    file.extend_from_slice(&l.to_be_bytes());
                    file.extend_from_slice(&r.to_be_bytes());
                }
            }
        }
        file.extend_from_slice(&[0; 16]);
        file.extend_from_slice(&data.out);
        file.extend_from_slice(METADATA_MARKER);

        let mut meta = Writer::default();
        meta.map(4);
        meta.string("node_count");
        meta.uint(UINT32, count);
        meta.string("record_size");
        meta.uint(UINT16, u32::from(record_size));
        meta.string("ip_version");
        meta.uint(UINT16, 6);
        meta.string("database_type");
        meta.string("Test-City");
        file.extend_from_slice(&meta.out);
        file
    }

    fn london() -> Place {
        Place {
            country: "GB".into(),
            region: "ENG".into(),
            city: "London".into(),
            latitude: 52,
            longitude: 0,
        }
    }

    #[test]
    fn every_record_size_locates_an_ipv4_address_to_a_rounded_city() {
        for size in [24, 28, 32] {
            let locator = Locator::from_bytes(database(size)).expect("opens");
            assert_eq!(
                locator.locate(IpAddr::V4(Ipv4Addr::new(81, 2, 69, 160))),
                Some(london()),
                "record size {size}"
            );
        }
    }

    /// A dual-stack socket reports IPv4 peers as `::ffff:a.b.c.d`, and those
    /// must land in the IPv4 part of the tree, not the IPv6 one.
    #[test]
    fn a_mapped_ipv4_address_is_located_as_ipv4() {
        let locator = Locator::from_bytes(database(24)).expect("opens");
        let mapped: IpAddr = "::ffff:81.2.69.160".parse().unwrap();
        assert_eq!(locator.locate(mapped), Some(london()));
    }

    #[test]
    fn a_country_only_record_has_no_city() {
        let locator = Locator::from_bytes(database(28)).expect("opens");
        let place = locator
            .locate("2001:db8::1".parse().unwrap())
            .expect("located");
        assert_eq!(&*place.country, "JP");
        assert_eq!(&*place.city, "");
        assert_eq!(&*place.region, "");
        assert_eq!((place.latitude, place.longitude), (36, 140));
    }

    #[test]
    fn an_address_outside_the_database_is_nowhere() {
        let locator = Locator::from_bytes(database(24)).expect("opens");
        assert_eq!(locator.locate(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), None);
        assert_eq!(
            locator.locate(IpAddr::V4(Ipv4Addr::new(81, 2, 70, 1))),
            None
        );
        assert_eq!(locator.locate("2001:db9::1".parse().unwrap()), None);
    }

    #[test]
    fn something_that_is_not_a_database_is_refused() {
        assert!(Locator::from_bytes(Vec::new()).is_err());
        assert!(Locator::from_bytes(b"not a database at all".to_vec()).is_err());
    }

    /// A database is a file somebody downloads. A damaged one must cost the
    /// map its locations, not the relay its process.
    #[test]
    fn a_truncated_database_never_panics() {
        let whole = database(24);
        let probe = IpAddr::V4(Ipv4Addr::new(81, 2, 69, 160));
        for cut in 0..whole.len() {
            let mut damaged = whole.clone();
            damaged.truncate(cut);
            if let Ok(locator) = Locator::from_bytes(damaged) {
                let _ = locator.locate(probe);
            }
            let mut flipped = whole.clone();
            flipped[cut] ^= 0xFF;
            if let Ok(locator) = Locator::from_bytes(flipped) {
                let _ = locator.locate(probe);
                let _ = locator.locate("2001:db8::1".parse().unwrap());
            }
        }
    }

    /// Session numbers, which only a fabric hands out.
    fn session(n: usize) -> SessionId {
        thread_local!(static FABRIC: Fabric = Fabric::new());
        thread_local!(static ISSUED: std::cell::RefCell<Vec<SessionId>> = const { std::cell::RefCell::new(Vec::new()) });
        ISSUED.with(|issued| {
            let mut issued = issued.borrow_mut();
            while issued.len() <= n {
                issued.push(FABRIC.with(Fabric::next_session_id));
            }
            issued[n]
        })
    }

    fn sighting(id: usize, tenant: &str, address: &str, publishing: bool) -> Sighting {
        Sighting {
            id: session(id),
            tenant: tenant.into(),
            address: address.parse().unwrap(),
            publishing,
        }
    }

    #[test]
    fn a_census_counts_places_and_roles_per_tenant() {
        let locator = Locator::from_bytes(database(24)).expect("opens");
        let mut surveyor = Surveyor::new();
        let census = surveyor.count(
            Some(&locator),
            [
                sighting(1, "acme", "81.2.69.1", true),
                sighting(2, "acme", "81.2.69.2", false),
                sighting(3, "acme", "192.168.1.9", false),
                sighting(4, "globex", "81.2.69.3", false),
            ],
        );

        let acme = &census.tenants[&Arc::<str>::from("acme")];
        assert_eq!((acme.publishers, acme.viewers, acme.unlocated), (1, 2, 1));
        assert_eq!(acme.places.get(&london()), Some(&2));
        let globex = &census.tenants[&Arc::<str>::from("globex")];
        assert_eq!(globex.sessions(), 1);
        assert_eq!(globex.places.get(&london()), Some(&1));
    }

    /// The census is what leaves the relay. Nothing in it can be an address.
    #[test]
    fn a_census_carries_no_address() {
        let locator = Locator::from_bytes(database(24)).expect("opens");
        let census =
            Surveyor::new().count(Some(&locator), [sighting(1, "acme", "81.2.69.77", false)]);
        let printed = format!("{census:?}");
        assert!(!printed.contains("81.2.69"), "{printed}");
        assert!(!printed.contains("77"), "{printed}");
    }

    #[test]
    fn places_are_remembered_only_while_their_session_lives() {
        let locator = Locator::from_bytes(database(24)).expect("opens");
        let mut surveyor = Surveyor::new();
        surveyor.count(
            Some(&locator),
            [
                sighting(1, "acme", "81.2.69.1", false),
                sighting(2, "acme", "81.2.69.2", false),
            ],
        );
        assert_eq!(surveyor.remembered(), 2);
        surveyor.count(Some(&locator), [sighting(2, "acme", "81.2.69.2", false)]);
        assert_eq!(surveyor.remembered(), 1);
        surveyor.count(Some(&locator), []);
        assert_eq!(surveyor.remembered(), 0);
    }

    #[test]
    fn without_a_database_everybody_is_unlocated() {
        let census = Surveyor::new().count(None, [sighting(1, "acme", "81.2.69.1", false)]);
        let acme = &census.tenants[&Arc::<str>::from("acme")];
        assert_eq!(acme.unlocated, 1);
        assert!(acme.places.is_empty());
    }

    fn place(country: &str, city: &str, latitude: i16, longitude: i16) -> Place {
        Place {
            country: country.into(),
            region: "".into(),
            city: city.into(),
            latitude,
            longitude,
        }
    }

    fn tally(places: &[(Place, u32)], unlocated: u32) -> Tally {
        let viewers = places.iter().map(|(_, n)| n).sum::<u32>() + unlocated;
        Tally {
            publishers: 0,
            viewers,
            places: places.iter().cloned().collect(),
            unlocated,
        }
    }

    #[test]
    fn a_place_below_the_threshold_is_withheld() {
        let tally = tally(
            &[
                (place("FR", "Paris", 49, 2), 3),
                (place("DE", "Berlin", 53, 13), 2),
            ],
            0,
        );
        let shown = Disclosure::new(3, 1).disclose(&tally);
        assert_eq!(shown.places, vec![(place("FR", "Paris", 49, 2), 3)]);
        assert_eq!(shown.withheld, 2);
    }

    /// Three small towns in one country are three people each too few to show
    /// and one country with enough to.
    #[test]
    fn small_places_pool_into_their_country() {
        let tally = tally(
            &[
                (place("FR", "Lyon", 46, 5), 2),
                (place("FR", "Lille", 51, 3), 1),
                (place("FR", "Paris", 49, 2), 5),
            ],
            0,
        );
        let shown = Disclosure::new(3, 1).disclose(&tally);
        assert_eq!(shown.withheld, 0);
        let pooled: Vec<_> = shown
            .places
            .iter()
            .filter(|(p, _)| p.city.is_empty())
            .collect();
        assert_eq!(pooled.len(), 1, "{shown:?}");
        let (country, count) = pooled[0];
        assert_eq!((&*country.country, *count), ("FR", 3));
        // The session-weighted centre of every French place, not of the pooled
        // ones alone, so the dot does not sit on the towns it is hiding.
        assert_eq!((country.latitude, country.longitude), (49, 3));
        assert!(shown.places.contains(&(place("FR", "Paris", 49, 2), 5)));
    }

    #[test]
    fn a_pool_below_the_threshold_is_withheld_with_the_unlocated() {
        let tally = tally(
            &[
                (place("NZ", "Wellington", -41, 175), 1),
                (place("NZ", "Auckland", -37, 175), 1),
            ],
            4,
        );
        let shown = Disclosure::new(3, 1).disclose(&tally);
        assert!(shown.places.is_empty(), "{shown:?}");
        assert_eq!(shown.withheld, 6);
    }

    #[test]
    fn the_threshold_cannot_be_configured_below_two() {
        assert_eq!(Disclosure::new(0, 1).min_count(), FLOOR);
        assert_eq!(Disclosure::new(1, 1).min_count(), FLOOR);
        let shown =
            Disclosure::new(1, 1).disclose(&tally(&[(place("IS", "Reykjavik", 64, -22), 1)], 0));
        assert!(
            shown.places.is_empty(),
            "a bucket of one is a person: {shown:?}"
        );
    }

    #[test]
    fn rounding_never_shows_a_shown_place_as_empty() {
        let disclosure = Disclosure::new(3, 5);
        assert_eq!(disclosure.round(3), 5);
        assert_eq!(disclosure.round(7), 5);
        assert_eq!(disclosure.round(8), 10);
        assert_eq!(disclosure.round(12), 10);
        assert_eq!(Disclosure::new(3, 0).round(7), 7);
    }

    /// Nothing is lost: every session is either in a shown place or withheld.
    #[test]
    fn shown_and_withheld_account_for_everybody() {
        let tally = tally(
            &[
                (place("US", "Seattle", 48, -122), 9),
                (place("US", "Boise", 44, -116), 1),
                (place("US", "Reno", 40, -120), 2),
                (place("CA", "Victoria", 48, -123), 2),
                (place("BR", "Recife", -8, -35), 4),
            ],
            3,
        );
        let shown = Disclosure::default().disclose(&tally);
        let total: u32 = shown.places.iter().map(|(_, n)| n).sum::<u32>() + shown.withheld;
        assert_eq!(total, tally.sessions());
        assert!(shown.places.iter().all(|(_, n)| *n >= 3), "{shown:?}");
    }
}
