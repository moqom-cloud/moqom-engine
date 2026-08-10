//! Recent objects, kept so a fetch can be answered locally.
//!
//! A subscription only delivers what is published from now on, which leaves two
//! gaps that matter. A subscriber joining a live track waits for the next group
//! boundary — up to a whole keyframe interval of black. And a subscriber whose
//! connection drops comes back having missed however long the outage lasted.
//! Both are FETCH's job, and a fetch that has to reach the original publisher
//! turns a local problem into a round trip across the network, per reconnecting
//! client. Answering from the relay is the difference.
//!
//! # Caching is a tee, not a stage in the path
//!
//! Forwarding stays a byte pump: [`crate::session`] copies a subgroup stream to
//! its subscribers without parsing objects, which is what keeps payloads opaque
//! and end-to-end encryptable. The cache reads a *copy* of those bytes. So a
//! stream this module cannot parse costs a cache miss and nothing else — it
//! cannot corrupt or stall a forward. That is deliberate: caching is an
//! optimisation, forwarding is the contract, and the failure modes should not be
//! shared.
//!
//! # Groups are the unit of retention
//!
//! Eviction drops whole groups. Half a group is worse than none: a group is the
//! independently decodable unit, so the objects left behind cannot be used
//! without the ones dropped, and serving them spends bandwidth to deliver
//! something undecodable. Byte budgets are therefore approximate by design —
//! the cache overshoots to a group boundary rather than truncating one.
//!
//! # Three answers, not two
//!
//! For any location a fetch asks about, the cache says *held*, *does not exist*,
//! or *unknown*, and the third is not a hedge. "Does not exist" is final and a
//! client can stop asking. "Unknown" means this relay does not have it but
//! someone might, so the request is worth forwarding upstream. Collapsing them
//! would either make clients wait for objects that are never coming or make them
//! give up on objects they could still get.
//!
//! Non-existence is only ever asserted from evidence: an `EndOfGroup` marker
//! bounds its group, an `EndOfTrack` marker bounds the track. A hole between two
//! held objects is *unknown*, because subgroups interleave Object IDs within a
//! group and holding one subgroup says nothing about what the others carried.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use moqom_proto::control::properties::Properties;
use moqom_proto::data::{
    FetchObject, FetchRecord, GroupOrder, SubgroupContent, SubgroupHeader, SubgroupObject,
    TerminalStatus,
};
use moqom_proto::model::{FetchEnd, FullTrackName, GroupId, Location, ObjectId, SubgroupId};
use moqom_proto::varint::VarInt;

/// How much history to keep.
///
/// Four limits rather than one because they fail differently. A group count
/// bounds *latency to the oldest usable join point*, which is what a late
/// joiner cares about. A per-track byte budget stops one high-bitrate track
/// from crowding out every other. A process budget stops the relay from
/// answering fetches by running out of memory. And an age bounds all three in
/// the dimension they cannot see.
///
/// # Why counting groups is not the same as bounding time
///
/// A group count only describes a window while somebody is publishing into it.
/// The moment a track goes quiet its last groups stop ageing out, because
/// eviction runs on write and there are no more writes. Nothing else expires
/// them: the byte budgets are shared across a whole process, so on a relay that
/// is not under memory pressure the final groups of a finished broadcast are
/// kept until the process restarts.
///
/// That was not a theoretical hole. A subscriber joining a track asks for the
/// group in progress so it has a keyframe rather than waiting for the next
/// boundary, and it anchors that fetch on [`Cache::largest`]. Rejoin a room
/// whose publisher has left and the relay hands over the previous session's
/// final group as though it were the live edge: measured on device, eighty-eight
/// frames stamped twenty-five minutes in the past, delivered in a twenty
/// millisecond burst before the first live frame. The subscriber has no way to
/// tell that from a publisher whose clock jumped, and duly reported one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Groups retained per track. Two is the useful minimum: the group being
    /// published and the one before it, so a join is never left waiting.
    pub groups_per_track: usize,
    /// Bytes retained per track, rounded up to a group boundary.
    pub bytes_per_track: usize,
    /// Bytes retained across every track.
    pub bytes_total: usize,
    /// How long a group can still be somebody's recent past.
    ///
    /// Measured from the first object written to a group, so a group ages from
    /// when it started rather than from when it was finished.
    pub max_age: Duration,
}

impl Default for Limits {
    /// Enough to cover a reconnect on a typical broadcast without pretending to
    /// be storage: at a two-second group interval, eight groups is a sixteen
    /// second window.
    fn default() -> Self {
        Self {
            groups_per_track: 8,
            bytes_per_track: 16 * 1024 * 1024,
            bytes_total: 512 * 1024 * 1024,
            // The same window the group count describes, so the two limits
            // agree about how far back this cache reaches instead of one of
            // them quietly outliving the other.
            max_age: Duration::from_secs(16),
        }
    }
}

impl Limits {
    /// Limits that keep nothing, for a relay that should not retain media.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            groups_per_track: 0,
            bytes_per_track: 0,
            bytes_total: 0,
            max_age: Duration::ZERO,
        }
    }

    /// Whether these limits allow keeping anything at all.
    #[must_use]
    pub const fn retains_anything(&self) -> bool {
        self.groups_per_track > 0
            && self.bytes_per_track > 0
            && self.bytes_total > 0
            && !self.max_age.is_zero()
    }
}

/// What the cache holds right now, for diagnostics and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    /// Tracks with at least one retained group.
    pub tracks: usize,
    /// Retained groups across every track.
    pub groups: usize,
    /// Retained objects across every track.
    pub objects: usize,
    /// Payload bytes retained. Excludes keys and bookkeeping.
    pub bytes: usize,
}

/// One retained object.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    subgroup: u64,
    priority: u8,
    properties: Properties,
    payload: Bytes,
}

impl Entry {
    /// What this entry counts against the byte budgets.
    ///
    /// Payload only. Properties are small, bounded, and counting them would make
    /// the budget depend on metadata the operator did not choose to store.
    fn weight(&self) -> usize {
        self.payload.len()
    }
}

/// One retained group.
#[derive(Debug, Clone)]
struct Group {
    /// Keyed by Object ID, which is unique within a group across its subgroups.
    objects: BTreeMap<u64, Entry>,
    /// The Object ID of an `EndOfGroup` marker: nothing at or above it exists.
    end: Option<u64>,
    bytes: usize,
    /// When the group's first object was written.
    written: Instant,
}

impl Default for Group {
    /// A group is only ever default-constructed at the moment it is first
    /// written to, which is exactly the instant its age is measured from.
    fn default() -> Self {
        Self {
            objects: BTreeMap::new(),
            end: None,
            bytes: 0,
            written: Instant::now(),
        }
    }
}

impl Group {
    /// Whether `object` is known not to exist, as opposed to merely absent.
    fn refutes(&self, object: u64) -> bool {
        self.end.is_some_and(|end| object >= end)
    }

    /// Whether this group is too old to be anybody's recent past.
    fn expired(&self, now: Instant, max_age: Duration) -> bool {
        now.saturating_duration_since(self.written) > max_age
    }
}

/// One track's history.
#[derive(Debug, Clone, Default)]
struct Track {
    groups: BTreeMap<u64, Group>,
    bytes: usize,
    /// Where an `EndOfTrack` marker was seen: nothing at or above it exists.
    end: Option<Location>,
    /// Bumped on every write, so the global budget can evict the track that has
    /// gone quietest rather than an arbitrary one.
    touched: u64,
}

#[derive(Debug, Default)]
struct State {
    tracks: HashMap<FullTrackName, Track>,
    bytes: usize,
    clock: u64,
    /// When the age sweep last ran, so it does not run per object.
    swept: Option<Instant>,
}

/// Recent objects for every track passing through this relay.
///
/// Cheap to clone; all clones share one store.
#[derive(Debug, Clone)]
pub struct Cache {
    limits: Limits,
    state: Arc<Mutex<State>>,
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
}

impl Default for Cache {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl Cache {
    /// A cache retaining up to `limits`.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            state: Arc::new(Mutex::new(State::default())),
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
        }
    }

    /// What this cache is allowed to retain.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // Nothing user-supplied runs under this lock, so a poisoned mutex means
        // a bug in this module. Recovering keeps that bug from spreading to
        // every session that touches the cache.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Start recording a subgroup stream belonging to `track`.
    ///
    /// The returned [`Recorder`] resolves the Subgroup ID, which for a stream
    /// declaring `FirstObjectId` is not known until its first object arrives.
    #[must_use]
    pub fn record(&self, track: FullTrackName, header: &SubgroupHeader) -> Recorder {
        Recorder {
            cache: self.clone(),
            track,
            group: header.group,
            subgroup: header.subgroup.resolved().map(SubgroupId::get),
            priority: header.priority.unwrap_or(128),
            enabled: self.limits.retains_anything(),
        }
    }

    /// Answer a fetch from what is retained.
    ///
    /// Returns the records to write on the fetch's data stream, in `order`, with
    /// markers covering the parts of the range this relay cannot vouch for. An
    /// empty result means the range is entirely unknown and nothing useful can
    /// be said about it — a caller should forward the request upstream rather
    /// than write an empty stream.
    #[must_use]
    pub fn fetch(
        &self,
        track: &FullTrackName,
        start: Location,
        end: FetchEnd,
        order: GroupOrder,
    ) -> Vec<FetchRecord> {
        self.fetch_at(track, start, end, order, Instant::now())
    }

    /// [`Cache::fetch`], as of `now`.
    fn fetch_at(
        &self,
        track: &FullTrackName,
        start: Location,
        end: FetchEnd,
        order: GroupOrder,
        now: Instant,
    ) -> Vec<FetchRecord> {
        let max_age = self.limits.max_age;
        let records = self
            .lock()
            .tracks
            .get(track)
            .map_or_else(Vec::new, |held| read(held, start, end, order, now, max_age));
        let counter = if records.is_empty() {
            &self.misses
        } else {
            &self.hits
        };
        counter.fetch_add(1, Ordering::Relaxed);
        records
    }

    /// The largest location retained for `track`, which is where a joining fetch
    /// ends and a subscription takes over.
    #[must_use]
    pub fn largest(&self, track: &FullTrackName) -> Option<Location> {
        self.largest_at(track, Instant::now())
    }

    /// [`Cache::largest`], as of `now`.
    ///
    /// An expired newest group means there is no live edge here to join, rather
    /// than a live edge that happens to be old. Answering `None` sends the
    /// subscriber to the next real group, which is the only honest place for it
    /// to start.
    fn largest_at(&self, track: &FullTrackName, now: Instant) -> Option<Location> {
        let state = self.lock();
        let held = state.tracks.get(track)?;
        let (&group, last) = held.groups.iter().next_back()?;
        if last.expired(now, self.limits.max_age) {
            return None;
        }
        let (&object, _) = last.objects.iter().next_back()?;
        location_of(group, object)
    }

    /// The oldest group retained for `track`. A joining fetch cannot usefully
    /// reach further back than this.
    #[must_use]
    pub fn oldest_group(&self, track: &FullTrackName) -> Option<GroupId> {
        self.oldest_group_at(track, Instant::now())
    }

    /// [`Cache::oldest_group`], as of `now`.
    fn oldest_group_at(&self, track: &FullTrackName, now: Instant) -> Option<GroupId> {
        let state = self.lock();
        let held = state.tracks.get(track)?;
        let (&group, _) = held
            .groups
            .iter()
            .find(|(_, held)| !held.expired(now, self.limits.max_age))?;
        Some(GroupId::new(VarInt::new(group).ok()?))
    }

    /// Drop everything retained for `track`.
    pub fn forget(&self, track: &FullTrackName) {
        let mut state = self.lock();
        if let Some(held) = state.tracks.remove(track) {
            state.bytes -= held.bytes;
        }
    }

    /// What is currently retained.
    #[must_use]
    pub fn stats(&self) -> Stats {
        let state = self.lock();
        Stats {
            tracks: state.tracks.len(),
            groups: state.tracks.values().map(|t| t.groups.len()).sum(),
            objects: state
                .tracks
                .values()
                .flat_map(|t| t.groups.values())
                .map(|g| g.objects.len())
                .sum(),
            bytes: state.bytes,
        }
    }

    /// Fetches answered from the cache, and fetches it could say nothing about.
    #[must_use]
    pub fn hit_rate(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }

    /// Record one object.
    fn store(
        &self,
        track: &FullTrackName,
        group: u64,
        subgroup: u64,
        priority: u8,
        object: &SubgroupObject,
    ) {
        let id = object.object.get();
        let mut state = self.lock();
        state.clock += 1;
        let clock = state.clock;
        let held = state.tracks.entry(track.clone()).or_default();
        held.touched = clock;

        match &object.content {
            SubgroupContent::Terminal(status) => {
                // A marker is bookkeeping, not media: it is not stored as an
                // object, it changes what the cache can say does not exist.
                match status {
                    TerminalStatus::EndOfGroup => {
                        let entry = held.groups.entry(group).or_default();
                        entry.end = Some(entry.end.map_or(id, |seen| seen.min(id)));
                    }
                    TerminalStatus::EndOfTrack => {
                        if let Some(location) = location_of(group, id) {
                            held.end = Some(held.end.map_or(location, |seen| seen.min(location)));
                        }
                    }
                }
            }
            SubgroupContent::Normal {
                payload,
                properties,
            } => {
                let entry = Entry {
                    subgroup,
                    priority,
                    properties: properties.clone(),
                    payload: payload.clone(),
                };
                let weight = entry.weight();
                let target = held.groups.entry(group).or_default();
                // Objects are immutable, so a repeat is the same bytes and
                // replacing it is a no-op — except for the byte accounting,
                // which would drift if the old weight were not returned first.
                let replaced = target
                    .objects
                    .insert(id, entry)
                    .map_or(0, |previous| previous.weight());
                target.bytes = target.bytes + weight - replaced;
                held.bytes = held.bytes + weight - replaced;
                state.bytes = state.bytes + weight - replaced;
            }
        }

        let limits = self.limits;
        Self::evict(&mut state, track, limits, Instant::now());
    }

    /// How often the age sweep walks every track.
    const SWEEP: Duration = Duration::from_secs(1);

    /// Retire every group past its age, across every track.
    ///
    /// Across every track rather than only the one being written, because the
    /// track that needs this is by definition the one nobody is writing to. The
    /// other budgets can afford to be lazy — a track that has stopped growing
    /// has stopped threatening them — but age is the one limit a quiet track
    /// keeps crossing while doing nothing at all.
    ///
    /// Expiry takes no "keep the last group" floor, unlike the byte budget. That
    /// floor exists so a track over budget still has something to answer with;
    /// an expired track should have nothing to answer with, which is the point.
    fn expire(state: &mut State, max_age: Duration, now: Instant) {
        let mut emptied = Vec::new();
        for (name, held) in &mut state.tracks {
            let retired: Vec<u64> = held
                .groups
                .iter()
                .filter(|(_, group)| group.expired(now, max_age))
                .map(|(&id, _)| id)
                .collect();
            for id in retired {
                if let Some(group) = held.groups.remove(&id) {
                    held.bytes -= group.bytes;
                    state.bytes -= group.bytes;
                }
            }
            if held.groups.is_empty() && held.end.is_none() {
                emptied.push(name.clone());
            }
        }
        for name in emptied {
            state.tracks.remove(&name);
        }
    }

    /// Bring one track, and then the process, back within budget.
    fn evict(state: &mut State, track: &FullTrackName, limits: Limits, now: Instant) {
        // Paced, because this is the one pass that has to visit every track and
        // it would otherwise run once per stored object. Correctness does not
        // depend on the cadence — every read checks a group's age exactly — so
        // all the sweep decides is how long retired bytes are held, and a
        // second of that against a sixteen second window is not worth the walk.
        if state
            .swept
            .is_none_or(|at| now.saturating_duration_since(at) >= Self::SWEEP)
        {
            state.swept = Some(now);
            Self::expire(state, limits.max_age, now);
        }

        if let Some(held) = state.tracks.get_mut(track) {
            let mut freed = 0;
            while held.groups.len() > limits.groups_per_track
                || (held.bytes > limits.bytes_per_track && held.groups.len() > 1)
            {
                // Always the oldest group. Under descending fetch order a
                // subscriber reads newest-first, but retention is still about
                // how far back the window reaches.
                let Some((&oldest, _)) = held.groups.iter().next() else {
                    break;
                };
                let Some(group) = held.groups.remove(&oldest) else {
                    break;
                };
                held.bytes -= group.bytes;
                freed += group.bytes;
            }
            state.bytes -= freed;
            if held.groups.is_empty() && held.end.is_none() {
                state.tracks.remove(track);
            }
        }

        // The process budget evicts from whichever track has gone quietest,
        // which is the one whose history is least likely to be asked for.
        while state.bytes > limits.bytes_total {
            let Some(quietest) = state
                .tracks
                .iter()
                .filter(|(_, held)| !held.groups.is_empty())
                .min_by_key(|(_, held)| held.touched)
                .map(|(name, _)| name.clone())
            else {
                break;
            };
            let Some(held) = state.tracks.get_mut(&quietest) else {
                break;
            };
            let Some((&oldest, _)) = held.groups.iter().next() else {
                break;
            };
            let Some(group) = held.groups.remove(&oldest) else {
                break;
            };
            held.bytes -= group.bytes;
            state.bytes -= group.bytes;
            if held.groups.is_empty() {
                state.tracks.remove(&quietest);
            }
        }
    }
}

/// Records one subgroup stream into the cache.
///
/// Holds the attribution a subgroup stream's objects do not carry: which track
/// they belong to, which group, which subgroup, and at what priority.
#[derive(Debug)]
pub struct Recorder {
    cache: Cache,
    track: FullTrackName,
    group: GroupId,
    /// `None` until resolved, for a stream whose Subgroup ID is its first
    /// object's.
    subgroup: Option<u64>,
    priority: u8,
    enabled: bool,
}

impl Recorder {
    /// Record one object read from the stream.
    pub fn push(&mut self, object: &SubgroupObject) {
        if !self.enabled {
            return;
        }
        // A `FirstObjectId` stream names its subgroup by its first object, which
        // is only knowable here. Getting this wrong files objects under subgroup
        // zero and reports the wrong Subgroup ID on every fetch of them.
        let subgroup = *self.subgroup.get_or_insert(object.object.get());
        self.cache.store(
            &self.track,
            self.group.get(),
            subgroup,
            self.priority,
            object,
        );
    }

    /// Whether this recorder is storing anything, so a caller can skip parsing
    /// entirely when retention is off.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Build the records answering a range from one track's history.
fn read(
    held: &Track,
    start: Location,
    end: FetchEnd,
    order: GroupOrder,
    now: Instant,
    max_age: Duration,
) -> Vec<FetchRecord> {
    let mut records = Vec::new();
    let groups: Vec<u64> = {
        let ascending = held
            .groups
            .range(start.group.get()..=end.last_group().get())
            .filter(|(_, group)| !group.expired(now, max_age))
            .map(|(&group, _)| group);
        match order {
            GroupOrder::Ascending => ascending.collect(),
            GroupOrder::Descending => ascending.rev().collect(),
        }
    };

    for group in groups {
        let Some(retained) = held.groups.get(&group) else {
            continue;
        };
        // Within a group, objects always ascend. Descending order reverses which
        // group comes first, not the objects inside one.
        let mut pending: Option<Location> = None;
        let mut previous: Option<u64> = None;

        for (&id, entry) in &retained.objects {
            let Some(location) = location_of(group, id) else {
                continue;
            };
            if location < start || !end.covers(location) {
                continue;
            }
            if held.end.is_some_and(|last| location >= last) {
                break;
            }

            // A hole below this object: either refuted by an end-of-group marker
            // or genuinely unknown. Emitted lazily so a run of consecutive
            // objects costs no markers at all.
            if let Some(before) = previous
                && id > before + 1
                && let Some(gap) = location_of(group, id - 1)
            {
                pending = Some(gap);
            }
            if let Some(gap) = pending.take() {
                records.push(if retained.refutes(gap.object.get()) {
                    FetchRecord::EndOfNonExistentRange(gap)
                } else {
                    FetchRecord::EndOfUnknownRange(gap)
                });
            }

            records.push(FetchRecord::Object(FetchObject {
                location,
                subgroup: SubgroupId::new(VarInt::new(entry.subgroup).unwrap_or(VarInt::ZERO)),
                priority: entry.priority,
                properties: entry.properties.clone(),
                payload: entry.payload.clone(),
            }));
            previous = Some(id);
        }
    }
    records
}

/// A location, or `None` for IDs past what one can name.
fn location_of(group: u64, object: u64) -> Option<Location> {
    Some(Location::new(
        GroupId::new(VarInt::new(group).ok()?),
        ObjectId::new(VarInt::new(object).ok()?),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use moqom_proto::model::{TrackAlias, TrackNamespace};

    fn track(name: &str) -> FullTrackName {
        FullTrackName::new(
            TrackNamespace::from_parts([&b"moqom"[..], b"room-1"]).expect("valid namespace"),
            Bytes::copy_from_slice(name.as_bytes()),
        )
        .expect("valid track name")
    }

    fn header(group: u32) -> SubgroupHeader {
        SubgroupHeader::new(
            TrackAlias::from(0u32),
            GroupId::from(group),
            moqom_proto::data::subgroup::SubgroupSource::Zero,
        )
    }

    fn object(id: u32, payload: &'static [u8]) -> SubgroupObject {
        SubgroupObject::new(id, Bytes::from_static(payload))
    }

    fn terminal(id: u32, status: TerminalStatus) -> SubgroupObject {
        SubgroupObject {
            object: id.into(),
            content: SubgroupContent::Terminal(status),
        }
    }

    /// Record `objects` into `group` of `name`.
    fn store(cache: &Cache, name: &FullTrackName, group: u32, objects: &[SubgroupObject]) {
        let mut recorder = cache.record(name.clone(), &header(group));
        for object in objects {
            recorder.push(object);
        }
    }

    fn payloads(records: &[FetchRecord]) -> Vec<&[u8]> {
        records
            .iter()
            .filter_map(|record| match record {
                FetchRecord::Object(object) => Some(&object.payload[..]),
                _ => None,
            })
            .collect()
    }

    fn locations(records: &[FetchRecord]) -> Vec<Location> {
        records.iter().map(FetchRecord::location).collect()
    }

    fn whole_group(group: u32) -> FetchEnd {
        FetchEnd::EndOfGroup(GroupId::from(group))
    }

    #[test]
    fn what_goes_in_comes_back_out() {
        let cache = Cache::default();
        let name = track("video");
        store(
            &cache,
            &name,
            1,
            &[object(0, b"aaa"), object(1, b"bb"), object(2, b"c")],
        );

        let records = cache.fetch(&name, Location::ZERO, whole_group(1), GroupOrder::Ascending);
        assert_eq!(payloads(&records), vec![&b"aaa"[..], b"bb", b"c"]);
        assert_eq!(
            cache.stats(),
            Stats {
                tracks: 1,
                groups: 1,
                objects: 3,
                bytes: 6
            }
        );
    }

    #[test]
    fn an_unknown_track_is_a_miss_rather_than_an_empty_answer() {
        let cache = Cache::default();
        assert!(
            cache
                .fetch(
                    &track("nothing"),
                    Location::ZERO,
                    whole_group(9),
                    GroupOrder::Ascending
                )
                .is_empty()
        );
        assert_eq!(cache.hit_rate(), (0, 1));
    }

    /// The window has to be bounded by count, or a long broadcast is a memory
    /// leak with extra steps.
    #[test]
    fn retention_is_bounded_by_group_count() {
        let cache = Cache::new(Limits {
            groups_per_track: 3,
            ..Limits::default()
        });
        let name = track("video");
        for group in 0..10 {
            store(&cache, &name, group, &[object(0, b"x")]);
        }

        assert_eq!(cache.stats().groups, 3);
        assert_eq!(cache.oldest_group(&name), Some(GroupId::from(7u32)));
        assert_eq!(
            cache.largest(&name),
            Some(Location::new(GroupId::from(9u32), ObjectId::ZERO))
        );
    }

    /// The bug this bounds: a track that stops publishing stops being evicted,
    /// because eviction runs on write. Without an age it keeps its last groups
    /// for the life of the process and offers them to the next joiner as a live
    /// edge, which on device meant twenty-five minute old video ahead of the
    /// first real frame.
    #[test]
    fn a_track_that_went_quiet_has_no_live_edge() {
        let cache = Cache::default();
        let name = track("video");
        store(&cache, &name, 1, &[object(0, b"old")]);

        let later = Instant::now() + Limits::default().max_age + Duration::from_secs(1);
        assert_eq!(
            cache.largest_at(&name, Instant::now()),
            Some(Location::new(GroupId::from(1u32), ObjectId::ZERO)),
            "a group just written is the live edge"
        );
        assert_eq!(
            cache.largest_at(&name, later),
            None,
            "an expired group is not a live edge, it is history"
        );
        assert!(
            cache
                .fetch_at(
                    &name,
                    Location::ZERO,
                    whole_group(1),
                    GroupOrder::Ascending,
                    later,
                )
                .is_empty(),
            "and it cannot be fetched either, or the edge check is the only guard"
        );
        assert_eq!(cache.oldest_group_at(&name, later), None);
    }

    /// Expiry has to release the memory too, not merely hide the groups from
    /// readers, or a quiet relay accumulates every track it ever carried.
    #[test]
    fn expiry_releases_what_it_retires() {
        let cache = Cache::default();
        let name = track("video");
        store(&cache, &name, 1, &[object(0, b"old"), object(1, b"older")]);
        assert_eq!(cache.stats().bytes, 8);

        let later = Instant::now() + Limits::default().max_age + Duration::from_secs(1);
        Cache::expire(&mut cache.lock(), Limits::default().max_age, later);

        assert_eq!(
            cache.stats(),
            Stats::default(),
            "an expired track should account for nothing, not merely answer nothing"
        );
    }

    /// The track that most needs expiring is the one nobody is writing to, so a
    /// pass that only visits the track being written would never reach it.
    #[test]
    fn expiry_reaches_a_track_nobody_is_writing_to() {
        let cache = Cache::default();
        let quiet = track("quiet");
        store(&cache, &quiet, 1, &[object(0, b"old")]);

        // Far enough ahead that the quiet track is stale, then a write to some
        // other track — the only thing that happens on a relay whose publisher
        // has left.
        let busy = track("busy");
        Cache::expire(
            &mut cache.lock(),
            Limits::default().max_age,
            Instant::now() + Limits::default().max_age + Duration::from_secs(1),
        );
        store(&cache, &busy, 1, &[object(0, b"new")]);

        assert_eq!(cache.stats().tracks, 1);
        assert_eq!(cache.largest(&quiet), None);
        assert!(cache.largest(&busy).is_some());
    }

    /// Evicting the newest group would leave the cache useless for exactly the
    /// case it exists for, so the direction is worth pinning.
    #[test]
    fn eviction_takes_the_oldest_group() {
        let cache = Cache::new(Limits {
            groups_per_track: 2,
            ..Limits::default()
        });
        let name = track("video");
        store(&cache, &name, 1, &[object(0, b"old")]);
        store(&cache, &name, 2, &[object(0, b"mid")]);
        store(&cache, &name, 3, &[object(0, b"new")]);

        let records = cache.fetch(&name, Location::ZERO, whole_group(3), GroupOrder::Ascending);
        assert_eq!(payloads(&records), vec![&b"mid"[..], b"new"]);
    }

    /// A byte budget that truncated a group would leave objects nothing can
    /// decode, so it overshoots to a boundary instead.
    #[test]
    fn a_byte_budget_evicts_whole_groups() {
        let cache = Cache::new(Limits {
            groups_per_track: 100,
            bytes_per_track: 10,
            bytes_total: 1_000,
            ..Limits::default()
        });
        let name = track("video");
        for group in 0..5 {
            store(
                &cache,
                &name,
                group,
                &[object(0, b"aaaa"), object(1, b"bbbb")],
            );
        }

        let stats = cache.stats();
        assert!(stats.bytes <= 16, "kept {} bytes", stats.bytes);
        // Whole groups, so the object count is a multiple of two rather than
        // whatever number happened to fit the budget exactly.
        assert_eq!(stats.objects % 2, 0);
    }

    /// A single group over budget is still worth keeping: dropping it leaves
    /// nothing to answer with, which is strictly worse than being over.
    #[test]
    fn the_last_group_survives_a_byte_budget() {
        let cache = Cache::new(Limits {
            groups_per_track: 4,
            bytes_per_track: 1,
            bytes_total: 1_000_000,
            ..Limits::default()
        });
        let name = track("video");
        store(
            &cache,
            &name,
            1,
            &[object(0, b"much larger than the budget")],
        );
        assert_eq!(cache.stats().groups, 1);
    }

    /// One noisy track must not be able to push out every other, and the one to
    /// sacrifice is whichever has gone quietest.
    #[test]
    fn the_process_budget_evicts_the_quietest_track() {
        let cache = Cache::new(Limits {
            groups_per_track: 10,
            bytes_per_track: 1_000_000,
            bytes_total: 12,
            ..Limits::default()
        });
        let quiet = track("quiet");
        let busy = track("busy");

        store(&cache, &quiet, 1, &[object(0, b"aaaa")]);
        for group in 1..4 {
            store(&cache, &busy, group, &[object(0, b"bbbb")]);
        }

        assert!(
            cache
                .fetch(
                    &quiet,
                    Location::ZERO,
                    whole_group(1),
                    GroupOrder::Ascending
                )
                .is_empty(),
            "the quiet track should have been evicted first"
        );
        assert!(
            !cache
                .fetch(&busy, Location::ZERO, whole_group(3), GroupOrder::Ascending)
                .is_empty()
        );
        assert!(cache.stats().bytes <= 12);
    }

    #[test]
    fn retention_can_be_turned_off_entirely() {
        let cache = Cache::new(Limits::none());
        let name = track("video");
        let mut recorder = cache.record(name.clone(), &header(1));
        assert!(!recorder.is_enabled());
        recorder.push(&object(0, b"x"));

        assert_eq!(cache.stats(), Stats::default());
    }

    #[test]
    fn a_range_clips_to_what_was_asked_for() {
        let cache = Cache::default();
        let name = track("video");
        store(&cache, &name, 1, &[object(0, b"a"), object(1, b"b")]);
        store(&cache, &name, 2, &[object(0, b"c"), object(1, b"d")]);
        store(&cache, &name, 3, &[object(0, b"e")]);

        let records = cache.fetch(
            &name,
            Location::new(GroupId::from(1u32), ObjectId::from(1u32)),
            FetchEnd::Through(Location::new(GroupId::from(2u32), ObjectId::from(0u32))),
            GroupOrder::Ascending,
        );
        assert_eq!(payloads(&records), vec![&b"b"[..], b"c"]);
    }

    /// A zero object on the wire means the whole group, and a cache that reads
    /// it as "through object zero" returns one object instead of the group.
    #[test]
    fn a_whole_group_range_includes_the_whole_group() {
        let cache = Cache::default();
        let name = track("video");
        store(
            &cache,
            &name,
            4,
            &[object(0, b"a"), object(1, b"b"), object(2, b"c")],
        );

        let records = cache.fetch(
            &name,
            Location::new(GroupId::from(4u32), ObjectId::ZERO),
            FetchEnd::from_wire(Location::new(GroupId::from(4u32), ObjectId::ZERO)),
            GroupOrder::Ascending,
        );
        assert_eq!(payloads(&records), vec![&b"a"[..], b"b", b"c"]);
    }

    #[test]
    fn descending_order_reverses_groups_but_not_objects() {
        let cache = Cache::default();
        let name = track("video");
        store(&cache, &name, 1, &[object(0, b"a"), object(1, b"b")]);
        store(&cache, &name, 2, &[object(0, b"c"), object(1, b"d")]);

        let records = cache.fetch(
            &name,
            Location::ZERO,
            whole_group(2),
            GroupOrder::Descending,
        );
        assert_eq!(payloads(&records), vec![&b"c"[..], b"d", b"a", b"b"]);
    }

    /// A hole in a group is unknown, not absent: subgroups interleave Object IDs
    /// within a group, so holding one says nothing about what the others carried.
    #[test]
    fn a_hole_in_a_group_is_unknown() {
        let cache = Cache::default();
        let name = track("video");
        store(&cache, &name, 1, &[object(0, b"a"), object(5, b"b")]);

        let records = cache.fetch(&name, Location::ZERO, whole_group(1), GroupOrder::Ascending);
        assert!(
            matches!(records[1], FetchRecord::EndOfUnknownRange(gap)
                if gap == Location::new(GroupId::from(1u32), ObjectId::from(4u32))),
            "expected an unknown marker covering 1..=4, got {:?}",
            records[1]
        );
        assert_eq!(payloads(&records), vec![&b"a"[..], b"b"]);
    }

    /// With an end-of-group marker the same hole becomes final, and a client can
    /// stop asking about it.
    #[test]
    fn an_end_of_group_marker_refutes_the_objects_above_it() {
        let cache = Cache::default();
        let name = track("video");
        // Objects 0 and 9 held, and nothing at or above 3 exists — so the hole
        // between them is partly refuted rather than merely unknown.
        store(
            &cache,
            &name,
            1,
            &[
                object(0, b"a"),
                terminal(3, TerminalStatus::EndOfGroup),
                object(9, b"b"),
            ],
        );

        let records = cache.fetch(&name, Location::ZERO, whole_group(1), GroupOrder::Ascending);
        assert!(
            matches!(records[1], FetchRecord::EndOfNonExistentRange(_)),
            "expected a non-existent marker, got {:?}",
            records[1]
        );
        // The marker itself is bookkeeping, not an object, so it is not served.
        assert_eq!(payloads(&records), vec![&b"a"[..], b"b"]);
    }

    #[test]
    fn an_end_of_track_marker_stops_the_answer() {
        let cache = Cache::default();
        let name = track("video");
        store(
            &cache,
            &name,
            1,
            &[
                object(0, b"a"),
                object(1, b"b"),
                terminal(2, TerminalStatus::EndOfTrack),
            ],
        );
        store(&cache, &name, 2, &[object(0, b"never")]);

        let records = cache.fetch(&name, Location::ZERO, whole_group(2), GroupOrder::Ascending);
        assert_eq!(payloads(&records), vec![&b"a"[..], b"b"]);
    }

    /// Objects are immutable, so a duplicate is the same bytes. Counting it
    /// twice would shrink the effective window every time a publisher retried.
    #[test]
    fn a_repeated_object_does_not_grow_the_byte_count() {
        let cache = Cache::default();
        let name = track("video");
        store(&cache, &name, 1, &[object(0, b"aaaa")]);
        let once = cache.stats();
        store(&cache, &name, 1, &[object(0, b"aaaa")]);

        assert_eq!(cache.stats(), once);
    }

    /// A `FirstObjectId` stream names its subgroup by its first object, and
    /// filing those objects under subgroup zero would misreport every one.
    #[test]
    fn a_first_object_subgroup_is_resolved_from_the_first_object() {
        let cache = Cache::default();
        let name = track("video");
        let mut head = header(1);
        head.subgroup = moqom_proto::data::subgroup::SubgroupSource::FirstObjectId;

        let mut recorder = cache.record(name.clone(), &head);
        recorder.push(&object(6, b"a"));
        recorder.push(&object(7, b"b"));

        let records = cache.fetch(&name, Location::ZERO, whole_group(1), GroupOrder::Ascending);
        for record in &records {
            let FetchRecord::Object(object) = record else {
                continue;
            };
            assert_eq!(
                object.subgroup,
                SubgroupId::from(6u32),
                "subgroup should be the first object's ID"
            );
        }
        assert_eq!(payloads(&records), vec![&b"a"[..], b"b"]);
    }

    /// Two subgroups of one group interleave Object IDs, and a fetch has to
    /// merge them back into one ascending run.
    #[test]
    fn subgroups_of_a_group_merge_into_one_ascending_run() {
        let cache = Cache::default();
        let name = track("video");
        let mut head = header(1);
        head.subgroup = moqom_proto::data::subgroup::SubgroupSource::Explicit(SubgroupId::ZERO);
        let mut first = cache.record(name.clone(), &head);
        first.push(&object(0, b"a"));
        first.push(&object(2, b"c"));

        head.subgroup =
            moqom_proto::data::subgroup::SubgroupSource::Explicit(SubgroupId::from(1u32));
        let mut second = cache.record(name.clone(), &head);
        second.push(&object(1, b"b"));
        second.push(&object(3, b"d"));

        let records = cache.fetch(&name, Location::ZERO, whole_group(1), GroupOrder::Ascending);
        assert_eq!(payloads(&records), vec![&b"a"[..], b"b", b"c", b"d"]);
        assert!(
            !records
                .iter()
                .any(|r| matches!(r, FetchRecord::EndOfUnknownRange(_))),
            "a fully held group has no holes: {records:?}"
        );
    }

    #[test]
    fn forgetting_a_track_releases_its_bytes() {
        let cache = Cache::default();
        let name = track("video");
        store(&cache, &name, 1, &[object(0, b"aaaa")]);
        cache.forget(&name);

        assert_eq!(cache.stats(), Stats::default());
    }

    /// The warm-start case: a subscriber joins mid-group and wants what has
    /// already gone by in the group it is about to receive the rest of.
    #[test]
    fn a_late_joiner_can_fetch_the_group_in_progress() {
        let cache = Cache::default();
        let name = track("video");
        store(&cache, &name, 41, &[object(0, b"old")]);
        store(&cache, &name, 42, &[object(0, b"key"), object(1, b"delta")]);

        let live = cache.largest(&name).expect("something retained");
        assert_eq!(
            live,
            Location::new(GroupId::from(42u32), ObjectId::from(1u32))
        );

        let records = cache.fetch(
            &name,
            Location::new(GroupId::from(42u32), ObjectId::ZERO),
            FetchEnd::Through(live),
            GroupOrder::Ascending,
        );
        assert_eq!(payloads(&records), vec![&b"key"[..], b"delta"]);
        assert_eq!(
            locations(&records),
            vec![
                Location::new(GroupId::from(42u32), ObjectId::ZERO),
                Location::new(GroupId::from(42u32), ObjectId::from(1u32)),
            ]
        );
        assert_eq!(cache.hit_rate(), (1, 0));
    }

    /// What a reconnecting client does: ask for everything from where it left
    /// off. It gets back what is still retained, and the answer has to be
    /// writable as one fetch stream.
    #[test]
    fn a_reconnecting_client_can_ask_from_where_it_stopped() {
        let cache = Cache::new(Limits {
            groups_per_track: 4,
            ..Limits::default()
        });
        let name = track("video");
        for group in 0..6 {
            store(&cache, &name, group, &[object(0, b"a"), object(1, b"b")]);
        }

        let records = cache.fetch(
            &name,
            Location::new(GroupId::from(1u32), ObjectId::ZERO),
            whole_group(5),
            GroupOrder::Ascending,
        );
        // Groups 0 and 1 are gone; the answer starts where retention does rather
        // than where the client asked.
        assert_eq!(
            records.first().map(FetchRecord::location),
            Some(Location::new(GroupId::from(2u32), ObjectId::ZERO))
        );
        assert_eq!(records.len(), 8);

        // And it has to be encodable as a stream, which is the real test of the
        // ordering: the writer refuses anything that does not advance.
        let mut writer = moqom_proto::data::FetchWriter::new(GroupOrder::Ascending);
        let mut buf = Vec::new();
        for record in &records {
            writer
                .write(&mut buf, record)
                .expect("a well-ordered answer");
        }
    }

    /// Descending answers have to be encodable too, and the group deltas have
    /// the opposite sign — so an answer that is valid ascending is not
    /// automatically valid descending.
    #[test]
    fn a_descending_answer_is_encodable() {
        let cache = Cache::default();
        let name = track("video");
        for group in 1..4 {
            store(&cache, &name, group, &[object(0, b"a"), object(1, b"b")]);
        }

        let records = cache.fetch(
            &name,
            Location::ZERO,
            whole_group(3),
            GroupOrder::Descending,
        );
        let mut writer = moqom_proto::data::FetchWriter::new(GroupOrder::Descending);
        let mut buf = Vec::new();
        for record in &records {
            writer
                .write(&mut buf, record)
                .expect("a well-ordered answer");
        }

        let mut reader = moqom_proto::data::FetchReader::new(GroupOrder::Descending);
        let mut cursor = buf.as_slice();
        let mut read = Vec::new();
        while !cursor.is_empty() {
            read.push(reader.read(&mut cursor).expect("readable"));
        }
        assert_eq!(read, records);
    }
}
