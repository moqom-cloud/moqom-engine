//! One track, read over the relay and a direct path at once, delivered once.
//!
//! The relay subscription is opened first and is never closed: it is the
//! fallback, and a fallback that has to be re-established is a gap. A direct
//! subscription is attached when one exists, and the two are merged by object
//! identity, so whichever path delivers an object first wins and the copy that
//! arrives second is dropped.
//!
//! # States
//!
//! - **Relay.** Objects from the relay are delivered. A direct path that has
//!   just been attached is on probation: its objects are delivered too, when
//!   they win the race, and it is watched.
//! - **Direct.** Entered once the direct path has kept up for
//!   [`PathSettings::settle`]. Relay objects are no longer delivered; they are
//!   held, briefly, in case the direct path turns out to have lost them.
//! - **Back to relay.** If the relay has held an object for
//!   [`PathSettings::stall`] that the direct path has not delivered, the direct
//!   path is presumed lost: it is dropped and the held objects are delivered in
//!   order. The same happens at once if the direct subscription ends, and when
//!   the caller reports a network change.
//!
//! Stalls are judged against the relay rather than against a clock, so a
//! publisher that simply stops sending does not look like a broken path.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::time::Duration;

use tokio::time::Instant;

use crate::Error;
use crate::session::{Object, Subscription};

/// Which path an object arrived over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// Through the relay.
    Relay,
    /// Straight from the peer.
    Direct,
}

/// When to trust the direct path, and when to stop.
#[derive(Debug, Clone, Copy)]
pub struct PathSettings {
    /// How long a direct path must keep up before the relay copy is set aside.
    pub settle: Duration,
    /// How long the relay may hold an object the direct path has not delivered
    /// before the direct path is abandoned.
    pub stall: Duration,
    /// How many relay objects to hold while on the direct path. Older ones are
    /// discarded, which bounds memory and also bounds how far back a fallback
    /// can recover.
    pub held: usize,
}

impl Default for PathSettings {
    /// Three seconds to settle, a quarter of a second to give up.
    ///
    /// The stall bound is what a fallback costs in added delay on the objects
    /// caught in it, so it is short; the relay copy is already on hand.
    fn default() -> Self {
        Self {
            settle: Duration::from_secs(3),
            stall: Duration::from_millis(250),
            held: 1024,
        }
    }
}

/// One delivered object, and the path that delivered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// The object.
    pub object: Object,
    /// Which path won the race for it.
    pub path: Path,
}

type Key = (u64, u64);

/// A track read over the relay, with a direct path when there is one.
pub struct DualSubscription {
    relay: Subscription,
    direct: Option<Subscription>,
    settings: PathSettings,
    on_direct: bool,
    /// When the direct path started keeping up, during probation.
    keeping_up_since: Option<Instant>,
    /// Relay objects held while on the direct path, by identity, with when
    /// each arrived.
    held: BTreeMap<Key, (Object, Instant)>,
    /// During probation, objects the relay delivered first and the direct path
    /// has yet to, with when the relay delivered each.
    awaiting: BTreeMap<Key, Instant>,
    /// Objects already delivered, so the second copy is dropped.
    delivered: HashSet<Key>,
    delivered_order: VecDeque<Key>,
    /// Ready to hand out, in order.
    ready: VecDeque<Delivery>,
    relay_ended: bool,
    switches: u32,
}

/// How many delivered identities to remember for deduplication.
const REMEMBERED: usize = 4096;

impl DualSubscription {
    /// Read `relay`, with no direct path yet.
    #[must_use]
    pub fn new(relay: Subscription, settings: PathSettings) -> Self {
        Self {
            relay,
            direct: None,
            settings,
            on_direct: false,
            keeping_up_since: None,
            held: BTreeMap::new(),
            awaiting: BTreeMap::new(),
            delivered: HashSet::new(),
            delivered_order: VecDeque::new(),
            ready: VecDeque::new(),
            relay_ended: false,
            switches: 0,
        }
    }

    /// Attach a direct subscription to the same track, starting its probation.
    pub fn attach_direct(&mut self, direct: Subscription) {
        self.direct = Some(direct);
        self.keeping_up_since = None;
        self.awaiting.clear();
    }

    /// Which path objects are currently being delivered from.
    #[must_use]
    pub const fn path(&self) -> Path {
        if self.on_direct {
            Path::Direct
        } else {
            Path::Relay
        }
    }

    /// How many times the active path has changed, in either direction.
    #[must_use]
    pub const fn switches(&self) -> u32 {
        self.switches
    }

    /// Whether a direct subscription is attached, on probation or in use.
    #[must_use]
    pub const fn has_direct(&self) -> bool {
        self.direct.is_some()
    }

    /// The network changed: drop the direct path and go back to the relay.
    ///
    /// A new interface means new addresses on at least one side, and the
    /// direct path was opened between the old ones. The caller should exchange
    /// fresh offers and attach a new direct subscription if one opens.
    pub fn network_changed(&mut self) {
        self.fall_back();
    }

    /// The next object, from whichever path is delivering, exactly once.
    ///
    /// `None` when the relay subscription has ended: the relay is the
    /// subscription of record, and a direct path alone does not keep this one
    /// alive.
    ///
    /// # Errors
    /// A relay subscription that fails. A direct path that fails is a fallback,
    /// not an error.
    pub async fn next(&mut self) -> Result<Option<Delivery>, Error> {
        loop {
            if let Some(delivery) = self.ready.pop_front() {
                return Ok(Some(delivery));
            }
            if self.relay_ended {
                return Ok(None);
            }

            let stall_at = self
                .held
                .values()
                .map(|(_, arrived)| *arrived)
                .min()
                .map(|oldest| oldest + self.settings.stall);
            let lagging_at = self
                .awaiting
                .values()
                .min()
                .map(|oldest| *oldest + self.settings.stall);

            tokio::select! {
                biased;
                received = next_or_pending(self.direct.as_mut()) => match received {
                    Ok(Some(object)) => self.received_direct(object),
                    Ok(None) | Err(_) => self.fall_back(),
                },
                received = self.relay.next_object() => match received? {
                    Some(object) => self.received_relay(object),
                    None => self.relay_ended = true,
                },
                () = sleep_until_or_pending(stall_at) => self.fall_back(),
                () = sleep_until_or_pending(lagging_at) => {
                    // Probation restarts rather than ending: a direct path
                    // that drops an object while settling may still be
                    // better than the relay, but has not shown it yet.
                    self.awaiting.clear();
                    self.keeping_up_since = None;
                }
            }
        }
    }

    fn received_relay(&mut self, object: Object) {
        let key = key(&object);
        if self.delivered.contains(&key) {
            return;
        }
        if self.on_direct {
            self.held.insert(key, (object, Instant::now()));
            while self.held.len() > self.settings.held {
                self.held.pop_first();
            }
            return;
        }
        // On probation the relay winning a race is not a failure -- the two
        // paths may be nearly equal -- but the direct path must still deliver
        // the same object within the stall bound to stay on probation.
        if self.direct.is_some() {
            self.awaiting.insert(key, Instant::now());
        }
        self.deliver(object, Path::Relay);
    }

    fn received_direct(&mut self, object: Object) {
        let key = key(&object);
        self.held.remove(&key);
        self.awaiting.remove(&key);
        let now = Instant::now();
        if !self.on_direct {
            let since = *self.keeping_up_since.get_or_insert(now);
            if now.duration_since(since) >= self.settings.settle {
                self.on_direct = true;
                self.awaiting.clear();
                self.switches = self.switches.saturating_add(1);
            }
        }
        if self.delivered.contains(&key) {
            return;
        }
        // Anything older than this that the relay is holding was skipped by
        // the direct path, and is delivered now rather than waiting for a
        // stall: on a stream of ordered groups it is a gap, not a reordering.
        let skipped: Vec<Key> = self.held.range(..key).map(|(k, _)| *k).collect();
        for skipped in skipped {
            if let Some((held, _)) = self.held.remove(&skipped) {
                self.deliver(held, Path::Relay);
            }
        }
        self.deliver(object, Path::Direct);
    }

    fn fall_back(&mut self) {
        self.direct = None;
        self.keeping_up_since = None;
        self.awaiting.clear();
        if self.on_direct {
            self.on_direct = false;
            self.switches = self.switches.saturating_add(1);
        }
        let held = std::mem::take(&mut self.held);
        for (_, (object, _)) in held {
            self.deliver(object, Path::Relay);
        }
    }

    fn deliver(&mut self, object: Object, path: Path) {
        let key = key(&object);
        if !self.delivered.insert(key) {
            return;
        }
        self.delivered_order.push_back(key);
        while self.delivered_order.len() > REMEMBERED {
            if let Some(old) = self.delivered_order.pop_front() {
                self.delivered.remove(&old);
            }
        }
        self.ready.push_back(Delivery { object, path });
    }
}

fn key(object: &Object) -> Key {
    (object.group.get(), object.object)
}

async fn next_or_pending(direct: Option<&mut Subscription>) -> Result<Option<Object>, Error> {
    match direct {
        Some(direct) => direct.next_object().await,
        None => std::future::pending().await,
    }
}

async fn sleep_until_or_pending(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}
