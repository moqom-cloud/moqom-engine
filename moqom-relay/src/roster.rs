//! Who is connected, and how to get rid of them.
//!
//! Every other shared thing in this relay is keyed by what sessions are *doing*
//! — a namespace they announced, a track they pull, a bucket they are charged
//! against. This one is keyed by the sessions themselves, and it exists for two
//! reasons neither of the others can serve.
//!
//! The first is that the control plane needs to be told who is in a room, and a
//! relay that only remembers announcements can answer that question for
//! publishers and not for the audience, which is almost everybody.
//!
//! The second is ejection. A ban is a row in somebody's database until a
//! connection closes, and closing it means reaching a session from outside its
//! own task. Nothing else here can: a session is otherwise reachable only by
//! [`Command`](crate::fabric::Command) on a channel it drains itself, which is
//! exactly the wrong mechanism for "stop draining that channel".
//!
//! # Why this holds a transport handle when the metrics deliberately do not
//!
//! [`crate::metrics`] keeps a record per live session and explicitly refuses to
//! keep the connection with it, because a diagnostic surface that pins file
//! descriptors turns a monitoring endpoint into a resource leak. The rule is
//! right and this is the exception that proves what it is for: a handle held so
//! it can be *closed* is the opposite of a handle held so it can be read, and
//! dropping the record is what releases it either way.
//!
//! # Only the sessions the control plane can name
//!
//! A session with no verified room is not enrolled at all. Not an oversight: the
//! control plane routes everything — snapshots, bans, ejections — by tenant and
//! room, so a session that cannot be named in those terms is one it has nothing
//! to say about. On a relay with no keys configured that is every session, which
//! is the correct amount of reporting from a relay that authorises nothing.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use tokio::sync::mpsc;

use crate::fabric::{Command, SessionId};
use crate::policy::Silence;
use crate::scope::{Publish, Scope, capability};

/// Something that can be hung up on.
///
/// A trait rather than the transport itself for one reason, and it is not
/// abstraction for its own sake: ejection is the behaviour most worth testing
/// here and a `moqom_transport::Session` cannot be built without a socket and a
/// peer. With this, a test asserts that the right people were closed and why,
/// which is the part that has to be right.
pub trait Closes: Send + Sync {
    /// Close the connection, with a MOQT application error code and a reason.
    fn close(&self, code: u32, reason: &[u8]);
}

impl Closes for moqom_transport::Session {
    fn close(&self, code: u32, reason: &[u8]) {
        moqom_transport::Session::close(self, code, reason);
    }
}

/// One live session, as somebody who is not it would describe it.
pub struct Presence {
    /// This relay's own handle on the session.
    pub id: SessionId,
    /// The customer.
    pub tenant: Arc<str>,
    /// The room. A session without one is never enrolled — see the module docs.
    pub room: Arc<str>,
    /// The person.
    pub user: Arc<str>,
    /// Which of their devices.
    pub device: Arc<str>,
    /// What they may publish.
    pub publish: Publish,
    /// Their moderation powers, as the token minted them.
    pub capabilities: u32,
    /// Whether they own the room.
    pub owner: bool,
    /// Whether they are waiting to go live rather than live.
    pub backstage: bool,
    /// Where they connected from, for address bans and abuse investigation.
    pub address: IpAddr,
    /// When they finished the handshake.
    pub opened: SystemTime,
    /// Whose following brought them, from the token's `via` claim.
    pub via: Option<Arc<str>>,

    /// The connection, held only so it can be closed.
    transport: Arc<dyn Closes>,

    /// This session's own command loop.
    ///
    /// The exception to the paragraph above about ejection. Closing a session
    /// cannot go through a channel the session drains, but restricting one
    /// must: stopping a track and telling its publisher why are things only
    /// that session can do, on its own connection, and this is how a directive
    /// arriving on the control-plane link reaches it.
    commands: mpsc::Sender<Command>,

    /// Set when this relay closed the session on somebody's instruction.
    ///
    /// Read at teardown, where the difference between "ejected" and "the
    /// connection dropped" is otherwise unrecoverable: both arrive as a session
    /// task returning a transport error, and reporting an ejection as a network
    /// failure would have the control plane hold a place open for somebody it
    /// just threw out.
    ejected: AtomicBool,
}

/// Who and where, which is all a log line wants. The connection is a handle and
/// prints as nothing useful.
impl std::fmt::Debug for Presence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Presence")
            .field("id", &self.id)
            .field("tenant", &self.tenant)
            .field("room", &self.room)
            .field("user", &self.user)
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

impl Presence {
    /// Whether this session was closed on instruction rather than by accident.
    #[must_use]
    pub fn was_ejected(&self) -> bool {
        self.ejected.load(Ordering::Relaxed)
    }

    /// Whether this session runs the room rather than merely appearing in it.
    ///
    /// The one distinction an audience-only mute turns on: a host or cohost
    /// keeps receiving what the audience no longer does. Stage powers count
    /// because force-muting is one of them, and somebody trusted to impose a
    /// mute is trusted to hear through it.
    #[must_use]
    pub const fn privileged(&self) -> bool {
        self.owner || self.capabilities & (capability::STAGE | capability::ROOM) != 0
    }

    /// Whether this is `username`, and `device` if one was named.
    ///
    /// An empty device matches every device that person is signed in on, which
    /// is what a kick usually means and what the control plane's
    /// `ParticipantRef` says by leaving the field out.
    #[must_use]
    pub fn is(&self, username: &str, device: &str) -> bool {
        &*self.user == username && (device.is_empty() || &*self.device == device)
    }

    /// Close this session, saying why in the connection's close reason.
    ///
    /// Returns without waiting: closing a QUIC connection is a datagram and a
    /// state change, and the session's own task finds out by its next read
    /// failing. Blocking here would make one unreachable peer delay a directive
    /// aimed at everybody else in the room.
    pub fn eject(&self, code: u32, reason: &str) {
        self.ejected.store(true, Ordering::Relaxed);
        self.transport.close(code, reason.as_bytes());
    }

    /// Tell this session what it may no longer publish.
    ///
    /// Returns whether the instruction was handed over, which is not whether
    /// the camera is off: what happens next is a stream to a phone, and a
    /// directive result that waited for it would hold the control plane's link
    /// open for as long as one bad connection took to fail.
    ///
    /// A full queue is a session already being asked to do 32 things, which in
    /// practice is one that has stopped draining — so the restriction is
    /// dropped rather than blocking the link, and said out loud. The policy
    /// still holds it: nobody will be allowed to subscribe to the tracks it
    /// names, whatever the phone does.
    pub fn restrict(&self, silence: Silence) -> bool {
        match self.commands.try_send(Command::Restrict { silence }) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(
                    session = %self.id,
                    user = %self.user,
                    error = %e,
                    "could not hand a mute to its session"
                );
                false
            }
        }
    }
}

/// Why a session is no longer here.
///
/// Mirrors the control plane's `SessionClosed.Cause`, and kept as a relay type
/// rather than the generated one so that the roster owes nothing to protobuf —
/// which is what lets it be tested without a control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Departure {
    /// The peer said goodbye.
    Clean,
    /// The connection failed. They may be back inside the reconnect window, so
    /// this is not a departure yet as far as the room is concerned.
    Lost,
    /// This relay closed them on the control plane's instruction.
    Ejected,
    /// They asked for something the protocol forbids.
    Protocol,
    /// The relay is going away.
    Shutdown,
}

/// Something the roster wants whoever is reporting upstream to know.
#[derive(Debug)]
pub enum Note {
    /// Somebody finished a handshake.
    Arrived(Arc<Presence>),
    /// Somebody's session ended.
    Left {
        /// Which session.
        id: SessionId,
        /// Where they were, so a reporter need not have kept the presence.
        tenant: Arc<str>,
        /// The room they were in.
        room: Arc<str>,
        /// Why they are gone.
        why: Departure,
    },
}

/// Everybody connected to this relay who can be named in a room.
///
/// Cheap to clone; all clones see the same sessions.
#[derive(Debug, Clone, Default)]
pub struct Roster {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug, Default)]
struct Inner {
    sessions: HashMap<SessionId, Arc<Presence>>,
    /// Where changes are reported, when anything is listening.
    ///
    /// One consumer rather than a broadcast, and unbounded rather than
    /// buffered. Both follow from what is being sent: a lost departure leaves
    /// the control plane believing in somebody who is not there, and the only
    /// thing that would ever repair it is the next reattach. A queue that can
    /// drop is therefore worse than a queue that can grow, and the growth is
    /// bounded by the connection rate of one relay.
    reports: Option<mpsc::UnboundedSender<Note>>,
}

impl Roster {
    /// An empty roster that nobody is listening to.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Start receiving changes, replacing any previous listener.
    ///
    /// Replacing rather than adding, because there is exactly one thing that
    /// reports upstream and a second one would double every join the control
    /// plane sees.
    #[must_use]
    pub fn listen(&self) -> mpsc::UnboundedReceiver<Note> {
        let (sender, receiver) = mpsc::unbounded_channel();
        self.lock().reports = Some(sender);
        receiver
    }

    /// Enrol a session that has completed its handshake.
    ///
    /// Returns the presence for the caller to keep, or `None` for a session the
    /// control plane could not name — no verified scope, or a scope with no
    /// room.
    pub fn admit(
        &self,
        id: SessionId,
        scope: &Scope,
        address: IpAddr,
        via: Option<Arc<str>>,
        transport: Arc<dyn Closes>,
        commands: mpsc::Sender<Command>,
    ) -> Option<Arc<Presence>> {
        let room = scope.room.clone()?;
        let presence = Arc::new(Presence {
            id,
            tenant: scope.tenant.clone(),
            room,
            user: scope.user.clone(),
            device: scope.device.clone(),
            publish: scope.publish,
            capabilities: scope.capabilities,
            owner: scope.owner,
            backstage: scope.backstage,
            address,
            opened: SystemTime::now(),
            via,
            transport,
            commands,
            ejected: AtomicBool::new(false),
        });

        let mut inner = self.lock();
        inner.sessions.insert(id, Arc::clone(&presence));
        if let Some(reports) = &inner.reports {
            let _ = reports.send(Note::Arrived(Arc::clone(&presence)));
        }
        Some(presence)
    }

    /// Remove a session that has ended, saying why.
    ///
    /// `why` is what the session's own outcome says, and is overridden by
    /// [`Departure::Ejected`] when this relay was the one that closed it: the
    /// transport error a session sees after being ejected is indistinguishable
    /// from one caused by a tunnel, and only this side knows the difference.
    pub fn release(&self, id: SessionId, why: Departure) {
        let mut inner = self.lock();
        let Some(presence) = inner.sessions.remove(&id) else {
            return;
        };
        let why = if presence.was_ejected() {
            Departure::Ejected
        } else {
            why
        };
        if let Some(reports) = &inner.reports {
            let _ = reports.send(Note::Left {
                id,
                tenant: Arc::clone(&presence.tenant),
                room: Arc::clone(&presence.room),
                why,
            });
        }
    }

    /// One session, if it is still here.
    ///
    /// For deciding what a *subscriber* is entitled to, which is a question
    /// asked on the publisher's session about somebody else's — the fan-out
    /// knows a route's [`SessionId`] and nothing more about who is on the end
    /// of it.
    #[must_use]
    pub fn find(&self, id: SessionId) -> Option<Arc<Presence>> {
        self.lock().sessions.get(&id).map(Arc::clone)
    }

    /// Everybody here, for the hello that reattaches a broken link.
    #[must_use]
    pub fn everybody(&self) -> Vec<Arc<Presence>> {
        self.lock().sessions.values().map(Arc::clone).collect()
    }

    /// Everybody in one room.
    #[must_use]
    pub fn in_room(&self, tenant: &str, room: &str) -> Vec<Arc<Presence>> {
        self.lock()
            .sessions
            .values()
            .filter(|p| &*p.tenant == tenant && &*p.room == room)
            .map(Arc::clone)
            .collect()
    }

    /// Every room this relay is serving, as (tenant, room).
    ///
    /// What the periodic snapshot pull iterates. Deduplicated here rather than
    /// by the caller because a room with forty people in it is one room to ask
    /// about, and asking forty times is how a poll becomes a load test.
    #[must_use]
    pub fn rooms(&self) -> Vec<(Arc<str>, Arc<str>)> {
        let inner = self.lock();
        let mut rooms: Vec<(Arc<str>, Arc<str>)> = inner
            .sessions
            .values()
            .map(|p| (Arc::clone(&p.tenant), Arc::clone(&p.room)))
            .collect();
        rooms.sort_unstable_by(|a, b| (&*a.0, &*a.1).cmp(&(&*b.0, &*b.1)));
        rooms.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
        rooms
    }

    /// How many sessions are here.
    #[must_use]
    pub fn count(&self) -> usize {
        self.lock().sessions.len()
    }

    /// How many sessions one room holds, for the participant ceiling.
    #[must_use]
    pub fn occupancy(&self, tenant: &str, room: &str) -> usize {
        self.lock()
            .sessions
            .values()
            .filter(|p| &*p.tenant == tenant && &*p.room == room)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Fabric;
    use std::net::Ipv4Addr;

    /// A connection that records being closed instead of having a peer.
    #[derive(Debug, Default)]
    struct Hangup {
        closed: Mutex<Vec<(u32, String)>>,
    }

    impl Closes for Hangup {
        fn close(&self, code: u32, reason: &[u8]) {
            self.closed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((code, String::from_utf8_lossy(reason).into_owned()));
        }
    }

    fn scope(user: &str, room: Option<&str>) -> Scope {
        Scope {
            tenant: "acme".into(),
            user: user.into(),
            device: "phone".into(),
            room: room.map(Into::into),
            publish: Publish::AUDIO,
            capabilities: 0,
            owner: false,
            backstage: false,
        }
    }

    fn address() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))
    }

    fn enrol(
        roster: &Roster,
        id: SessionId,
        user: &str,
        room: Option<&str>,
    ) -> Option<Arc<Presence>> {
        // The queue is dropped, which is right for every test here but the one
        // about restricting: that one builds its own so there is somebody to
        // receive.
        let (commands, _queue) = mpsc::channel(4);
        roster.admit(
            id,
            &scope(user, room),
            address(),
            None,
            Arc::new(Hangup::default()),
            commands,
        )
    }

    #[test]
    fn a_session_the_control_plane_cannot_name_is_not_enrolled() {
        let roster = Roster::new();
        let ids = Fabric::new();
        assert!(enrol(&roster, ids.next_session_id(), "ada", None).is_none());
        assert_eq!(roster.count(), 0);
        assert!(enrol(&roster, ids.next_session_id(), "ada", Some("r1")).is_some());
        assert_eq!(roster.count(), 1);
    }

    #[test]
    fn rooms_are_listed_once_however_many_people_are_in_them() {
        let roster = Roster::new();
        let ids = Fabric::new();
        enrol(&roster, ids.next_session_id(), "ada", Some("r1"));
        enrol(&roster, ids.next_session_id(), "bea", Some("r1"));
        enrol(&roster, ids.next_session_id(), "cy", Some("r2"));

        assert_eq!(roster.rooms().len(), 2);
        assert_eq!(roster.occupancy("acme", "r1"), 2);
        assert_eq!(roster.count(), 3);
    }

    #[test]
    fn leaving_is_reported_once_and_only_for_somebody_who_was_here() {
        let roster = Roster::new();
        let mut notes = roster.listen();
        let id = Fabric::new().next_session_id();
        enrol(&roster, id, "ada", Some("r1"));
        assert!(matches!(notes.try_recv(), Ok(Note::Arrived(_))));

        roster.release(id, Departure::Clean);
        assert!(matches!(
            notes.try_recv(),
            Ok(Note::Left {
                why: Departure::Clean,
                ..
            })
        ));

        // And again, for somebody the roster has already let go of.
        roster.release(id, Departure::Clean);
        assert!(notes.try_recv().is_err());
    }

    #[test]
    fn an_ejected_session_is_not_reported_as_a_dropped_connection() {
        let roster = Roster::new();
        let mut notes = roster.listen();
        let id = Fabric::new().next_session_id();
        let presence = enrol(&roster, id, "ada", Some("r1")).expect("enrolled");
        let _ = notes.try_recv();

        presence.eject(0x03, "banned");

        // The session's own task reports what it saw, which is a dead socket.
        roster.release(id, Departure::Lost);

        assert!(matches!(
            notes.try_recv(),
            Ok(Note::Left {
                why: Departure::Ejected,
                ..
            })
        ));
    }

    #[test]
    fn a_restriction_is_handed_to_the_session_that_must_carry_it_out() {
        let roster = Roster::new();
        let id = Fabric::new().next_session_id();
        let (commands, mut queue) = mpsc::channel(4);
        let presence = roster
            .admit(
                id,
                &scope("ada", Some("r1")),
                address(),
                None,
                Arc::new(Hangup::default()),
                commands,
            )
            .expect("enrolled");

        let silence = Silence {
            everyone: crate::media::Kinds::VIDEO,
            audience: crate::media::Kinds::NONE,
        };
        assert!(presence.restrict(silence));
        match queue.try_recv() {
            Ok(Command::Restrict { silence: got }) => assert_eq!(got, silence),
            other => panic!("expected a restriction, got {other:?}"),
        }

        // A session nobody is draining is reported rather than waited for.
        drop(queue);
        assert!(!presence.restrict(silence));
    }

    #[test]
    fn only_the_people_running_the_room_hear_through_an_audience_mute() {
        let roster = Roster::new();
        let ids = Fabric::new();
        let (commands, _queue) = mpsc::channel(4);
        let mut host = scope("ada", Some("r1"));
        host.capabilities = capability::STAGE;
        let host = roster
            .admit(
                ids.next_session_id(),
                &host,
                address(),
                None,
                Arc::new(Hangup::default()),
                commands,
            )
            .expect("enrolled");
        let viewer = enrol(&roster, ids.next_session_id(), "bea", Some("r1")).expect("enrolled");

        assert!(host.privileged());
        assert!(!viewer.privileged());
        assert_eq!(roster.find(host.id).map(|found| found.id), Some(host.id));
    }

    #[test]
    fn a_kick_without_a_device_reaches_every_device() {
        let roster = Roster::new();
        let id = Fabric::new().next_session_id();
        let presence = enrol(&roster, id, "ada", Some("r1")).expect("enrolled");
        assert!(presence.is("ada", ""));
        assert!(presence.is("ada", "phone"));
        assert!(!presence.is("ada", "laptop"));
        assert!(!presence.is("bea", ""));
    }
}
