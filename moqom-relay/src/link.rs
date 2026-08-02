//! The stream to the control plane.
//!
//! One bidirectional gRPC call, held open for as long as the relay runs. Up it
//! go the sessions this relay is serving; down come the rooms' policy and the
//! directives that act on people already connected. It is the only thing in this
//! process that speaks anything other than MOQT, and it is deliberately nowhere
//! near the media path — see [`crate::policy`] for why a handshake never asks
//! anybody anything.
//!
//! # Why the relay dials out
//!
//! The obvious arrangement is the other one: the control plane keeps a registry
//! of relays and calls whichever holds the session. Both reasons for rejecting
//! it are operational. Relays run behind a UDP load balancer and the control
//! plane runs on Cloud Run, so outbound is a URL and inbound is a second
//! ingress, a second certificate, and a firewall rule per instance. And a relay
//! that has lost the control plane finds out immediately, because its own stream
//! broke; in the other direction it would learn nothing and keep serving a room
//! whose bans it can no longer receive.
//!
//! # What this will not do
//!
//! Mutes and grant overrides arrive and are refused, out loud, with the reason
//! travelling back in the `DirectiveResult` so a moderator's tool says "not
//! enforced" rather than "done". Neither is implementable without the relay
//! filtering a live track by media kind, which is a change to the forwarding
//! path rather than to this file. Reporting them as carried out would be worse
//! than refusing them: a force-mute that silently does nothing is how somebody
//! keeps talking over a moderator who has been told they are muted.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::fabric::Fabric;
use crate::generated::admin::v1 as admin;
use crate::generated::relay::v1 as pb;
use crate::policy::{self, Banned, Rules};
use crate::roster::{Departure, Note, Presence};
use crate::session::code;

/// How often the relay says it is still here.
///
/// Not a liveness check in either direction — a broken gRPC stream is noticed by
/// both ends without one. It carries the session count, which is what a director
/// steering new sessions between relays will want, and it keeps intermediaries
/// from timing out an idle HTTP/2 stream, which is the failure this actually
/// prevents in a deployment behind a load balancer.
const HEARTBEAT: Duration = Duration::from_secs(15);

/// How long to keep serving new sessions after losing the control plane, until
/// a `Welcome` says otherwise.
const DEFAULT_GRACE: Duration = Duration::from_mins(5);

/// The first and longest waits between reconnection attempts.
const FIRST_RETRY: Duration = Duration::from_millis(250);
const LONGEST_RETRY: Duration = Duration::from_secs(30);

/// Where the control plane is and who this relay says it is.
#[derive(Debug, Clone)]
pub struct Supervisor {
    /// The control plane's URL, `https://…` in a deployment and `http://…` for
    /// a test.
    pub endpoint: String,
    /// The service account credential, sent as a bearer token. The control
    /// plane refuses the stream unless the account is marked as a relay.
    pub credential: String,
    /// This relay's identifier, stable across restarts of one instance so that
    /// the control plane can tell a restart from a new machine.
    pub relay_id: String,
    /// Where this relay is, for the director's steering decisions.
    pub region: String,
}

impl Supervisor {
    /// Read the deployment's configuration, or `None` if there is no control
    /// plane to attach to.
    ///
    /// Absent is a supported configuration and the one every bench runs in: a
    /// relay with no control plane authorises what its tokens say and enforces
    /// no bans, which is exactly what a two-phone latency rig needs and exactly
    /// what must not be exposed to anybody else.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let endpoint = std::env::var("MOQOM_CONTROL_ENDPOINT").ok()?;
        let credential = std::env::var("MOQOM_CONTROL_CREDENTIAL").unwrap_or_default();
        if credential.is_empty() {
            tracing::warn!(
                "MOQOM_CONTROL_ENDPOINT is set with no MOQOM_CONTROL_CREDENTIAL; \
                 the control plane will refuse the stream"
            );
        }
        Some(Self {
            endpoint,
            credential,
            relay_id: std::env::var("MOQOM_RELAY_ID").unwrap_or_else(|_| default_id()),
            region: std::env::var("MOQOM_RELAY_REGION").unwrap_or_default(),
        })
    }
}

/// An identifier for a relay whose deployment did not give it one.
///
/// The hostname, which in a managed instance group is the instance name and is
/// therefore stable across restarts of that instance — which is the property the
/// control plane needs of it. A random one would make every restart look like a
/// new machine and leave the old one's sessions to time out.
fn default_id() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "relay".to_owned())
}

/// The attached link, which stops when dropped.
#[derive(Debug)]
pub struct Link {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Link {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Link {
    /// Attach to the control plane and keep trying for as long as this lives.
    ///
    /// Returns immediately. Nothing about a relay's media path waits on this:
    /// the first sessions may well arrive before the first snapshot does, and
    /// they are admitted, because a room the control plane has not yet been told
    /// about cannot have had a ban issued for it.
    #[must_use]
    pub fn attach(supervisor: Supervisor, fabric: Fabric) -> Self {
        let notes = fabric.roster().listen();
        Self {
            task: tokio::spawn(async move { serve(supervisor, fabric, notes).await }),
        }
    }

    /// Stop trying.
    pub fn detach(self) {
        drop(self);
    }
}

/// Attach, run until the stream breaks, wait, attach again, forever.
async fn serve(supervisor: Supervisor, fabric: Fabric, mut notes: mpsc::UnboundedReceiver<Note>) {
    let mut grace = DEFAULT_GRACE;
    let mut wait = FIRST_RETRY;
    loop {
        match attached(&supervisor, &fabric, &mut notes, &mut grace).await {
            Ok(()) => {
                tracing::warn!("control plane closed the link");
                wait = FIRST_RETRY;
            }
            Err(e) => {
                tracing::warn!(error = %e, "control plane link failed");
            }
        }
        fabric.metrics().control_attached(false);
        // The grace clock starts here and is not restarted by the retries, so
        // the period means what it says however many attempts fit inside it.
        fabric.policy().detached(grace);

        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(LONGEST_RETRY);
    }
}

/// One attempt: connect, say hello, and pump until something breaks.
async fn attached(
    supervisor: &Supervisor,
    fabric: &Fabric,
    notes: &mut mpsc::UnboundedReceiver<Note>,
    grace: &mut Duration,
) -> Result<(), tonic::Status> {
    let channel = tonic::transport::Endpoint::from_shared(supervisor.endpoint.clone())
        .map_err(|e| tonic::Status::invalid_argument(format!("control endpoint: {e}")))?
        // Long-lived and mostly idle. Keepalive is what stops a load balancer
        // silently dropping the stream and leaving both ends believing in it.
        .http2_keep_alive_interval(HEARTBEAT)
        .keep_alive_timeout(Duration::from_secs(20))
        .connect()
        .await
        .map_err(|e| tonic::Status::unavailable(format!("control plane: {e}")))?;

    let mut client = pb::relay_link_client::RelayLinkClient::new(channel);

    let (outbound, sink) = mpsc::channel::<pb::RelayMessage>(64);

    // Anything queued while the link was down describes a world the control
    // plane is about to be told about wholesale. Sending it after the hello
    // would announce arrivals for sessions already in `existing` and departures
    // for sessions it has never heard of.
    while notes.try_recv().is_ok() {}

    let hello = pb::RelayMessage {
        body: Some(pb::relay_message::Body::Hello(pb::Hello {
            relay_id: supervisor.relay_id.clone(),
            region: supervisor.region.clone(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            existing: fabric
                .roster()
                .everybody()
                .iter()
                .map(|presence| state_of(presence))
                .collect(),
        })),
    };
    outbound
        .send(hello)
        .await
        .map_err(|_| tonic::Status::internal("link closed before hello"))?;

    let mut request = tonic::Request::new(ReceiverStream::new(sink));
    if !supervisor.credential.is_empty() {
        let bearer = format!("Bearer {}", supervisor.credential)
            .parse()
            .map_err(|_| tonic::Status::invalid_argument("credential is not a header value"))?;
        request.metadata_mut().insert("authorization", bearer);
    }
    let mut inbound = client.attach(request).await?.into_inner();

    tracing::info!(
        relay = %supervisor.relay_id,
        endpoint = %supervisor.endpoint,
        sessions = fabric.roster().count(),
        "attached to the control plane"
    );
    fabric.policy().attached();
    fabric.metrics().control_attached(true);

    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    heartbeat.tick().await;
    let mut snapshots: Option<tokio::time::Interval> = None;

    loop {
        let pull = async {
            match snapshots.as_mut() {
                Some(interval) => interval.tick().await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            message = inbound.message() => {
                let Some(message) = message? else { return Ok(()) };
                if let Some(reply) = react(fabric, message, grace, &mut snapshots) {
                    send(&outbound, reply)?;
                }
            }
            note = notes.recv() => {
                let Some(note) = note else {
                    // The roster has handed its reports to somebody else, which
                    // only happens if a second link attached. Leave rather than
                    // run beside it reporting nothing.
                    return Ok(());
                };
                send(&outbound, report(note))?;
            }
            _ = heartbeat.tick() => {
                send(&outbound, pb::RelayMessage {
                    body: Some(pb::relay_message::Body::Heartbeat(pb::Heartbeat {
                        at: Some(SystemTime::now().into()),
                        session_count: fabric.roster().count() as u32,
                        subscription_count: 0,
                    })),
                })?;
            }
            _ = pull => {
                for (tenant, room) in fabric.roster().rooms() {
                    send(&outbound, pb::RelayMessage {
                        body: Some(pb::relay_message::Body::SnapshotRequest(pb::SnapshotRequest {
                            tenant: tenant.to_string(),
                            room: room.to_string(),
                        })),
                    })?;
                }
            }
        }
    }
}

/// Put a message on the stream, or give up on this attempt.
///
/// A full queue is not a thing to wait out here: the sink is drained by the
/// HTTP/2 writer, so a queue that stays full for sixty-four messages is a peer
/// that has stopped reading, and blocking on it would stall the arm of the
/// `select!` that reads directives.
fn send(
    outbound: &mpsc::Sender<pb::RelayMessage>,
    message: pb::RelayMessage,
) -> Result<(), tonic::Status> {
    outbound
        .try_send(message)
        .map_err(|_| tonic::Status::unavailable("control plane is not reading"))
}

/// Turn a roster change into something to send.
fn report(note: Note) -> pb::RelayMessage {
    let body = match note {
        Note::Arrived(presence) => pb::relay_message::Body::SessionOpened(pb::SessionOpened {
            session: Some(state_of(&presence)),
        }),
        Note::Left { id, why, .. } => pb::relay_message::Body::SessionClosed(pb::SessionClosed {
            session_id: id.number().to_string(),
            cause: cause_of(why) as i32,
            at: Some(SystemTime::now().into()),
        }),
    };
    pb::RelayMessage { body: Some(body) }
}

/// Act on something the control plane said, and say how it went.
fn react(
    fabric: &Fabric,
    message: pb::ControlMessage,
    grace: &mut Duration,
    snapshots: &mut Option<tokio::time::Interval>,
) -> Option<pb::RelayMessage> {
    match message.body? {
        pb::control_message::Body::Welcome(welcome) => {
            if let Some(given) = welcome.grace.and_then(|d| Duration::try_from(d).ok()) {
                *grace = given;
            }
            // Zero means never, which is only correct where the control plane
            // runs as a single replica: with more than one, a directive written
            // by a replica this relay is not attached to arrives no other way.
            let interval = welcome
                .snapshot_interval
                .and_then(|d| Duration::try_from(d).ok())
                .filter(|d| !d.is_zero());
            // Starting one period out rather than now: an interval's first tick
            // fires immediately, and the snapshot for a room arrives unasked
            // when its first session is reported. Asking again in the same
            // breath would double every attach.
            *snapshots = interval.map(|period| {
                let mut ticker =
                    tokio::time::interval_at(tokio::time::Instant::now() + period, period);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                ticker
            });
            tracing::info!(
                grace_s = grace.as_secs(),
                snapshot_s = interval.map_or(0, |d| d.as_secs()),
                "control plane accepted this relay"
            );
            None
        }
        pb::control_message::Body::RoomSnapshot(snapshot) => {
            apply(fabric, &snapshot);
            None
        }
        pb::control_message::Body::Directive(directive) => Some(pb::RelayMessage {
            body: Some(pb::relay_message::Body::DirectiveResult(carry_out(
                fabric, directive,
            ))),
        }),
        pb::control_message::Body::VerificationKeys(keys) => {
            // Not applied, and this is a real gap rather than a formality: a
            // relay whose keys come from its own configuration cannot follow a
            // rotation the control plane performs, so the retiring key must stay
            // in `MOQOM_RELAY_JWKS` until the last token it signed expires.
            // Logged so that a rotation is at least visible from here.
            tracing::warn!(
                keys = keys.keys.len(),
                "control plane pushed verification keys; this relay uses its configured JWKS"
            );
            None
        }
    }
}

/// Replace what is known about a room, and act on anybody it now excludes.
fn apply(fabric: &Fabric, snapshot: &pb::RoomSnapshot) {
    let room: policy::Where = (
        Arc::from(snapshot.tenant.as_str()),
        Arc::from(snapshot.room.as_str()),
    );
    let mut bans = Vec::with_capacity(snapshot.bans.len());
    for ban in &snapshot.bans {
        match translate(ban) {
            Some(ban) => bans.push(ban),
            None => fabric.policy().unreadable(),
        }
    }
    if !snapshot.mutes.is_empty() || !snapshot.grant_overrides.is_empty() {
        // Said once per snapshot rather than silently dropped. Both are state
        // this relay cannot act on yet, and a room whose mutes are in every
        // snapshot and enforced by nobody is worth a line in the log.
        tracing::warn!(
            tenant = %snapshot.tenant,
            room = %snapshot.room,
            mutes = snapshot.mutes.len(),
            overrides = snapshot.grant_overrides.len(),
            "snapshot carries state this relay does not enforce"
        );
    }

    fabric.policy().describe(
        room.clone(),
        Rules {
            closed: snapshot.closed,
            bans,
            ceiling: snapshot.max_participants,
        },
    );

    // A snapshot is also how a ban reaches a relay that was not attached when it
    // was issued, so it has to act on the room and not merely remember it.
    let caught = sweep(fabric, &room, "banned");
    let closed = if snapshot.closed {
        clear(fabric, &room, "room closed")
    } else {
        0
    };
    if caught + closed > 0 {
        tracing::info!(
            tenant = %snapshot.tenant,
            room = %snapshot.room,
            sessions = caught + closed,
            "snapshot ejected sessions"
        );
    }
}

/// Close every session in `room` that the policy now refuses.
fn sweep(fabric: &Fabric, room: &policy::Where, reason: &str) -> u32 {
    let mut ejected = 0;
    for presence in fabric.roster().in_room(&room.0, &room.1) {
        if fabric
            .policy()
            .catches(room, &presence.user, &presence.device, presence.address)
        {
            presence.eject(code::UNAUTHORIZED, reason);
            ejected += 1;
        }
    }
    fabric.metrics().ejected(u64::from(ejected));
    ejected
}

/// Close every session in `room`.
fn clear(fabric: &Fabric, room: &policy::Where, reason: &str) -> u32 {
    let everybody = fabric.roster().in_room(&room.0, &room.1);
    for presence in &everybody {
        presence.eject(code::UNAUTHORIZED, reason);
    }
    let ejected = everybody.len() as u32;
    fabric.metrics().ejected(u64::from(ejected));
    ejected
}

/// Do what a directive says, and report how many sessions it reached.
fn carry_out(fabric: &Fabric, directive: pb::Directive) -> pb::DirectiveResult {
    let id = directive.directive_id.clone();
    let room: policy::Where = (
        Arc::from(directive.tenant.as_str()),
        Arc::from(directive.room.as_str()),
    );

    let (action, affected, error) = match directive.action {
        Some(pb::directive::Action::Eject(eject)) => {
            let target = eject.target.unwrap_or_default();
            let mut count = 0;
            for presence in fabric.roster().in_room(&room.0, &room.1) {
                if presence.is(&target.username, &target.device) {
                    presence.eject(code::UNAUTHORIZED, &reason_for(eject.code));
                    count += 1;
                }
            }
            fabric.metrics().ejected(u64::from(count));
            ("eject", count, String::new())
        }
        Some(pb::directive::Action::UpdateBan(update)) => {
            let Some(ban) = update.ban.as_ref().and_then(translate) else {
                fabric.policy().unreadable();
                return refused(id, "this relay could not read that ban");
            };
            fabric.policy().revise(room.clone(), ban, update.active);
            // A ban on somebody already connected is the case this whole link
            // exists for. The control plane also sends an eject for most of
            // them, and the two agreeing is harmless: a session closed twice is
            // closed once.
            let count = if update.active {
                sweep(fabric, &room, "banned")
            } else {
                0
            };
            ("ban", count, String::new())
        }
        Some(pb::directive::Action::CloseRoom(close)) => {
            fabric.policy().close(room.clone(), true);
            let count = clear(fabric, &room, &reason_for(close.code));
            ("close_room", count, String::new())
        }
        Some(pb::directive::Action::ApplyMute(_)) => {
            return refused(
                id,
                "this relay does not enforce mutes: it forwards a publisher's tracks or none",
            );
        }
        Some(pb::directive::Action::ApplyGrants(_)) => {
            return refused(
                id,
                "this relay does not override token grants: a demotion takes effect on reissue",
            );
        }
        None => return refused(id, "directive named no action"),
    };

    fabric.metrics().directive(action);
    tracing::info!(
        directive = %id,
        action,
        tenant = %directive.tenant,
        room = %directive.room,
        sessions = affected,
        "directive carried out"
    );
    pb::DirectiveResult {
        directive_id: id,
        affected_sessions: affected,
        error,
    }
}

/// A directive this relay will not pretend to have carried out.
fn refused(id: String, why: &str) -> pb::DirectiveResult {
    tracing::warn!(directive = %id, why, "directive refused");
    pb::DirectiveResult {
        directive_id: id,
        affected_sessions: 0,
        error: why.to_owned(),
    }
}

/// What to tell a client whose connection is being closed under them.
///
/// The code travels in the close reason so the app can say something true
/// before the picture goes dark. A stream that merely stops is
/// indistinguishable from a crash, and the support ticket that follows costs
/// more than the string does.
fn reason_for(code: i32) -> String {
    admin::ModerationCode::try_from(code).map_or_else(
        |_| "moderation".to_owned(),
        |code| code.as_str_name().to_ascii_lowercase(),
    )
}

/// A ban as the policy understands it, or `None` for one this build cannot read.
fn translate(ban: &pb::Ban) -> Option<policy::Ban> {
    let who = match ban.key.as_ref()? {
        pb::ban::Key::Username(username) => Banned::User(username.clone()),
        pb::ban::Key::Device(identity) => Banned::Device {
            user: identity.username.clone(),
            device: identity.device.clone(),
        },
        pb::ban::Key::IpPrefix(prefix) => Banned::address(prefix)?,
    };
    Some(policy::Ban {
        who,
        until: ban.expires_at.and_then(|at| SystemTime::try_from(at).ok()),
    })
}

/// One session, in the control plane's terms.
fn state_of(presence: &Presence) -> pb::SessionState {
    pb::SessionState {
        session_id: presence.id.number().to_string(),
        tenant: presence.tenant.to_string(),
        room: presence.room.to_string(),
        identity: Some(admin::Identity {
            username: presence.user.to_string(),
            device: presence.device.to_string(),
        }),
        grants: Some(admin::Grants {
            publish: publishing(presence),
            moderation: moderation(presence.capabilities),
            is_owner: presence.owner,
        }),
        backstage: presence.backstage,
        remote_address: presence.address.to_string(),
        opened_at: Some(presence.opened.into()),
        // Deliberately unset. The field says the relay closes the session when
        // the token expires, and this relay does not: a session is authorised at
        // setup and runs until it ends. Sending an expiry would be a promise
        // about behaviour that does not exist, and the control plane would have
        // no way to tell.
        token_expires_at: None,
        arrived_via: presence.via.as_deref().unwrap_or_default().to_owned(),
    }
}

/// The media kinds a session may publish, as the admin API enumerates them.
fn publishing(presence: &Presence) -> Vec<i32> {
    use crate::scope::Publish;
    let mut kinds = Vec::new();
    for (bit, scope) in [
        (Publish::AUDIO, admin::PublishScope::Audio),
        (Publish::VIDEO, admin::PublishScope::Video),
        (Publish::SCREEN, admin::PublishScope::ScreenShare),
        (Publish::DATA, admin::PublishScope::Data),
    ] {
        if presence.publish.has(bit) {
            kinds.push(scope as i32);
        }
    }
    kinds
}

/// Which bit of a token's capability mask means which moderation power.
///
/// The positions are protocol — the same numbers appear in `control.Capability`
/// in Go and in `Capability.rawValue` in `MoqomKit` — and the enum numbers beside
/// them are not, which is exactly why this table has to exist and be written out
/// rather than derived. A relay that got it wrong would report a moderator to
/// the control plane as holding somebody else's powers, and the admin API would
/// show it.
const CAPABILITIES: [(u32, admin::Capability); 21] = [
    (1 << 0, admin::Capability::DeleteMessage),
    (1 << 1, admin::Capability::TimeoutUser),
    (1 << 2, admin::Capability::BanFromChat),
    (1 << 3, admin::Capability::SetChatMode),
    (1 << 4, admin::Capability::ManageFilters),
    (1 << 8, admin::Capability::PromoteToGuest),
    (1 << 9, admin::Capability::PromoteToCohost),
    (1 << 10, admin::Capability::Demote),
    (1 << 11, admin::Capability::ForceMute),
    (1 << 12, admin::Capability::Spotlight),
    (1 << 13, admin::Capability::ManageQueue),
    (1 << 14, admin::Capability::LockStage),
    (1 << 16, admin::Capability::Kick),
    (1 << 17, admin::Capability::BanFromRoom),
    (1 << 18, admin::Capability::BanFromTenant),
    (1 << 19, admin::Capability::CloseRoom),
    (1 << 20, admin::Capability::ChangeRoomPolicy),
    (1 << 21, admin::Capability::ManageWatchdogs),
    (1 << 24, admin::Capability::AppointModerators),
    (1 << 25, admin::Capability::ReadModerationLog),
    (1 << 26, admin::Capability::HandleAppeals),
];

/// The powers a mask names, dropping any bit this build does not know.
///
/// Dropping is right here and would be wrong in the verifier: [`crate::scope`]
/// refuses a token carrying an unknown capability, because a bit it cannot read
/// might be a power it is failing to enforce. By the time a session is on the
/// roster that decision has been made, and this is only describing it.
fn moderation(mask: u32) -> Vec<i32> {
    CAPABILITIES
        .iter()
        .filter(|(bit, _)| mask & bit != 0)
        .map(|&(_, capability)| capability as i32)
        .collect()
}

/// Why a session ended, in the control plane's terms.
const fn cause_of(why: Departure) -> pb::session_closed::Cause {
    match why {
        Departure::Clean => pb::session_closed::Cause::ClientClosed,
        Departure::Lost => pb::session_closed::Cause::TransportLost,
        Departure::Ejected => pb::session_closed::Cause::Ejected,
        Departure::Protocol => pb::session_closed::Cause::ProtocolViolation,
        Departure::Shutdown => pb::session_closed::Cause::RelayShutdown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Refusal;
    use crate::roster::Closes;
    use crate::scope::{Publish, Scope};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Mutex;
    use tokio::sync::mpsc::error::TryRecvError;

    /// How long a test waits for something that should be immediate.
    const PATIENCE: Duration = Duration::from_secs(10);

    /// A control plane that records what a relay says and replies to order.
    ///
    /// A real gRPC server on a loopback port rather than a mock of the client,
    /// because most of what this module does is stream handling: the interesting
    /// failures are a stream that breaks mid-life, a reattach that reports the
    /// wrong sessions, and a peer that stops reading. None of them exist in a
    /// test that calls the handlers directly.
    #[derive(Clone, Default)]
    struct FakeControl {
        heard: Arc<Mutex<Vec<pb::RelayMessage>>>,
        said: Arc<Mutex<Vec<pb::ControlMessage>>>,
        /// Raised to end every open stream, which is what a control plane
        /// restarting looks like from a relay.
        hangups: Arc<tokio::sync::Notify>,
    }

    impl FakeControl {
        /// Say this to the next relay that attaches, after the welcome.
        fn will_say(&self, message: pb::ControlMessage) {
            self.said
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(message);
        }

        fn everything_heard(&self) -> Vec<pb::RelayMessage> {
            self.heard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        /// Wait until something the relay sent satisfies `want`.
        async fn hears(
            &self,
            what: &str,
            want: impl Fn(&pb::RelayMessage) -> bool,
        ) -> pb::RelayMessage {
            let found = tokio::time::timeout(PATIENCE, async {
                loop {
                    if let Some(message) = self.everything_heard().into_iter().find(&want) {
                        return message;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await;
            found.unwrap_or_else(|_| panic!("timed out waiting for {what}"))
        }

        /// Start serving on a loopback port.
        async fn start(&self) -> Serving {
            let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .expect("a loopback port");
            let addr = listener.local_addr().expect("a bound address");
            Serving {
                task: self.serve(listener),
                addr,
            }
        }

        fn serve(&self, listener: tokio::net::TcpListener) -> tokio::task::JoinHandle<()> {
            let service = pb::relay_link_server::RelayLinkServer::new(self.clone());
            tokio::spawn(async move {
                let _ = tonic::transport::Server::builder()
                    .add_service(service)
                    .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                    .await;
            })
        }

        /// End every open stream, as a control plane restarting does.
        ///
        /// Better than killing the listener, which is what a first attempt at
        /// this test did: aborting the server leaves the established HTTP/2
        /// connection up, so the relay never notices and the test proves
        /// nothing.
        fn hang_up(&self) {
            self.hangups.notify_waiters();
        }

        /// Forget everything heard so far, for a test that wants to see what
        /// happens next rather than what happened before.
        fn forget(&self) {
            self.heard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
        }
    }

    /// A running fake control plane.
    struct Serving {
        task: tokio::task::JoinHandle<()>,
        addr: SocketAddr,
    }

    impl Serving {
        fn endpoint(&self) -> String {
            format!("http://{}", self.addr)
        }
    }

    impl Drop for Serving {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// An address with nothing listening on it.
    async fn nowhere() -> String {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("a loopback port");
        let addr = listener.local_addr().expect("a bound address");
        drop(listener);
        format!("http://{addr}")
    }

    /// Wait for something to become true, or fail the test saying what did not.
    async fn until(what: &str, check: impl Fn() -> bool) {
        tokio::time::timeout(PATIENCE, async {
            while !check() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
    }

    #[tonic::async_trait]
    impl pb::relay_link_server::RelayLink for FakeControl {
        type AttachStream = ReceiverStream<Result<pb::ControlMessage, tonic::Status>>;

        async fn attach(
            &self,
            request: tonic::Request<tonic::Streaming<pb::RelayMessage>>,
        ) -> Result<tonic::Response<Self::AttachStream>, tonic::Status> {
            let (down, downstream) = mpsc::channel(16);
            let mut up = request.into_inner();

            let welcome = pb::ControlMessage {
                body: Some(pb::control_message::Body::Welcome(pb::Welcome {
                    at: Some(SystemTime::now().into()),
                    grace: Some(prost_types::Duration {
                        seconds: 60,
                        nanos: 0,
                    }),
                    snapshot_interval: None,
                })),
            };

            let heard = Arc::clone(&self.heard);
            let said = Arc::clone(&self.said);
            let hangups = Arc::clone(&self.hangups);
            tokio::spawn(async move {
                // Everything queued for this attachment, once the relay is
                // listening. Ordered after the welcome because a relay that has
                // not been welcomed has no grace period to act on.
                let _ = down.send(Ok(welcome)).await;
                let queued: Vec<pb::ControlMessage> = std::mem::take(
                    &mut *said
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                );
                for message in queued {
                    let _ = down.send(Ok(message)).await;
                }

                loop {
                    tokio::select! {
                        () = hangups.notified() => return,
                        message = up.message() => match message {
                            Ok(Some(message)) => heard
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .push(message),
                            _ => return,
                        },
                    }
                }
            });

            Ok(tonic::Response::new(ReceiverStream::new(downstream)))
        }
    }

    /// A connection that records being closed instead of having a peer.
    #[derive(Debug, Default)]
    struct Hangup {
        closed: Mutex<Vec<String>>,
    }

    impl Hangup {
        fn was_closed(&self) -> bool {
            !self
                .closed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        }

        fn reason(&self) -> String {
            self.closed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .first()
                .cloned()
                .unwrap_or_default()
        }
    }

    impl Closes for Hangup {
        fn close(&self, _code: u32, reason: &[u8]) {
            self.closed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(String::from_utf8_lossy(reason).into_owned());
        }
    }

    fn scope(user: &str) -> Scope {
        Scope {
            tenant: "acme".into(),
            user: user.into(),
            device: "phone".into(),
            room: Some("r1".into()),
            publish: Publish::AUDIO,
            capabilities: 1 << 16,
            owner: false,
            backstage: false,
        }
    }

    fn address() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4))
    }

    /// Put somebody on the roster, and keep the handle that says whether they
    /// were hung up on.
    fn join(fabric: &Fabric, user: &str) -> Arc<Hangup> {
        let hangup = Arc::new(Hangup::default());
        fabric
            .roster()
            .admit(
                fabric.next_session_id(),
                &scope(user),
                address(),
                Some("bea".into()),
                Arc::clone(&hangup) as Arc<dyn Closes>,
            )
            .expect("a session in a room");
        hangup
    }

    fn supervisor(endpoint: String) -> Supervisor {
        Supervisor {
            endpoint,
            credential: "secret".to_owned(),
            relay_id: "relay-1".to_owned(),
            region: "us-west2".to_owned(),
        }
    }

    fn directive(action: pb::directive::Action) -> pb::ControlMessage {
        pb::ControlMessage {
            body: Some(pb::control_message::Body::Directive(pb::Directive {
                directive_id: "d-1".to_owned(),
                tenant: "acme".to_owned(),
                room: "r1".to_owned(),
                action: Some(action),
            })),
        }
    }

    fn is_opened(message: &pb::RelayMessage) -> bool {
        matches!(
            message.body,
            Some(pb::relay_message::Body::SessionOpened(_))
        )
    }

    fn result_of(message: &pb::RelayMessage) -> &pb::DirectiveResult {
        match &message.body {
            Some(pb::relay_message::Body::DirectiveResult(result)) => result,
            other => panic!("expected a directive result, got {other:?}"),
        }
    }

    fn is_result(message: &pb::RelayMessage) -> bool {
        matches!(
            message.body,
            Some(pb::relay_message::Body::DirectiveResult(_))
        )
    }

    #[tokio::test]
    async fn attaching_reports_who_is_already_here() {
        let control = FakeControl::default();
        let serving = control.start().await;
        let fabric = Fabric::observed(crate::Cache::default(), crate::Metrics::new());

        // Somebody joined before the link came up, which is every session on a
        // relay that restarted or lost its stream.
        join(&fabric, "ada");
        let _link = Link::attach(supervisor(serving.endpoint()), fabric.clone());

        let hello = control
            .hears("the hello", |m| {
                matches!(m.body, Some(pb::relay_message::Body::Hello(_)))
            })
            .await;
        let Some(pb::relay_message::Body::Hello(hello)) = hello.body else {
            unreachable!()
        };
        assert_eq!(hello.relay_id, "relay-1");
        assert_eq!(hello.region, "us-west2");
        assert_eq!(hello.existing.len(), 1);

        let session = &hello.existing[0];
        assert_eq!(session.tenant, "acme");
        assert_eq!(session.room, "r1");
        assert_eq!(session.identity.as_ref().expect("identity").username, "ada");
        assert_eq!(session.remote_address, "203.0.113.4");
        // The claim that is the whole point of carrying provenance this far.
        assert_eq!(session.arrived_via, "bea");
        let grants = session.grants.as_ref().expect("grants");
        assert_eq!(grants.publish, vec![admin::PublishScope::Audio as i32]);
        assert_eq!(grants.moderation, vec![admin::Capability::Kick as i32]);

        // And the relay now believes it is supervised.
        assert!(fabric.policy().supervised());
    }

    #[tokio::test]
    async fn arrivals_and_departures_are_reported_as_they_happen() {
        let control = FakeControl::default();
        let serving = control.start().await;
        let fabric = Fabric::new();
        let _link = Link::attach(supervisor(serving.endpoint()), fabric.clone());
        control
            .hears("the hello", |m| {
                matches!(m.body, Some(pb::relay_message::Body::Hello(_)))
            })
            .await;

        join(&fabric, "ada");
        let opened = control.hears("the arrival", is_opened).await;
        let Some(pb::relay_message::Body::SessionOpened(opened)) = opened.body else {
            unreachable!()
        };
        let id = opened.session.expect("a session").session_id;

        let ids: Vec<_> = fabric.roster().everybody().iter().map(|p| p.id).collect();
        fabric
            .roster()
            .release(ids[0], crate::roster::Departure::Lost);

        let closed = control
            .hears("the departure", |m| {
                matches!(m.body, Some(pb::relay_message::Body::SessionClosed(_)))
            })
            .await;
        let Some(pb::relay_message::Body::SessionClosed(closed)) = closed.body else {
            unreachable!()
        };
        assert_eq!(closed.session_id, id);
        // Lost rather than left: the participant may be back inside the
        // reconnect window, and the control plane holds their place on the
        // strength of this field.
        assert_eq!(
            closed.cause,
            pb::session_closed::Cause::TransportLost as i32
        );
    }

    /// The whole point of the link, in one test.
    #[tokio::test]
    async fn an_eject_closes_that_person_and_nobody_else() {
        let control = FakeControl::default();
        control.will_say(directive(pb::directive::Action::Eject(pb::Eject {
            target: Some(admin::ParticipantRef {
                username: "ada".to_owned(),
                device: String::new(),
            }),
            code: admin::ModerationCode::Harassment as i32,
        })));
        let serving = control.start().await;

        let fabric = Fabric::observed(crate::Cache::default(), crate::Metrics::new());
        let ada = join(&fabric, "ada");
        let bea = join(&fabric, "bea");
        let _link = Link::attach(supervisor(serving.endpoint()), fabric.clone());

        let result = control.hears("the directive result", is_result).await;
        let result = result_of(&result);
        assert_eq!(result.directive_id, "d-1");
        assert_eq!(result.affected_sessions, 1);
        assert_eq!(result.error, "");

        assert!(ada.was_closed(), "ada was ejected and is still connected");
        assert_eq!(ada.reason(), "moderation_code_harassment");
        assert!(!bea.was_closed(), "bea was not the one ejected");
    }

    #[tokio::test]
    async fn a_ban_closes_the_session_it_catches_and_keeps_them_out() {
        let control = FakeControl::default();
        control.will_say(directive(pb::directive::Action::UpdateBan(pb::UpdateBan {
            ban: Some(pb::Ban {
                key: Some(pb::ban::Key::Username("ada".to_owned())),
                expires_at: None,
                code: admin::ModerationCode::TenantPolicy as i32,
            }),
            active: true,
        })));
        let serving = control.start().await;

        let fabric = Fabric::new();
        let ada = join(&fabric, "ada");
        let _link = Link::attach(supervisor(serving.endpoint()), fabric.clone());

        let result = control.hears("the directive result", is_result).await;
        assert_eq!(result_of(&result).affected_sessions, 1);
        assert!(ada.was_closed());

        // And the ban outlives the connection it closed, which is what makes it
        // a ban rather than a kick.
        assert_eq!(
            fabric.policy().admits(&scope("ada"), address(), 0),
            Err(Refusal::Banned)
        );
        assert!(fabric.policy().admits(&scope("bea"), address(), 0).is_ok());
    }

    #[tokio::test]
    async fn a_snapshot_ejects_anybody_it_has_already_banned() {
        // The case a directive cannot cover: the ban was issued while this relay
        // was not attached, or by a control-plane replica it is not attached to.
        let control = FakeControl::default();
        control.will_say(pb::ControlMessage {
            body: Some(pb::control_message::Body::RoomSnapshot(pb::RoomSnapshot {
                tenant: "acme".to_owned(),
                room: "r1".to_owned(),
                closed: false,
                bans: vec![pb::Ban {
                    key: Some(pb::ban::Key::IpPrefix("203.0.113.0/24".to_owned())),
                    expires_at: None,
                    code: 0,
                }],
                mutes: Vec::new(),
                grant_overrides: Vec::new(),
                max_participants: 0,
            })),
        });
        let serving = control.start().await;

        let fabric = Fabric::new();
        let ada = join(&fabric, "ada");
        let _link = Link::attach(supervisor(serving.endpoint()), fabric.clone());

        tokio::time::timeout(PATIENCE, async {
            while !ada.was_closed() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the address ban to reach a live session");
    }

    #[tokio::test]
    async fn closing_a_room_empties_it() {
        let control = FakeControl::default();
        control.will_say(directive(pb::directive::Action::CloseRoom(pb::CloseRoom {
            code: admin::ModerationCode::OperatorAction as i32,
        })));
        let serving = control.start().await;

        let fabric = Fabric::new();
        let ada = join(&fabric, "ada");
        let bea = join(&fabric, "bea");
        let _link = Link::attach(supervisor(serving.endpoint()), fabric.clone());

        let result = control.hears("the directive result", is_result).await;
        assert_eq!(result_of(&result).affected_sessions, 2);
        assert!(ada.was_closed() && bea.was_closed());
        assert_eq!(
            fabric.policy().admits(&scope("cy"), address(), 0),
            Err(Refusal::Closed)
        );
    }

    /// A relay that cannot do something must say so rather than report success.
    #[tokio::test]
    async fn a_mute_is_refused_out_loud() {
        let control = FakeControl::default();
        control.will_say(directive(pb::directive::Action::ApplyMute(pb::ApplyMute {
            target: Some(admin::ParticipantRef {
                username: "ada".to_owned(),
                device: String::new(),
            }),
            media: vec![admin::MediaKind::Audio as i32],
            audience_only: false,
            muted: true,
            expires_at: None,
        })));
        let serving = control.start().await;

        let fabric = Fabric::new();
        let ada = join(&fabric, "ada");
        let _link = Link::attach(supervisor(serving.endpoint()), fabric.clone());

        let result = control.hears("the directive result", is_result).await;
        let result = result_of(&result);
        assert_eq!(result.affected_sessions, 0);
        assert!(
            result.error.contains("does not enforce mutes"),
            "the refusal must say what was not done: {:?}",
            result.error
        );
        // And nobody was thrown out as a substitute for muting them.
        assert!(!ada.was_closed());
    }

    /// A control plane that cannot be reached is not an outage for the room.
    #[tokio::test]
    async fn a_relay_that_cannot_reach_the_control_plane_keeps_serving() {
        let fabric = Fabric::new();
        let ada = join(&fabric, "ada");
        let _link = Link::attach(supervisor(nowhere().await), fabric.clone());

        until("the relay to notice it is out of touch", || {
            fabric.policy().out_of_touch()
        })
        .await;

        // Five minutes of grace by default. Nobody is thrown out and nobody is
        // turned away: what a relay in this state can miss is a *new* ban, and
        // it is still enforcing every ban it already has.
        assert!(fabric.policy().supervised());
        assert!(fabric.policy().admits(&scope("cy"), address(), 0).is_ok());
        assert!(!ada.was_closed());
    }

    #[tokio::test]
    async fn a_relay_reattaching_says_who_it_still_has() {
        let control = FakeControl::default();
        let serving = control.start().await;
        let fabric = Fabric::new();
        join(&fabric, "ada");
        let _link = Link::attach(supervisor(serving.endpoint()), fabric.clone());
        control
            .hears("the first hello", |m| {
                matches!(m.body, Some(pb::relay_message::Body::Hello(_)))
            })
            .await;

        control.forget();
        control.hang_up();

        // Somebody arrives while there is nobody to tell, and somebody else
        // leaves. Neither may be reported as an event afterwards: the events
        // describe a stream the control plane was not on, and it is about to be
        // told the whole truth instead.
        join(&fabric, "bea");
        let ada = fabric
            .roster()
            .everybody()
            .into_iter()
            .find(|p| &*p.user == "ada")
            .expect("ada");
        fabric.roster().release(ada.id, Departure::Clean);

        let hello = control
            .hears("the second hello", |m| {
                matches!(m.body, Some(pb::relay_message::Body::Hello(_)))
            })
            .await;
        let Some(pb::relay_message::Body::Hello(hello)) = hello.body else {
            unreachable!()
        };
        let named: Vec<&str> = hello
            .existing
            .iter()
            .filter_map(|s| s.identity.as_ref().map(|i| i.username.as_str()))
            .collect();
        assert_eq!(named, vec!["bea"]);

        // And nothing from the gap was replayed as though it had just happened.
        assert!(
            !control.everything_heard().iter().any(is_opened),
            "an arrival from before the reattach was reported as new"
        );
    }

    #[tokio::test]
    async fn departures_queue_rather_than_being_dropped() {
        // A lost departure leaves the control plane believing in somebody who is
        // not there, so the roster's queue is unbounded and takes them all.
        let fabric = Fabric::new();
        let mut notes = fabric.roster().listen();
        join(&fabric, "ada");
        assert!(matches!(notes.try_recv(), Ok(Note::Arrived(_))));
        assert_eq!(notes.try_recv().unwrap_err(), TryRecvError::Empty);
    }

    #[test]
    fn every_capability_bit_maps_to_its_own_power() {
        // The table is a hand-written mapping between two numbering schemes, so
        // the failure worth catching is two bits pointing at one enum value —
        // which would silently report the wrong power and read perfectly well.
        let mut seen = std::collections::HashSet::new();
        for (bit, capability) in CAPABILITIES {
            assert!(
                seen.insert(capability as i32),
                "duplicate power for {bit:#x}"
            );
            assert_eq!(bit.count_ones(), 1, "{bit:#x} is not a single bit");
        }
        assert_eq!(seen.len(), 21);
    }

    #[test]
    fn a_mask_names_the_powers_it_carries_and_no_others() {
        let mask = (1 << 11) | (1 << 16);
        let named = moderation(mask);
        assert_eq!(named.len(), 2);
        assert!(named.contains(&(admin::Capability::ForceMute as i32)));
        assert!(named.contains(&(admin::Capability::Kick as i32)));

        // A bit from a control plane newer than this relay.
        assert!(moderation(1 << 30).is_empty());
        assert!(moderation(0).is_empty());
    }

    #[test]
    fn a_ban_this_relay_cannot_read_is_refused_rather_than_widened() {
        // The dangerous failure is a malformed prefix that parses as something
        // permissive or as something universal.
        let ban = pb::Ban {
            key: Some(pb::ban::Key::IpPrefix("not-an-address/8".into())),
            expires_at: None,
            code: 0,
        };
        assert!(translate(&ban).is_none());

        let good = pb::Ban {
            key: Some(pb::ban::Key::IpPrefix("203.0.113.0/24".into())),
            expires_at: None,
            code: 0,
        };
        assert!(matches!(
            translate(&good).map(|b| b.who),
            Some(Banned::Address { .. })
        ));
    }

    #[test]
    fn a_moderation_code_reaches_the_client_as_words() {
        assert_eq!(
            reason_for(admin::ModerationCode::Harassment as i32),
            "moderation_code_harassment"
        );
        assert_eq!(reason_for(9_999), "moderation");
    }
}
