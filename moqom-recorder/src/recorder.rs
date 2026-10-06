//! Following a room and recording what it publishes.
//!
//! The recorder watches the room's namespace, `(tenant, "r", room)`. Each
//! publisher appears under it as `(tenant, "r", room, user, device)`; for each
//! one it subscribes to `.catalog`, and for each track a catalog lists it
//! subscribes to that track. A catalog that drops a track, or a publisher
//! whose namespace goes away, finishes that track's files.
//!
//! It never announces anything. Participants learn who is in a room by
//! watching the same namespace, so a recorder that does not publish is not
//! among the people they see -- which is the point, since it is not a person.
//! What tells them a recording is running is the recording watchdog the
//! control plane attaches before it assigns a recorder, and that is shown to
//! everyone in the room.
//!
//! Everything that must survive a reconnect -- the writers, and what each
//! publisher's catalog last said -- lives outside the session. When the
//! connection drops the recorder reconnects with the current credential,
//! resubscribes to everything it knew about, and writes on into the same
//! files. The relay restarts each subscription at the group in flight, so the
//! cost of a reconnect is the media that went by during the gap, marked in the
//! archive, and nothing written twice.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use moqom_client::{
    Credentials, DeviceKey, Error, FullTrackName, NamespaceEvent, Session, Subscription,
    TrackNamespace,
};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::catalog::{self, Follower, Track};
use crate::manifest::{Artifact, ArtifactKind, Manifest, TrackEntry};
use crate::store::Store;
use crate::track::{Finished, TrackConfig, TrackWriter, component, now_micros};

/// How long a relay gets to answer a SUBSCRIBE. It forwards to the publisher
/// first, and a publisher that never answers must not stall the room.
const SUBSCRIBE_TIMEOUT: Duration = Duration::from_secs(10);

/// A session that lasted this long was a success, whatever ended it, and the
/// next reconnect starts its backoff afresh.
const STABLE_SESSION: Duration = Duration::from_secs(30);

/// Consecutive failures to hold a session before the recording is failed.
/// About ten minutes at the backoff ceiling: long enough for a relay restart
/// or a token outage, short enough that a recording which cannot work says so.
const MAX_FAILURES: u32 = 24;

/// What a recorder is told.
#[derive(Clone)]
pub struct RecorderConfig {
    /// The recording.
    pub recording: String,
    /// The tenant.
    pub tenant: String,
    /// The room.
    pub room: String,
    /// Which attempt this is.
    pub attempt: u32,
    /// The relay, as `host:port`.
    pub relay: String,
    /// The name its certificate is verified against.
    pub server_name: String,
    /// TLS for the relay.
    pub tls: rustls::ClientConfig,
    /// The recorder's key, which every token it is given is bound to.
    pub key: Arc<DeviceKey>,
    /// Whether the room requires end-to-end encryption.
    pub e2ee_required: bool,
    /// Whether CMAF is wanted where it is possible.
    pub remux: bool,
    /// Where files are written before they are stored.
    pub spool: PathBuf,
    /// The store prefix, which begins with the tenant.
    pub prefix: String,
    /// Rotate files past this many bytes.
    pub segment_bytes: u64,
}

/// Counters the control plane is told on each renewal.
#[derive(Debug, Default)]
pub struct Progress {
    /// Objects archived.
    pub objects: AtomicU64,
    /// Payload bytes received, duplicates included: what the relay sent.
    pub bytes_received: AtomicU64,
    /// Bytes now in the store.
    pub bytes_stored: AtomicU64,
    /// Tracks being, or having been, recorded.
    pub tracks: AtomicU64,
    /// Reconnects so far.
    pub reconnects: AtomicU64,
}

/// What a recording attempt produced.
#[derive(Debug)]
pub struct Summary {
    /// The manifest, as stored.
    pub manifest: Manifest,
    /// The manifest's own file.
    pub manifest_artifact: Option<Artifact>,
    /// Why it ended early, if it did.
    pub error: Option<String>,
}

/// A recorder for one attempt at one recording.
pub struct Recorder {
    config: RecorderConfig,
    progress: Arc<Progress>,
}

enum Event {
    Catalog {
        namespace: TrackNamespace,
        payload: Bytes,
    },
    Ended {
        relative: String,
    },
    Failed(String),
}

enum Ended {
    Stopped,
    Lost(String),
    Failed(String),
}

/// A reader task, stopped when this is dropped: a session that is gone takes
/// its readers with it.
struct Reader {
    namespace: TrackNamespace,
    task: JoinHandle<()>,
}

impl Drop for Reader {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Participant {
    user: String,
    device: String,
    follower: Follower,
}

struct State {
    writers: HashMap<String, Arc<Mutex<TrackWriter>>>,
    participants: HashMap<TrackNamespace, Participant>,
    finished: mpsc::UnboundedSender<Finished>,
    encrypted: bool,
    ordinal: u32,
}

impl Recorder {
    /// A recorder that has not started.
    #[must_use]
    pub fn new(config: RecorderConfig) -> Self {
        Self {
            config,
            progress: Arc::new(Progress::default()),
        }
    }

    /// Its counters, for reporting while it runs.
    #[must_use]
    pub fn progress(&self) -> Arc<Progress> {
        Arc::clone(&self.progress)
    }

    /// Record until `stop` turns true or recording becomes impossible, then
    /// finish every file, store it, and write the manifest.
    ///
    /// `credentials` holds the current token. Whoever feeds it -- the worker's
    /// lease renewals, or a file on disk -- replaces it before it expires; the
    /// recorder hands each new one to the relay, and uses the latest whenever
    /// it reconnects.
    pub async fn run(
        self,
        store: Arc<Store>,
        mut credentials: watch::Receiver<Bytes>,
        mut stop: watch::Receiver<bool>,
    ) -> Summary {
        let started = now_micros();
        let (finished, queue) = mpsc::unbounded_channel();
        let uploader = tokio::spawn(upload(
            Arc::clone(&store),
            self.config.prefix.clone(),
            queue,
            Arc::clone(&self.progress),
        ));
        let mut state = State {
            writers: HashMap::new(),
            participants: HashMap::new(),
            finished,
            encrypted: self.config.e2ee_required,
            ordinal: 0,
        };

        let mut error = self.attend(&mut state, &mut credentials, &mut stop).await;

        let ended = now_micros();
        let mut tracks: Vec<TrackEntry> = Vec::new();
        for writer in state.writers.values() {
            let mut writer = lock(writer);
            if let Err(failure) = writer.close(ended) {
                error.get_or_insert_with(|| format!("finishing {}: {failure}", writer.relative()));
            }
            tracks.push(writer.entry());
        }
        tracks.sort_by(|a, b| a.track.cmp(&b.track));
        let encrypted = state.encrypted;
        drop(state);

        let (mut artifacts, upload_error) = uploader
            .await
            .unwrap_or_else(|failure| (Vec::new(), Some(failure.to_string())));
        if let Some(upload_error) = upload_error {
            error.get_or_insert(upload_error);
        }
        artifacts.sort_by(|a, b| a.name.cmp(&b.name));

        let manifest = Manifest {
            format: "moqom-recording".to_owned(),
            version: 1,
            recording: self.config.recording.clone(),
            tenant: self.config.tenant.clone(),
            room: self.config.room.clone(),
            attempt: self.config.attempt,
            encrypted,
            started_micros: started,
            ended_micros: ended,
            reconnects: u32::try_from(self.progress.reconnects.load(Ordering::Relaxed))
                .unwrap_or(u32::MAX),
            tracks,
            artifacts,
            error: error.clone(),
        };
        let manifest_artifact = match self.store_manifest(&store, &manifest, started, ended).await {
            Ok(artifact) => Some(artifact),
            Err(failure) => {
                error.get_or_insert(failure);
                None
            }
        };
        Summary {
            manifest,
            manifest_artifact,
            error,
        }
    }

    /// Hold a session with the relay for as long as the recording runs,
    /// reconnecting when it drops. Returns why recording became impossible, if
    /// it did; `None` is a requested stop.
    async fn attend(
        &self,
        state: &mut State,
        credentials: &mut watch::Receiver<Bytes>,
        stop: &mut watch::Receiver<bool>,
    ) -> Option<String> {
        let mut failures = 0u32;
        loop {
            if *stop.borrow() {
                return None;
            }
            let token = credentials.borrow().clone();
            let connected = tokio::select! {
                connected = self.connect(&token) => connected,
                () = stopped(stop) => return None,
            };
            let opened = Instant::now();
            let outcome = match connected {
                Ok(session) => {
                    state.ordinal += 1;
                    if state.ordinal > 1 {
                        self.progress.reconnects.fetch_add(1, Ordering::Relaxed);
                    }
                    for writer in state.writers.values() {
                        if let Err(failure) = lock(writer).session(state.ordinal) {
                            return Some(format!("writing the spool: {failure}"));
                        }
                    }
                    self.session(session, state, credentials, stop).await
                }
                Err(failure) => Ended::Lost(failure.to_string()),
            };
            match outcome {
                Ended::Stopped => return None,
                Ended::Failed(reason) => return Some(reason),
                Ended::Lost(reason) => {
                    if opened.elapsed() >= STABLE_SESSION {
                        failures = 0;
                    }
                    failures += 1;
                    tracing::warn!(recording = %self.config.recording, failures, %reason, "lost the relay; reconnecting");
                    if failures >= MAX_FAILURES {
                        return Some(format!("could not hold a session with the relay: {reason}"));
                    }
                }
            }
            let delay =
                Duration::from_millis(250u64 << failures.min(7)).min(Duration::from_secs(30));
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                () = stopped(stop) => return None,
            }
        }
    }

    async fn store_manifest(
        &self,
        store: &Store,
        manifest: &Manifest,
        started: u64,
        ended: u64,
    ) -> Result<Artifact, String> {
        let name = Manifest::name(self.config.attempt);
        let body = serde_json::to_vec_pretty(manifest).map_err(|failure| failure.to_string())?;
        let crc32c = crate::crc32c::checksum(&body);
        let key = format!("{}/{name}", self.config.prefix);
        let bytes = store
            .put(
                &key,
                Bytes::from(body),
                ArtifactKind::Manifest.content_type(),
            )
            .await
            .map_err(|failure| format!("storing the manifest: {failure}"))?;
        self.progress
            .bytes_stored
            .fetch_add(bytes, Ordering::Relaxed);
        Ok(Artifact {
            name,
            kind: ArtifactKind::Manifest,
            track: String::new(),
            bytes,
            crc32c,
            first_micros: Some(started),
            last_micros: Some(ended),
        })
    }

    async fn connect(&self, token: &[u8]) -> Result<Session, Error> {
        let addr = tokio::net::lookup_host(&self.config.relay)
            .await?
            .next()
            .ok_or_else(|| {
                Error::Io(std::io::Error::other(format!(
                    "{} did not resolve",
                    self.config.relay
                )))
            })?;
        let credentials = Credentials::proven(token, &self.config.key);
        Session::connect(
            addr,
            &self.config.server_name,
            self.config.tls.clone(),
            Some(&credentials),
        )
        .await
    }

    async fn session(
        &self,
        mut session: Session,
        state: &mut State,
        credentials: &mut watch::Receiver<Bytes>,
        stop: &mut watch::Receiver<bool>,
    ) -> Ended {
        let prefix = match TrackNamespace::from_parts([
            self.config.tenant.as_str(),
            "r",
            self.config.room.as_str(),
        ]) {
            Ok(prefix) => prefix,
            Err(failure) => return Ended::Failed(format!("the room cannot be named: {failure}")),
        };
        let mut watch = match session.watch(prefix).await {
            Ok(watch) => watch,
            Err(failure) => return Ended::Lost(failure.to_string()),
        };
        let (events_tx, mut events) = mpsc::channel(256);
        let mut readers: HashMap<String, Reader> = HashMap::new();

        let known: Vec<TrackNamespace> = state.participants.keys().cloned().collect();
        for namespace in known {
            if let Err(failure) = self
                .follow(&mut session, state, &namespace, &events_tx, &mut readers)
                .await
            {
                return Ended::Lost(failure.to_string());
            }
        }

        let mut renewing = true;
        loop {
            tokio::select! {
                event = watch.next() => match event {
                    Ok(Some(NamespaceEvent::Available(namespace))) => {
                        let Some(participant) = participant(&namespace) else { continue };
                        state.participants.entry(namespace.clone()).or_insert(participant);
                        if let Err(failure) = self.follow(&mut session, state, &namespace, &events_tx, &mut readers).await {
                            return Ended::Lost(failure.to_string());
                        }
                    }
                    Ok(Some(NamespaceEvent::Gone(namespace))) => {
                        readers.retain(|_, reader| reader.namespace != namespace);
                        if let Some(participant) = state.participants.remove(&namespace) {
                            let under = format!("{}/{}/", participant.user, participant.device);
                            for (relative, writer) in &state.writers {
                                if relative.starts_with(&under)
                                    && let Err(failure) = lock(writer).departed()
                                {
                                    return Ended::Failed(format!("writing the spool: {failure}"));
                                }
                            }
                        }
                    }
                    Ok(None) => return Ended::Lost("the relay closed the room's namespace watch".to_owned()),
                    Err(failure) => return Ended::Lost(failure.to_string()),
                },
                Some(event) = events.recv() => match event {
                    Event::Catalog { namespace, payload } => {
                        if let Err(ended) = self.catalog(&mut session, state, &namespace, &payload, &events_tx, &mut readers).await {
                            return ended;
                        }
                    }
                    Event::Ended { relative } => {
                        readers.remove(&relative);
                    }
                    Event::Failed(reason) => return Ended::Failed(reason),
                },
                changed = credentials.changed(), if renewing => {
                    if changed.is_err() {
                        renewing = false;
                        continue;
                    }
                    let token = credentials.borrow_and_update().clone();
                    if let Err(failure) = watch.renew(&Credentials::proven(&token, &self.config.key)).await {
                        return Ended::Lost(format!("renewing the credential: {failure}"));
                    }
                },
                () = stopped(stop) => return Ended::Stopped,
            }
        }
    }

    /// Subscribe to a publisher's catalog and to every track it is already
    /// known to have.
    async fn follow(
        &self,
        session: &mut Session,
        state: &mut State,
        namespace: &TrackNamespace,
        events: &mpsc::Sender<Event>,
        readers: &mut HashMap<String, Reader>,
    ) -> Result<(), Error> {
        self.subscribe(
            session,
            state,
            namespace,
            catalog::TRACK_NAME,
            None,
            events,
            readers,
        )
        .await?;
        let known: Vec<Track> = state
            .participants
            .get(namespace)
            .map(|participant| participant.follower.tracks().cloned().collect())
            .unwrap_or_default();
        for track in known {
            self.subscribe(
                session,
                state,
                namespace,
                &track.name.clone(),
                Some(&track),
                events,
                readers,
            )
            .await?;
        }
        Ok(())
    }

    async fn catalog(
        &self,
        session: &mut Session,
        state: &mut State,
        namespace: &TrackNamespace,
        payload: &[u8],
        events: &mpsc::Sender<Event>,
        readers: &mut HashMap<String, Reader>,
    ) -> Result<(), Ended> {
        let Some(participant) = state.participants.get_mut(namespace) else {
            return Ok(());
        };
        let changes = match participant.follower.apply(payload) {
            Ok(changes) => changes,
            Err(failure) => {
                tracing::warn!(recording = %self.config.recording, %namespace, %failure, "a catalog could not be read; keeping the last one");
                return Ok(());
            }
        };
        if participant.follower.encrypted() {
            state.encrypted = true;
        }
        let place = format!("{}/{}", participant.user, participant.device);
        for name in &changes.removed {
            let relative = format!("{place}/{}", component(name.as_bytes()));
            readers.remove(&relative);
            if let Some(writer) = state.writers.get(&relative)
                && let Err(failure) = lock(writer).departed()
            {
                return Err(Ended::Failed(format!("writing the spool: {failure}")));
            }
        }
        for track in &changes.changed {
            let relative = format!("{place}/{}", component(track.name.as_bytes()));
            if let Some(writer) = state.writers.get(&relative) {
                lock(writer).describe(track);
            }
        }
        for track in &changes.added {
            if let Err(failure) = self
                .subscribe(
                    session,
                    state,
                    namespace,
                    &track.name,
                    Some(track),
                    events,
                    readers,
                )
                .await
            {
                return Err(Ended::Lost(failure.to_string()));
            }
        }
        Ok(())
    }

    /// Why this track gets no CMAF, if it does not.
    fn remux(&self, encrypted: bool) -> Result<(), String> {
        if !self.config.remux {
            return Err("CMAF was not requested for this recording".to_owned());
        }
        if self.config.e2ee_required {
            return Err(
                "the room requires end-to-end encryption and the recorder holds no media key"
                    .to_owned(),
            );
        }
        if encrypted {
            return Err(
                "the publisher's catalog names a media key, so its payloads are ciphertext"
                    .to_owned(),
            );
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn subscribe(
        &self,
        session: &mut Session,
        state: &mut State,
        namespace: &TrackNamespace,
        name: &str,
        track: Option<&Track>,
        events: &mpsc::Sender<Event>,
        readers: &mut HashMap<String, Reader>,
    ) -> Result<(), Error> {
        let Some(participant) = state.participants.get(namespace) else {
            return Ok(());
        };
        let relative = format!(
            "{}/{}/{}",
            participant.user,
            participant.device,
            component(name.as_bytes())
        );
        if readers.contains_key(&relative) {
            return Ok(());
        }
        let encrypted = self.config.e2ee_required || participant.follower.encrypted();
        let full = FullTrackName::new(namespace.clone(), Bytes::copy_from_slice(name.as_bytes()))
            .map_err(|failure| Error::Setup(failure.to_string()))?;
        let subscription = match tokio::time::timeout(SUBSCRIBE_TIMEOUT, session.subscribe(full))
            .await
        {
            Ok(Ok(subscription)) => subscription,
            Ok(Err(Error::Refused { code, reason })) => {
                tracing::debug!(recording = %self.config.recording, %relative, code, %reason, "subscription refused; waiting for the catalog to restate it");
                return Ok(());
            }
            Ok(Err(failure)) => return Err(failure),
            Err(_) => {
                tracing::warn!(recording = %self.config.recording, %relative, "no answer to a subscription");
                return Ok(());
            }
        };

        let writer = if let Some(writer) = state.writers.get(&relative) {
            if let Some(track) = track {
                lock(writer).describe(track);
            }
            Arc::clone(writer)
        } else {
            let config = TrackConfig {
                recording: self.config.recording.clone(),
                attempt: self.config.attempt,
                namespace: namespace
                    .fields()
                    .iter()
                    .map(|field| String::from_utf8_lossy(field).into_owned())
                    .collect(),
                track: name.to_owned(),
                relative: relative.clone(),
                spool: self.config.spool.clone(),
                segment_bytes: self.config.segment_bytes,
                encrypted,
            };
            let remux = if track.is_some() {
                self.remux(encrypted)
            } else {
                Ok(())
            };
            let mut writer = TrackWriter::new(config, track, remux, state.finished.clone());
            if let Err(failure) = writer.session(state.ordinal) {
                // Not awaited: this runs on the task that drains the queue.
                let _ = events.try_send(Event::Failed(format!("writing the spool: {failure}")));
            }
            self.progress.tracks.fetch_add(1, Ordering::Relaxed);
            let writer = Arc::new(Mutex::new(writer));
            state.writers.insert(relative.clone(), Arc::clone(&writer));
            writer
        };

        let catalog = (name == catalog::TRACK_NAME).then(|| namespace.clone());
        let task = tokio::spawn(read(
            subscription,
            writer,
            catalog,
            Arc::clone(&self.progress),
            events.clone(),
            relative.clone(),
        ));
        readers.insert(
            relative,
            Reader {
                namespace: namespace.clone(),
                task,
            },
        );
        Ok(())
    }
}

/// A publisher's namespace is the room's plus a user and a device; anything
/// else under the room is not a publisher.
fn participant(namespace: &TrackNamespace) -> Option<Participant> {
    let fields = namespace.fields();
    if fields.len() != 5 || fields[1].as_ref() != b"r" {
        return None;
    }
    Some(Participant {
        user: component(&fields[3]),
        device: component(&fields[4]),
        follower: Follower::new(),
    })
}

async fn read(
    mut subscription: Subscription,
    writer: Arc<Mutex<TrackWriter>>,
    catalog: Option<TrackNamespace>,
    progress: Arc<Progress>,
    events: mpsc::Sender<Event>,
    relative: String,
) {
    loop {
        let object = match subscription.next_object().await {
            Ok(Some(object)) => object,
            Ok(None) => break,
            Err(failure) => {
                tracing::debug!(%relative, %failure, "subscription ended");
                break;
            }
        };
        progress
            .bytes_received
            .fetch_add(object.payload.len() as u64, Ordering::Relaxed);
        let written = lock(&writer).object(&object);
        match written {
            Ok(true) => {
                progress.objects.fetch_add(1, Ordering::Relaxed);
                if let Some(namespace) = &catalog {
                    let event = Event::Catalog {
                        namespace: namespace.clone(),
                        payload: object.payload.clone(),
                    };
                    if events.send(event).await.is_err() {
                        return;
                    }
                }
            }
            Ok(false) => {}
            Err(failure) => {
                let _ = events
                    .send(Event::Failed(format!("writing the spool: {failure}")))
                    .await;
                return;
            }
        }
    }
    let _ = events.send(Event::Ended { relative }).await;
}

async fn upload(
    store: Arc<Store>,
    prefix: String,
    mut queue: mpsc::UnboundedReceiver<Finished>,
    progress: Arc<Progress>,
) -> (Vec<Artifact>, Option<String>) {
    let mut artifacts = Vec::new();
    let mut error = None;
    while let Some(finished) = queue.recv().await {
        let key = format!("{prefix}/{}", finished.artifact.name);
        match store
            .upload(
                &finished.path,
                &key,
                finished.artifact.crc32c,
                finished.artifact.kind.content_type(),
            )
            .await
        {
            Ok(bytes) => {
                progress.bytes_stored.fetch_add(bytes, Ordering::Relaxed);
                if !matches!(&*store, Store::Local(_)) {
                    let _ = tokio::fs::remove_file(&finished.path).await;
                }
                artifacts.push(finished.artifact);
            }
            Err(failure) => {
                // Left in the spool: the file is whole and checksummed, and a
                // rerun or an operator can store it later.
                tracing::error!(%key, %failure, "a finished file could not be stored");
                error.get_or_insert_with(|| failure.to_string());
            }
        }
    }
    (artifacts, error)
}

async fn stopped(stop: &mut watch::Receiver<bool>) {
    // A dropped sender is a stop too: nobody is left to say when.
    let _ = stop.wait_for(|stop| *stop).await;
}

fn lock(writer: &Mutex<TrackWriter>) -> std::sync::MutexGuard<'_, TrackWriter> {
    writer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
