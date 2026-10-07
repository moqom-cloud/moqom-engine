//! The recorder against the real relay.
//!
//! The relay verifies tokens and observes proofs: the recorder proves its
//! token, as it must in production, while the publisher here is a bare MOQT
//! peer presenting a bearer token. The publisher is written against the wire
//! types rather than `moqom-client`, because it has to answer subscriptions for
//! two tracks in one namespace with two aliases, which is what a real media
//! publisher does and what the client's publisher does not.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::{Buf, Bytes, BytesMut};
use moqom_client::{DeviceKey, ObjectProperties};
use moqom_proto::control::{
    ControlFrame, MessageBody, MessageType, Namespace, PublishNamespace, RequestIdGenerator, Role,
    Setup, Subscribe, SubscribeNamespace, SubscribeOk, write_message,
};
use moqom_proto::data::{
    SubgroupContent, SubgroupHeader, SubgroupObject, SubgroupSource, SubgroupWriter,
};
use moqom_proto::error::DecodeError;
use moqom_proto::model::{GroupId, TrackAlias, TrackNamespace};
use moqom_recorder::archive::{Reader, Record};
use moqom_recorder::manifest::{ArtifactKind, Join, JoinFrom, Manifest};
use moqom_recorder::store::{LocalDir, Store};
use moqom_recorder::{Recorder, RecorderConfig};
use moqom_relay::possession::{Enforcement, Possession};
use moqom_relay::{
    Authenticator, Cache, Fabric, Limits, Rules, Session as RelaySession, VerificationKey,
};
use moqom_transport::{Server, alpn, server::with_moqt_alpn};
use tokio::sync::{mpsc, watch};
use web_transport_quinn::{RecvStream, SendStream};

const PATIENCE: Duration = Duration::from_secs(15);
const KEY_ID: &str = "test-key";
const TENANT: &str = "acme";
const ROOM: &str = "standup";
/// The device field is the first sixteen characters of the token's thumbprint.
const PUBLISHER_JKT: &str = "phonephonephone1-and-the-rest";
const DEVICE: &str = "phonephonephone1";
/// The subject the control plane mints every recorder token with.
const RECORDER: &str = "moqom-recorder";

async fn within<F: Future>(what: &str, future: F) -> F::Output {
    tokio::time::timeout(PATIENCE, future)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

fn signer() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).expect("a valid seed")
}

fn token(subject: &str, thumbprint: &str, publish: u32) -> String {
    let issued = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    let header = serde_json::json!({ "alg": "EdDSA", "typ": "MOQT", "kid": KEY_ID });
    let claims = serde_json::json!({
        "iss": "https://api.moqom.cloud",
        "sub": subject,
        "aud": TENANT,
        "iat": issued,
        "exp": issued + 600,
        "cnf": { "jkt": thumbprint },
        "moqt": { "room": ROOM, "pub": publish, "cap": 0, "own": false, "bs": false },
    });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = signer().sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
}

struct Relay {
    addr: SocketAddr,
    certificate: rustls::pki_types::CertificateDer<'static>,
    accept: tokio::task::JoinHandle<()>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

fn relay() -> Relay {
    relay_with(Limits::default(), 0)
}

/// A relay retaining what `limits` allow, holding the room to `ceiling`
/// sessions (zero for none).
fn relay_with(limits: Limits, ceiling: u32) -> Relay {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let generated =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("a certificate");
    let certificate = generated.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::try_from(generated.signing_key.serialize_der())
        .expect("a key");
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .expect("certificate and key agree");
    let server = Server::bind(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        with_moqt_alpn(tls),
    )
    .expect("a port");
    let addr = server.local_addr().expect("bound");
    let identity = URL_SAFE_NO_PAD.encode(
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, certificate.as_ref()).as_ref(),
    );
    let fabric = Fabric::with_cache(Cache::new(limits))
        .authenticated(Authenticator::new(
            "",
            vec![VerificationKey {
                id: KEY_ID.to_owned(),
                bytes: signer().public_key().as_ref().to_vec(),
            }],
        ))
        .proving(Possession::new(Enforcement::Observed, Some(identity)));
    if ceiling > 0 {
        fabric.policy().describe(
            (TENANT.into(), ROOM.into()),
            Rules {
                ceiling,
                ..Rules::default()
            },
        );
    }
    let accept = tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            let fabric = fabric.clone();
            tokio::spawn(async move {
                let Ok((session, negotiated)) = incoming.establish().await else {
                    return;
                };
                let _ = RelaySession::serve(session, negotiated.carrier, fabric).await;
            });
        }
    });
    Relay {
        addr,
        certificate,
        accept,
    }
}

struct Frames {
    stream: RecvStream,
    buffer: BytesMut,
}

impl Frames {
    async fn next(&mut self) -> Option<ControlFrame> {
        loop {
            let mut cursor = &self.buffer[..];
            match ControlFrame::decode(&mut cursor) {
                Ok(frame) => {
                    let consumed = self.buffer.len() - cursor.remaining();
                    self.buffer.advance(consumed);
                    return Some(frame);
                }
                Err(DecodeError::Short { .. }) => {}
                Err(error) => panic!("undecodable control frame: {error}"),
            }
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk).await {
                Ok(Some(0) | None) | Err(_) => return None,
                Ok(Some(n)) => self.buffer.extend_from_slice(&chunk[..n]),
            }
        }
    }
}

async fn write<M: MessageBody>(stream: &mut SendStream, message: &M) {
    let mut buf = BytesMut::new();
    write_message(&mut buf, message).expect("a message that fits");
    stream.write_all(&buf).await.expect("writing a message");
}

/// A subgroup still being written, for a group in flight.
struct OpenGroup {
    stream: SendStream,
    writer: SubgroupWriter,
    next: u32,
}

impl OpenGroup {
    async fn write(&mut self, payload: &[u8], properties: ObjectProperties) {
        let mut buf = BytesMut::new();
        let object = SubgroupObject {
            object: self.next.into(),
            content: SubgroupContent::Normal {
                payload: Bytes::copy_from_slice(payload),
                properties: properties.to_wire(),
            },
        };
        self.next += 1;
        self.writer
            .write(&mut buf, &object)
            .expect("an encodable object");
        self.stream
            .write_all(&buf)
            .await
            .expect("writing an object");
    }

    fn finish(mut self) {
        self.stream.finish().expect("finishing a subgroup");
    }
}

/// A bare MOQT publisher: one namespace, an alias per track.
struct Publisher {
    session: moqom_transport::Session,
    requests: RequestIdGenerator,
    _control: (SendStream, Frames),
    _endpoint: quinn::Endpoint,
    announcement: Option<(SendStream, Frames)>,
}

impl Publisher {
    async fn connect(relay: &Relay, token: &str) -> Self {
        let mut tls = moqom_client::tls::pinned(relay.certificate.clone());
        tls.alpn_protocols = vec![alpn::MOQT_DRAFT_19.to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("TLS 1.3");
        let mut endpoint =
            quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("a socket");
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let connection = endpoint
            .connect(relay.addr, "localhost")
            .expect("connectable")
            .await
            .expect("the relay accepts");
        let session = moqom_transport::Session::raw(
            connection,
            web_transport_quinn::proto::ConnectRequest::new(
                url::Url::parse("https://localhost/").expect("a URL"),
            ),
            web_transport_quinn::proto::ConnectResponse::OK,
        );
        let (mut send, recv) = session.open_bi().await.expect("a control stream");
        let mut setup = Setup::new();
        setup
            .options
            .set_bytes(
                moqom_proto::control::setup::option_type::AUTHORIZATION_TOKEN,
                Bytes::copy_from_slice(token.as_bytes()),
            )
            .expect("a token that fits");
        write(&mut send, &setup).await;
        let mut frames = Frames {
            stream: recv,
            buffer: BytesMut::new(),
        };
        let frame = within("the relay's SETUP", frames.next())
            .await
            .expect("admitted");
        assert_eq!(frame.message_type, MessageType::Setup);
        Self {
            session,
            requests: RequestIdGenerator::new(Role::Client),
            _control: (send, frames),
            _endpoint: endpoint,
            announcement: None,
        }
    }

    async fn announce(&mut self, namespace: &TrackNamespace) {
        let (mut send, recv) = self.session.open_bi().await.expect("a request stream");
        let id = self.requests.allocate().expect("ids remain");
        write(&mut send, &PublishNamespace::new(id, namespace.clone())).await;
        self.announcement = Some((
            send,
            Frames {
                stream: recv,
                buffer: BytesMut::new(),
            },
        ));
    }

    /// Withdraw the announcement, which is how a publisher leaves.
    fn withdraw(&mut self) {
        if let Some((mut send, _)) = self.announcement.take() {
            let _ = send.finish();
        }
    }

    /// Answer every SUBSCRIBE with the alias for its track name, reporting
    /// which tracks were asked for.
    fn answer(&self, aliases: &'static [(&'static str, u32)]) -> mpsc::UnboundedReceiver<String> {
        let (tx, rx) = mpsc::unbounded_channel();
        let session = self.session.clone();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((mut send, recv)) = session.accept_bi().await {
                let mut frames = Frames {
                    stream: recv,
                    buffer: BytesMut::new(),
                };
                let Some(frame) = frames.next().await else {
                    continue;
                };
                if frame.message_type != MessageType::Subscribe {
                    continue;
                }
                let request = Subscribe::decode(&mut frame.body.clone()).expect("a SUBSCRIBE");
                let name = String::from_utf8_lossy(request.track.name()).into_owned();
                let alias = aliases
                    .iter()
                    .find(|(track, _)| *track == name)
                    .map_or(99, |(_, alias)| *alias);
                write(&mut send, &SubscribeOk::new(TrackAlias::from(alias))).await;
                held.push((send, frames));
                let _ = tx.send(name);
            }
        });
        rx
    }

    async fn publish(&self, alias: u32, group: u32, objects: &[(&[u8], ObjectProperties)]) {
        let mut stream = self.session.open_uni().await.expect("a data stream");
        let mut header = SubgroupHeader::new(
            TrackAlias::from(alias),
            GroupId::from(group),
            SubgroupSource::Zero,
        );
        header.properties_present = objects.iter().any(|(_, properties)| !properties.is_empty());
        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        let mut writer = SubgroupWriter::new(&header);
        for (index, (payload, properties)) in objects.iter().enumerate() {
            let payload = Bytes::copy_from_slice(payload);
            let object = if header.properties_present {
                SubgroupObject {
                    object: (index as u32).into(),
                    content: SubgroupContent::Normal {
                        payload,
                        properties: properties.to_wire(),
                    },
                }
            } else {
                SubgroupObject::new(index as u32, payload)
            };
            writer
                .write(&mut buf, &object)
                .expect("an encodable object");
        }
        stream.write_all(&buf).await.expect("writing a subgroup");
        stream.finish().expect("finishing a subgroup");
    }

    /// Open a group and leave it open, as a camera does mid-GOP.
    async fn open(&self, alias: u32, group: u32) -> OpenGroup {
        let mut stream = self.session.open_uni().await.expect("a data stream");
        let mut header = SubgroupHeader::new(
            TrackAlias::from(alias),
            GroupId::from(group),
            SubgroupSource::Zero,
        );
        header.properties_present = true;
        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        stream.write_all(&buf).await.expect("writing a header");
        OpenGroup {
            stream,
            writer: SubgroupWriter::new(&header),
            next: 0,
        }
    }

    /// Watch the room, as every participant does, and list who is in it.
    async fn roster(&mut self) -> Vec<TrackNamespace> {
        let prefix = TrackNamespace::from_parts([TENANT, "r", ROOM]).expect("a prefix");
        let (mut send, recv) = self.session.open_bi().await.expect("a request stream");
        let id = self.requests.allocate().expect("ids remain");
        write(&mut send, &SubscribeNamespace::new(id, prefix.clone())).await;
        let mut frames = Frames {
            stream: recv,
            buffer: BytesMut::new(),
        };
        let mut seen = Vec::new();
        while let Ok(Some(frame)) =
            tokio::time::timeout(Duration::from_millis(400), frames.next()).await
        {
            if frame.message_type == MessageType::Namespace {
                let message = Namespace::decode(&mut frame.body.clone()).expect("a NAMESPACE");
                seen.push(message.resolve(&prefix).expect("under the prefix"));
            }
        }
        drop(send);
        seen
    }
}

/// SPS and PPS for 1280x720 Baseline, 4-byte length-prefixed as the catalog
/// carries them.
fn decoder_configuration() -> String {
    let sps: &[u8] = &[0x67, 0x42, 0xC0, 0x1F, 0xDA, 0x01, 0x40, 0x16, 0xE8];
    let pps: &[u8] = &[0x68, 0xCE, 0x3C, 0x80];
    let mut out = Vec::new();
    for nal in [sps, pps] {
        out.extend_from_slice(&(nal.len() as u32).to_be_bytes());
        out.extend_from_slice(nal);
    }
    out.iter().fold(String::new(), |mut hex, byte| {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

fn catalog(encrypted: bool) -> Vec<u8> {
    let mut catalog = serde_json::json!({
        "version": 1,
        "tracks": [{
            "name": "video",
            "kind": "video",
            "codec": "video/h264",
            "decoderConfiguration": decoder_configuration(),
            "width": 1280,
            "height": 720,
            "frameRate": 30.0,
        }],
    });
    if encrypted {
        catalog["keyID"] = serde_json::json!(7);
    }
    serde_json::to_vec(&catalog).expect("serialisable")
}

fn frame(nal_type: u8, size: usize) -> Vec<u8> {
    let mut nal = vec![nal_type];
    nal.resize(size, 0xAB);
    let mut out = (nal.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&nal);
    out
}

fn properties(capture: u64, opening: bool) -> ObjectProperties {
    let mut properties = ObjectProperties {
        capture_time_micros: Some(capture),
        ..ObjectProperties::default()
    };
    if opening {
        let config = moqom_recorder::catalog::unhex(&decoder_configuration()).expect("hex");
        properties = properties.opening(config);
    }
    properties
}

fn scratch(name: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("moqom-recorder-it-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    path
}

/// An archived object: group, object, payload length, capture time.
type Seen = (u64, u64, usize, Option<u64>);

fn objects_in(path: &Path) -> (moqom_recorder::archive::Header, Vec<Seen>) {
    let mut reader =
        Reader::open(std::fs::File::open(path).expect("the archive exists")).expect("an archive");
    let mut objects = Vec::new();
    while let Some(record) = reader.next_record().expect("intact") {
        if let Record::Object(object) = record {
            objects.push((
                object.group,
                object.object,
                object.payload.len(),
                object.properties.capture_time_micros,
            ));
        }
    }
    (reader.header().clone(), objects)
}

struct Running {
    stop: watch::Sender<bool>,
    _tokens: watch::Sender<Bytes>,
    progress: Arc<moqom_recorder::recorder::Progress>,
    task: tokio::task::JoinHandle<moqom_recorder::Summary>,
}

fn start(relay: &Relay, out: &Path, e2ee_required: bool) -> Running {
    let (key, _) = DeviceKey::generate().expect("a recorder key");
    let token = token(RECORDER, &key.thumbprint(), 0);
    let recorder = Recorder::new(RecorderConfig {
        recording: "rec_1".into(),
        tenant: TENANT.into(),
        room: ROOM.into(),
        attempt: 1,
        relay: relay.addr.to_string(),
        server_name: "localhost".into(),
        tls: moqom_client::tls::pinned(relay.certificate.clone()),
        key: Arc::new(key),
        e2ee_required,
        remux: true,
        spool: out.join(".spool"),
        prefix: format!("{TENANT}/rec_1"),
        segment_bytes: 64 << 20,
    });
    let progress = recorder.progress();
    let (tokens, credentials) = watch::channel(Bytes::from(token));
    let (stop, stopping) = watch::channel(false);
    let store = Arc::new(Store::Local(LocalDir::new(out)));
    let task = tokio::spawn(recorder.run(store, credentials, stopping));
    Running {
        stop,
        _tokens: tokens,
        progress,
        task,
    }
}

async fn until_archived(progress: &moqom_recorder::recorder::Progress, objects: u64) {
    within("the recorder to archive everything", async {
        while progress.objects.load(Ordering::Relaxed) < objects {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

async fn until_asked(asked: &mut mpsc::UnboundedReceiver<String>, track: &str) {
    within(&format!("a subscription to {track}"), async {
        while let Some(name) = asked.recv().await {
            if name == track {
                return;
            }
        }
        panic!("the publisher went away");
    })
    .await;
}

async fn publish_two_groups(publisher: &Publisher) {
    let base = 1_700_000_000_000_000u64;
    let key = frame(0x65, 400);
    let delta = frame(0x41, 120);
    for group in 0..2u32 {
        let at = base + u64::from(group) * 100_000;
        publisher
            .publish(
                2,
                group,
                &[
                    (&key, properties(at, true)),
                    (&delta, properties(at + 33_333, false)),
                    (&delta, properties(at + 66_666, false)),
                ],
            )
            .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plaintext_room_is_archived_and_muxed_and_the_recorder_is_not_on_the_roster() {
    let relay = relay();
    let out = scratch("plaintext");
    let namespace =
        TrackNamespace::from_parts([TENANT, "r", ROOM, "ada", DEVICE]).expect("a namespace");

    let mut publisher = Publisher::connect(&relay, &token("ada", PUBLISHER_JKT, 3)).await;
    let mut asked = publisher.answer(&[(".catalog", 1), ("video", 2)]);
    publisher.announce(&namespace).await;

    let running = start(&relay, &out, false);
    until_asked(&mut asked, ".catalog").await;
    publisher
        .publish(1, 0, &[(&catalog(false), ObjectProperties::default())])
        .await;
    until_asked(&mut asked, "video").await;
    publish_two_groups(&publisher).await;
    until_archived(&running.progress, 7).await;

    // Who the room shows: the publisher, and nobody else, although the
    // recorder is connected and subscribed to everything.
    assert_eq!(publisher.roster().await, vec![namespace.clone()]);

    publisher.withdraw();
    running.stop.send(true).expect("the recorder is running");
    let summary = within("the recorder to finish", running.task)
        .await
        .expect("no panic");
    assert_eq!(summary.error, None);

    let root = out.join("acme/rec_1/ada").join(DEVICE);
    let (header, objects) = objects_in(&root.join("video/a1-s00000.mqa"));
    assert!(!header.encrypted);
    assert_eq!(header.namespace, ["acme", "r", "standup", "ada", DEVICE]);
    // In arrival order, which across groups is whatever order their streams
    // were read in; every object exactly once.
    let mut ids: Vec<(u64, u64)> = objects
        .iter()
        .map(|(group, object, _, _)| (*group, *object))
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, [(0, 0), (0, 1), (0, 2), (1, 0), (1, 1), (1, 2)]);
    let second = objects
        .iter()
        .find(|(group, object, _, _)| (*group, *object) == (0, 1))
        .expect("0.1");
    assert_eq!(
        second.3,
        Some(1_700_000_000_033_333),
        "capture times are kept"
    );
    let (_, catalog_objects) = objects_in(&root.join(".catalog/a1-s00000.mqa"));
    assert_eq!(catalog_objects.len(), 1);

    let cmaf = std::fs::read(root.join("video/a1-r1-p00000.mp4")).expect("a CMAF file");
    assert_eq!(&cmaf[4..8], b"ftyp");
    assert_eq!(
        cmaf.windows(4).filter(|window| window == b"moof").count(),
        2,
        "one fragment per group"
    );

    let manifest: Manifest = serde_json::from_slice(
        &std::fs::read(out.join("acme/rec_1/manifest-a1.json")).expect("a manifest"),
    )
    .expect("a readable manifest");
    assert!(!manifest.encrypted);
    assert_eq!(manifest.tracks.len(), 2);
    let video = manifest
        .tracks
        .iter()
        .find(|track| track.track.ends_with("/video"))
        .expect("video");
    assert_eq!(video.objects, 6);
    assert_eq!(video.cmaf_skipped, None);
    assert!(
        manifest
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == ArtifactKind::Cmaf)
    );
    assert!(summary.manifest_artifact.is_some());
    assert!(running.progress.bytes_stored.load(Ordering::Relaxed) > 0);

    let _ = std::fs::remove_dir_all(&out);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_encrypted_room_is_archived_as_ciphertext_only() {
    let relay = relay();
    let out = scratch("e2ee");
    let namespace =
        TrackNamespace::from_parts([TENANT, "r", ROOM, "ada", DEVICE]).expect("a namespace");

    let mut publisher = Publisher::connect(&relay, &token("ada", PUBLISHER_JKT, 3)).await;
    let mut asked = publisher.answer(&[(".catalog", 1), ("video", 2)]);
    publisher.announce(&namespace).await;

    let running = start(&relay, &out, true);
    until_asked(&mut asked, ".catalog").await;
    publisher
        .publish(1, 0, &[(&catalog(true), ObjectProperties::default())])
        .await;
    until_asked(&mut asked, "video").await;
    publish_two_groups(&publisher).await;
    until_archived(&running.progress, 7).await;

    running.stop.send(true).expect("the recorder is running");
    let summary = within("the recorder to finish", running.task)
        .await
        .expect("no panic");
    assert_eq!(summary.error, None);

    let root = out.join("acme/rec_1/ada").join(DEVICE);
    let (header, objects) = objects_in(&root.join("video/a1-s00000.mqa"));
    assert!(header.encrypted);
    assert_eq!(objects.len(), 6);
    assert!(
        !root.join("video/a1-r1-p00000.mp4").exists(),
        "no CMAF from ciphertext"
    );

    assert!(summary.manifest.encrypted);
    assert!(
        summary
            .manifest
            .artifacts
            .iter()
            .all(|artifact| artifact.kind == ArtifactKind::Archive)
    );
    let video = summary
        .manifest
        .tracks
        .iter()
        .find(|track| track.track.ends_with("/video"))
        .expect("video");
    assert!(
        video
            .cmaf_skipped
            .as_deref()
            .is_some_and(|reason| reason.contains("end-to-end"))
    );

    let _ = std::fs::remove_dir_all(&out);
}

/// A publisher that leaves and comes back is two runs of files, with the
/// departure marked, not one file with an unexplained gap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_publisher_leaving_finishes_its_files() {
    let relay = relay();
    let out = scratch("departed");
    let namespace =
        TrackNamespace::from_parts([TENANT, "r", ROOM, "ada", DEVICE]).expect("a namespace");

    let mut publisher = Publisher::connect(&relay, &token("ada", PUBLISHER_JKT, 3)).await;
    let mut asked = publisher.answer(&[(".catalog", 1), ("video", 2)]);
    publisher.announce(&namespace).await;

    let running = start(&relay, &out, false);
    until_asked(&mut asked, ".catalog").await;
    publisher
        .publish(1, 0, &[(&catalog(false), ObjectProperties::default())])
        .await;
    until_asked(&mut asked, "video").await;
    publish_two_groups(&publisher).await;
    until_archived(&running.progress, 7).await;

    publisher.withdraw();
    let first = out
        .join("acme/rec_1/ada")
        .join(DEVICE)
        .join("video/a1-s00000.mqa");
    within("the departure to finish the archive", async {
        while !first.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;

    let mut reader =
        Reader::open(std::fs::File::open(&first).expect("the archive")).expect("an archive");
    let mut departed = false;
    let mut ended = false;
    while let Some(record) = reader.next_record().expect("intact") {
        match record {
            Record::Departed { .. } => departed = true,
            Record::End { objects, .. } => {
                assert_eq!(objects, 6);
                ended = true;
            }
            _ => {}
        }
    }
    assert!(departed && ended, "a departed publisher's file is finished");

    running.stop.send(true).expect("the recorder is running");
    let summary = within("the recorder to finish", running.task)
        .await
        .expect("no panic");
    assert_eq!(summary.error, None);
    let _ = std::fs::remove_dir_all(&out);
}

/// Somebody already in the room, watching ada, which is what makes the relay
/// pull and cache her tracks before the recorder arrives.
struct Viewer {
    session: moqom_client::Session,
    subscriptions: Vec<moqom_client::Subscription>,
}

impl Viewer {
    async fn connect(relay: &Relay) -> Self {
        let token = token("bea", "viewerviewerview-and-the-rest", 0);
        let credentials = moqom_client::Credentials::bearer(token.as_bytes());
        let session = moqom_client::Session::connect(
            relay.addr,
            "localhost",
            moqom_client::tls::pinned(relay.certificate.clone()),
            Some(&credentials),
        )
        .await
        .expect("the viewer is admitted");
        Self {
            session,
            subscriptions: Vec::new(),
        }
    }

    async fn watch(&mut self, namespace: &TrackNamespace, track: &str) {
        let full = moqom_client::FullTrackName::new(
            namespace.clone(),
            Bytes::copy_from_slice(track.as_bytes()),
        )
        .expect("a track name");
        let subscription = within("the viewer's subscription", self.session.subscribe(full))
            .await
            .expect("subscribed");
        self.subscriptions.push(subscription);
    }

    /// Read `count` objects off the latest subscription.
    async fn received(&mut self, count: usize) {
        let subscription = self.subscriptions.last_mut().expect("a subscription");
        for _ in 0..count {
            within("the viewer to receive", subscription.next_object())
                .await
                .expect("readable")
                .expect("an object");
        }
    }
}

async fn until_tracks(progress: &moqom_recorder::recorder::Progress, tracks: u64) {
    within("the recorder to subscribe", async {
        while progress.tracks.load(Ordering::Relaxed) < tracks {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    // SUBSCRIBE_OK is sent once the relay has the subscriber; this only lets
    // the recorder's task get to its read.
    tokio::time::sleep(Duration::from_millis(100)).await;
}

fn manifest_track<'a>(
    manifest: &'a Manifest,
    track: &str,
) -> &'a moqom_recorder::manifest::TrackEntry {
    manifest
        .tracks
        .iter()
        .find(|entry| entry.track.ends_with(track))
        .expect("the track is in the manifest")
}

/// A recorder joining while a group is in flight records that group from its
/// first object, by fetching it from the relay once the subscription has
/// shown where the live edge is -- and the catalog, which nobody republishes,
/// from the relay's cache at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recorder_joining_mid_group_catches_up_on_the_group_in_flight() {
    let relay = relay();
    let out = scratch("catch-up");
    let namespace =
        TrackNamespace::from_parts([TENANT, "r", ROOM, "ada", DEVICE]).expect("a namespace");

    let mut publisher = Publisher::connect(&relay, &token("ada", PUBLISHER_JKT, 3)).await;
    let mut asked = publisher.answer(&[(".catalog", 1), ("video", 2)]);
    publisher.announce(&namespace).await;

    let mut viewer = Viewer::connect(&relay).await;
    viewer.watch(&namespace, ".catalog").await;
    until_asked(&mut asked, ".catalog").await;
    publisher
        .publish(1, 0, &[(&catalog(false), ObjectProperties::default())])
        .await;
    viewer.received(1).await;
    viewer.watch(&namespace, "video").await;
    until_asked(&mut asked, "video").await;

    let base = 1_700_000_000_000_000u64;
    let key = frame(0x65, 400);
    let delta = frame(0x41, 120);
    let mut in_flight = publisher.open(2, 5).await;
    in_flight.write(&key, properties(base, true)).await;
    in_flight
        .write(&delta, properties(base + 33_333, false))
        .await;
    viewer.received(2).await;

    let running = start(&relay, &out, false);
    until_tracks(&running.progress, 2).await;
    in_flight
        .write(&delta, properties(base + 66_666, false))
        .await;
    in_flight.finish();
    publisher
        .publish(
            2,
            6,
            &[
                (&key, properties(base + 100_000, true)),
                (&delta, properties(base + 133_333, false)),
                (&delta, properties(base + 166_666, false)),
            ],
        )
        .await;
    until_archived(&running.progress, 7).await;

    running.stop.send(true).expect("the recorder is running");
    let summary = within("the recorder to finish", running.task)
        .await
        .expect("no panic");
    assert_eq!(summary.error, None);

    let root = out.join("acme/rec_1/ada").join(DEVICE);
    let (_, objects) = objects_in(&root.join("video/a1-s00000.mqa"));
    let mut ids: Vec<(u64, u64)> = objects.iter().map(|seen| (seen.0, seen.1)).collect();
    ids.sort_unstable();
    assert_eq!(
        ids,
        [(5, 0), (5, 1), (5, 2), (6, 0), (6, 1), (6, 2)],
        "the group in flight is whole, and nothing is archived twice"
    );

    let video = manifest_track(&summary.manifest, "/video");
    assert_eq!(
        video.joins,
        [Join {
            session: 1,
            from: JoinFrom::CaughtUp,
            group: Some(5),
            object: Some(0),
            reason: None,
        }]
    );
    let catalog = manifest_track(&summary.manifest, "/.catalog");
    assert_eq!(catalog.joins.len(), 1);
    assert_eq!(catalog.joins[0].from, JoinFrom::CaughtUp);
    assert_eq!(catalog.joins[0].object, Some(0));

    // The group-5 CMAF fragment is there too: the fetched group arrived
    // while the live one was still held for reordering.
    let cmaf = std::fs::read(root.join("video/a1-r1-p00000.mp4")).expect("a CMAF file");
    assert_eq!(
        cmaf.windows(4).filter(|window| window == b"moof").count(),
        2,
        "one fragment per group, the caught-up one included"
    );
    let _ = std::fs::remove_dir_all(&out);
}

/// A relay that keeps nothing cannot answer the catch-up, and the recorder
/// says so rather than pretending the track began where it did.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_the_group_in_flight_the_recording_starts_at_the_next_and_says_so() {
    let relay = relay_with(Limits::none(), 0);
    let out = scratch("no-catch-up");
    let namespace =
        TrackNamespace::from_parts([TENANT, "r", ROOM, "ada", DEVICE]).expect("a namespace");

    let mut publisher = Publisher::connect(&relay, &token("ada", PUBLISHER_JKT, 3)).await;
    let mut asked = publisher.answer(&[(".catalog", 1), ("video", 2)]);
    publisher.announce(&namespace).await;

    let mut viewer = Viewer::connect(&relay).await;
    viewer.watch(&namespace, ".catalog").await;
    until_asked(&mut asked, ".catalog").await;
    publisher
        .publish(1, 0, &[(&catalog(false), ObjectProperties::default())])
        .await;
    viewer.received(1).await;
    viewer.watch(&namespace, "video").await;
    until_asked(&mut asked, "video").await;

    let base = 1_700_000_000_000_000u64;
    let key = frame(0x65, 400);
    let delta = frame(0x41, 120);
    let mut in_flight = publisher.open(2, 5).await;
    in_flight.write(&key, properties(base, true)).await;
    viewer.received(1).await;

    let running = start(&relay, &out, false);
    until_tracks(&running.progress, 1).await;
    // Nothing retained the catalog, so the recorder learns of video only when
    // it is restated.
    publisher
        .publish(1, 1, &[(&catalog(false), ObjectProperties::default())])
        .await;
    until_tracks(&running.progress, 2).await;
    in_flight
        .write(&delta, properties(base + 33_333, false))
        .await;
    in_flight.finish();
    publisher
        .publish(
            2,
            6,
            &[
                (&key, properties(base + 100_000, true)),
                (&delta, properties(base + 133_333, false)),
            ],
        )
        .await;
    until_archived(&running.progress, 3).await;
    // Long enough for the refused catch-up to be written down.
    tokio::time::sleep(Duration::from_millis(300)).await;

    running.stop.send(true).expect("the recorder is running");
    let summary = within("the recorder to finish", running.task)
        .await
        .expect("no panic");
    assert_eq!(summary.error, None);

    let root = out.join("acme/rec_1/ada").join(DEVICE);
    let (_, objects) = objects_in(&root.join("video/a1-s00000.mqa"));
    let ids: Vec<(u64, u64)> = objects.iter().map(|seen| (seen.0, seen.1)).collect();
    assert_eq!(ids, [(6, 0), (6, 1)]);

    let video = manifest_track(&summary.manifest, "/video");
    assert_eq!(video.joins.len(), 1);
    assert_eq!(video.joins[0].from, JoinFrom::NextGroup);
    assert_eq!(
        (video.joins[0].group, video.joins[0].object),
        (Some(6), Some(0))
    );
    assert!(video.joins[0].reason.is_some());
    let catalog = manifest_track(&summary.manifest, "/.catalog");
    assert_eq!(catalog.joins[0].from, JoinFrom::NextGroup);
    assert!(catalog.joins[0].reason.is_some());
    let _ = std::fs::remove_dir_all(&out);
}

/// A room at its ceiling still admits its recorder, and the recorder does not
/// take anybody's place: the next person is refused for the people in the
/// room, not for the recorder.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_room_admits_its_recorder_and_the_recorder_takes_no_seat() {
    let relay = relay_with(Limits::default(), 1);
    let out = scratch("full");
    let namespace =
        TrackNamespace::from_parts([TENANT, "r", ROOM, "ada", DEVICE]).expect("a namespace");

    let mut publisher = Publisher::connect(&relay, &token("ada", PUBLISHER_JKT, 3)).await;
    let mut asked = publisher.answer(&[(".catalog", 1), ("video", 2)]);
    publisher.announce(&namespace).await;

    let refused = |relay: &Relay| {
        let token = token("bea", "viewerviewerview-and-the-rest", 0);
        let addr = relay.addr;
        let tls = moqom_client::tls::pinned(relay.certificate.clone());
        async move {
            let credentials = moqom_client::Credentials::bearer(token.as_bytes());
            match moqom_client::Session::connect(addr, "localhost", tls, Some(&credentials)).await {
                Ok(session) => {
                    // Refusal can arrive as the connection closing just after
                    // SETUP rather than in place of it.
                    let reason = within("a refusal", session.closed()).await;
                    reason.to_string()
                }
                Err(failure) => failure.to_string(),
            }
        }
    };
    assert!(
        refused(&relay).await.contains("full"),
        "the room is full before the recorder arrives"
    );

    let running = start(&relay, &out, false);
    until_asked(&mut asked, ".catalog").await;
    publisher
        .publish(1, 0, &[(&catalog(false), ObjectProperties::default())])
        .await;
    until_asked(&mut asked, "video").await;
    publish_two_groups(&publisher).await;
    until_archived(&running.progress, 7).await;

    assert!(
        refused(&relay).await.contains("full"),
        "still full, and for the same one person"
    );

    running.stop.send(true).expect("the recorder is running");
    let summary = within("the recorder to finish", running.task)
        .await
        .expect("no panic");
    assert_eq!(summary.error, None);
    let video = manifest_track(&summary.manifest, "/video");
    assert_eq!(video.objects, 6);
    let _ = std::fs::remove_dir_all(&out);
}
