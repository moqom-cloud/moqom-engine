//! Draft-22 and draft-19 peers on the same relay.
//!
//! The draft-22 peer here is written against the draft, not against the
//! relay's session code, for the reason the support module gives: a framing
//! mistake shared by both ends is observed by neither. It does not declare
//! `MOQOM_PARAMETERS`, so it is also the peer that must never be sent one of
//! MOQOM's private parameters — every message it receives is decoded with
//! draft-22's parameter checks, which reject them.

mod support;

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use moqom_proto::control::params::param_type as p;
use moqom_proto::control::typed::LocationFilter;
use moqom_proto::control::{
    ControlFrame, Fetch, FetchKind, FetchOk, MessageBody, MessageType, ParamValue, Parameter,
    Parameters, PublishNamespace, PublishStateNotify, RequestError, RequestId, RequestOk, Setup,
    Subscribe, SubscribeOk, write_message_in,
};
use moqom_proto::data::{
    FetchHeader, FetchObject, FetchReader, FetchRecord, FetchWriter, GroupOrder, SubgroupHeader,
    SubgroupObject, SubgroupReader, SubgroupSource, SubgroupWriter,
};
use moqom_proto::error::DecodeError;
use moqom_proto::model::{FullTrackName, GroupId, Location, ObjectId, TrackAlias, TrackNamespace};
use moqom_proto::{Draft, VarInt};
use moqom_transport::alpn;
use support::{Client, Relay, closed_reason, dial, namespace, track, within};
use web_transport_quinn::{RecvStream, SendStream};

const D22: Draft = Draft::D22;

fn location(group: u64, object: u64) -> Location {
    Location::new(
        GroupId::new(VarInt::new(group).unwrap()),
        ObjectId::new(VarInt::new(object).unwrap()),
    )
}

fn typed(type_value: u64, value: ParamValue) -> Parameter {
    Parameter::typed(type_value, value).expect("a draft-22 parameter")
}

/// A draft-22 peer, from SETUP onwards.
struct Peer {
    session: moqom_transport::Session,
    next_request: u64,
    /// The relay's SETUP.
    setup: Setup,
    _control: (SendStream, Frames),
    _endpoint: quinn::Endpoint,
}

impl Peer {
    /// Connect offering only `moqt-22`, and exchange SETUP on the pair of
    /// unidirectional control streams §6.3 requires.
    async fn connect(relay: &Relay) -> Self {
        let (endpoint, session) = dial(relay, alpn::MOQT_DRAFT_22).await;
        let mut send = session
            .open_uni()
            .await
            .expect("opening our control stream");
        write(&mut send, &Setup::new()).await;

        let recv = within("the relay's control stream", session.accept_uni())
            .await
            .expect("the relay opens its control stream");
        let mut frames = Frames::new(recv);
        let frame = within("the relay's SETUP", frames.expect()).await;
        assert_eq!(frame.message_type, MessageType::Setup);
        let len = frame.body.len();
        let setup = frame
            .parse_in(D22, |body| Setup::decode(body, len))
            .expect("a draft-22 SETUP");
        Self {
            session,
            next_request: 0,
            setup,
            _control: (send, frames),
            _endpoint: endpoint,
        }
    }

    fn request_id(&mut self) -> RequestId {
        let id = RequestId::new(self.next_request).expect("request ids remain");
        self.next_request += 2;
        id
    }

    async fn request(&mut self, message: &impl MessageBody) -> (SendStream, Frames) {
        let (mut send, recv) = self.session.open_bi().await.expect("a request stream");
        write(&mut send, message).await;
        (send, Frames::new(recv))
    }

    /// `PUBLISH_NAMESPACE`, insisting on the `REQUEST_OK` draft-22 answers with.
    async fn announce(&mut self, namespace: &TrackNamespace) -> (SendStream, Frames) {
        let id = self.request_id();
        let (send, mut frames) = self
            .request(&PublishNamespace::new(id, namespace.clone()))
            .await;
        let frame = within("PUBLISH_NAMESPACE_OK", frames.expect()).await;
        assert_eq!(frame.message_type, MessageType::RequestOk);
        frame
            .parse_in(D22, RequestOk::decode)
            .expect("a REQUEST_OK");
        (send, frames)
    }

    async fn subscribe(
        &mut self,
        track: &FullTrackName,
        parameters: Vec<Parameter>,
    ) -> (RequestId, SubscribeOk, SendStream, Frames) {
        let id = self.request_id();
        let mut request = Subscribe::new(id, track.clone());
        request.parameters = Parameters::from_vec(parameters);
        let (send, mut frames) = self.request(&request).await;
        let frame = within("an answer to SUBSCRIBE", frames.expect()).await;
        assert_eq!(
            frame.message_type,
            MessageType::SubscribeOk,
            "refused: {:?}",
            frame.parse_in(D22, RequestError::decode)
        );
        let ok = frame
            .parse_in(D22, SubscribeOk::decode)
            .expect("a SUBSCRIBE_OK");
        (id, ok, send, frames)
    }

    /// Answer the relay's next SUBSCRIBE with `alias`.
    async fn answer_subscription(&self, alias: TrackAlias) -> (FullTrackName, SendStream, Frames) {
        let (mut send, recv) = within("the relay's SUBSCRIBE", self.session.accept_bi())
            .await
            .expect("a request stream");
        let mut frames = Frames::new(recv);
        let frame = within("a SUBSCRIBE", frames.expect()).await;
        assert_eq!(frame.message_type, MessageType::Subscribe);
        let request = frame
            .parse_in(D22, Subscribe::decode)
            .expect("a SUBSCRIBE with only draft-22 parameters");
        assert!(
            request.request_id.get() % 2 == 1,
            "a server's request IDs are odd"
        );
        write(&mut send, &SubscribeOk::new(alias)).await;
        (request.track, send, frames)
    }

    async fn publish_group(&self, alias: TrackAlias, group: u64, payloads: &[&[u8]]) {
        let mut stream = self.session.open_uni().await.expect("a data stream");
        let buf = D22.scope(|| {
            let header = SubgroupHeader::new(
                alias,
                GroupId::new(VarInt::new(group).unwrap()),
                SubgroupSource::Zero,
            );
            let mut buf = BytesMut::new();
            header.encode(&mut buf);
            let mut writer = SubgroupWriter::new(&header);
            for (id, payload) in payloads.iter().enumerate() {
                let object = SubgroupObject::new(id as u32, Bytes::copy_from_slice(payload));
                writer.write(&mut buf, &object).expect("a writable object");
            }
            buf
        });
        stream.write_all(&buf).await.expect("writing a subgroup");
        stream.finish().expect("finishing a subgroup");
    }

    /// The next unidirectional stream the relay opens, read to its end.
    async fn next_stream(&self) -> Bytes {
        let mut recv = within("a data stream", self.session.accept_uni())
            .await
            .expect("the relay opens a data stream");
        within("the data stream's end", recv.read_to_end(1 << 20))
            .await
            .expect("reading a data stream")
            .into()
    }

    async fn read_subgroup(&self) -> (SubgroupHeader, Vec<Bytes>) {
        let bytes = self.next_stream().await;
        D22.scope(|| {
            let mut cursor = &bytes[..];
            let header = SubgroupHeader::decode(&mut cursor).expect("a draft-22 subgroup header");
            let mut reader = SubgroupReader::new(&header);
            let mut payloads = Vec::new();
            while !cursor.is_empty() {
                match reader.read(&mut cursor).expect("a draft-22 object").content {
                    moqom_proto::data::SubgroupContent::Normal { payload, .. } => {
                        payloads.push(payload);
                    }
                    moqom_proto::data::SubgroupContent::Terminal(_) => break,
                }
            }
            (header, payloads)
        })
    }

    async fn read_fetch_stream(&self) -> (RequestId, Vec<FetchRecord>) {
        let bytes = self.next_stream().await;
        D22.scope(|| {
            let mut cursor = &bytes[..];
            let header = FetchHeader::decode(&mut cursor).expect("a draft-22 FETCH_HEADER");
            let mut reader = FetchReader::new(GroupOrder::Ascending);
            let mut records = Vec::new();
            while !cursor.is_empty() {
                records.push(reader.read(&mut cursor).expect("a draft-22 fetch record"));
            }
            (header.request_id, records)
        })
    }
}

fn payloads(records: &[FetchRecord]) -> Vec<Bytes> {
    records
        .iter()
        .filter_map(|record| match record {
            FetchRecord::Object(object) => Some(object.payload.clone()),
            _ => None,
        })
        .collect()
}

/// Control messages off a stream, in draft-22 framing.
struct Frames {
    stream: RecvStream,
    buffer: BytesMut,
}

impl Frames {
    fn new(stream: RecvStream) -> Self {
        Self {
            stream,
            buffer: BytesMut::new(),
        }
    }

    async fn expect(&mut self) -> ControlFrame {
        self.next()
            .await
            .expect("a message rather than a closed stream")
    }

    async fn next(&mut self) -> Option<ControlFrame> {
        loop {
            let mut cursor = &self.buffer[..];
            match ControlFrame::decode_in(D22, &mut cursor) {
                Ok(frame) => {
                    let consumed = self.buffer.len() - cursor.len();
                    let _ = self.buffer.split_to(consumed);
                    return Some(frame);
                }
                Err(DecodeError::Short { .. }) => {}
                Err(e) => panic!("undecodable draft-22 frame: {e}"),
            }
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk).await {
                Ok(Some(0) | None) | Err(_) => return None,
                Ok(Some(n)) => self.buffer.extend_from_slice(&chunk[..n]),
            }
        }
    }
}

async fn write(stream: &mut SendStream, message: &impl MessageBody) {
    let mut buf = BytesMut::new();
    write_message_in(D22, &mut buf, message).expect("a message that fits a frame");
    stream.write_all(&buf).await.expect("writing a message");
}

#[tokio::test]
async fn the_relay_answers_a_draft_22_setup_in_kind() {
    let relay = Relay::start();
    let peer = Peer::connect(&relay).await;
    assert!(
        peer.setup.options.moqom_parameters(),
        "the relay offers its private parameters to a draft-22 peer"
    );
}

#[tokio::test]
async fn a_draft_22_viewer_watches_a_draft_19_publisher() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let _announced = publisher.announce(&namespace(&["room"])).await;
    let mut viewer = Peer::connect(&relay).await;

    let name = track(&["room"], "video");
    let subscribing = viewer.subscribe(&name, Vec::new());
    let answering = publisher.answer_subscription(TrackAlias::new(VarInt::from_u32(7)));
    let ((_, ok, _send, _frames), _served) = tokio::join!(subscribing, answering);

    publisher
        .publish_group(
            TrackAlias::new(VarInt::from_u32(7)),
            GroupId::ZERO,
            &[b"a", b"b"],
        )
        .await;
    let (header, objects) = viewer.read_subgroup().await;
    assert_eq!(
        header.track_alias, ok.track_alias,
        "rewritten to the viewer's alias"
    );
    assert_eq!(
        objects,
        vec![Bytes::from_static(b"a"), Bytes::from_static(b"b")]
    );
}

#[tokio::test]
async fn a_draft_19_viewer_watches_a_draft_22_publisher() {
    let relay = Relay::start();
    let mut publisher = Peer::connect(&relay).await;
    let _announced = publisher.announce(&namespace(&["room"])).await;
    let mut viewer = Client::connect(&relay).await;

    let name = track(&["room"], "video");
    let subscribing = viewer.subscribe(&name);
    let answering = publisher.answer_subscription(TrackAlias::new(VarInt::from_u32(3)));
    let (subscription, (asked_for, _send, _frames)) = tokio::join!(subscribing, answering);
    let subscription = subscription.expect("subscribed");
    assert_eq!(asked_for, name);

    publisher
        .publish_group(TrackAlias::new(VarInt::from_u32(3)), 4, &[b"x", b"y", b"z"])
        .await;
    let (header, objects) = viewer.read_subgroup().await;
    assert_eq!(header.track_alias, subscription.alias);
    assert_eq!(header.group.get(), 4);
    assert_eq!(objects.len(), 3);
    assert_eq!(objects[2], Bytes::from_static(b"z"));
}

#[tokio::test]
async fn a_fill_delivers_the_cached_groups_on_a_fetch_stream() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let _announced = publisher.announce(&namespace(&["room"])).await;
    let name = track(&["room"], "video");
    let alias = TrackAlias::new(VarInt::from_u32(1));

    // A draft-19 viewer first, so the relay is pulling and caching.
    let mut early = Client::connect(&relay).await;
    let (early_subscription, _served) =
        tokio::join!(early.subscribe(&name), publisher.answer_subscription(alias));
    let _early_subscription = early_subscription.expect("subscribed");
    publisher
        .publish_group(alias, GroupId::ZERO, &[b"g0o0", b"g0o1"])
        .await;
    early.read_subgroup().await;
    publisher
        .publish_group(alias, GroupId::new(VarInt::from_u32(1)), &[b"g1o0"])
        .await;
    early.read_subgroup().await;

    let mut viewer = Peer::connect(&relay).await;
    let fill = typed(p::FILL_PARAMETERS, ParamValue::Nested(Parameters::new()));
    let (id, ok, _send, _frames) = viewer.subscribe(&name, vec![fill]).await;
    assert_eq!(
        ok.parameters
            .get(p::LARGEST_OBJECT)
            .and_then(Parameter::as_location),
        Some(location(1, 0)),
        "SUBSCRIBE_OK names the Largest Object the fill is measured against"
    );

    let (named, records) = viewer.read_fetch_stream().await;
    assert_eq!(
        named, id,
        "a fill stream carries the SUBSCRIBE's Request ID"
    );
    assert_eq!(
        payloads(&records),
        vec![
            Bytes::from_static(b"g0o0"),
            Bytes::from_static(b"g0o1"),
            Bytes::from_static(b"g1o0"),
        ]
    );

    // And the subscription carries on live after it.
    publisher
        .publish_group(alias, GroupId::new(VarInt::from_u32(2)), &[b"g2o0"])
        .await;
    let (header, objects) = viewer.read_subgroup().await;
    assert_eq!(header.group.get(), 2);
    assert_eq!(objects, vec![Bytes::from_static(b"g2o0")]);
}

#[tokio::test]
async fn a_paused_subscription_gets_no_fill() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let _announced = publisher.announce(&namespace(&["room"])).await;
    let name = track(&["room"], "video");
    let alias = TrackAlias::new(VarInt::from_u32(1));
    let mut early = Client::connect(&relay).await;
    let (early_subscription, _served) =
        tokio::join!(early.subscribe(&name), publisher.answer_subscription(alias));
    let _early_subscription = early_subscription.expect("subscribed");
    publisher
        .publish_group(alias, GroupId::ZERO, &[b"cached"])
        .await;
    early.read_subgroup().await;

    let mut viewer = Peer::connect(&relay).await;
    let fill = typed(p::FILL_PARAMETERS, ParamValue::Nested(Parameters::new()));
    let paused = typed(p::FORWARD, ParamValue::VarInt(VarInt::from_u32(0)));
    let _subscribed = viewer.subscribe(&name, vec![fill, paused]).await;
    let opened =
        tokio::time::timeout(Duration::from_millis(300), viewer.session.accept_uni()).await;
    assert!(opened.is_err(), "§3.4.1: no fill while Forward is 0");
}

#[tokio::test]
async fn a_draft_22_fetch_goes_upstream_for_what_the_cache_lacks() {
    let relay = Relay::start();
    let mut publisher = Peer::connect(&relay).await;
    let _announced = publisher.announce(&namespace(&["room"])).await;
    let mut viewer = Peer::connect(&relay).await;
    let name = track(&["room"], "video");

    let id = viewer.request_id();
    let mut fetch = Fetch::new(
        id,
        FetchKind::Filtered {
            track: name.clone(),
        },
    );
    fetch.parameters.push(typed(
        p::LOCATION_FILTER,
        ParamValue::LocationFilter(
            LocationFilter::between(location(0, 0), location(0, 1)).expect("a range"),
        ),
    ));
    let asking = viewer.request(&fetch);

    // §3.2.3: nothing is cached, so the relay must ask the publisher.
    let answering = async {
        let (mut send, recv) = within("the relay's FETCH", publisher.session.accept_bi())
            .await
            .expect("a request stream");
        let mut frames = Frames::new(recv);
        let frame = within("a FETCH", frames.expect()).await;
        assert_eq!(frame.message_type, MessageType::Fetch);
        let upstream = frame
            .parse_in(D22, Fetch::decode)
            .expect("a FETCH with only draft-22 parameters");
        assert!(matches!(upstream.kind, FetchKind::Filtered { ref track } if *track == name));
        write(&mut send, &FetchOk::new(location(0, 1))).await;

        let mut stream = publisher.session.open_uni().await.expect("a data stream");
        let buf = D22.scope(|| {
            let mut buf = BytesMut::new();
            FetchHeader::new(upstream.request_id).encode(&mut buf);
            let mut writer = FetchWriter::new(GroupOrder::Ascending);
            for (object, payload) in [(0, &b"first"[..]), (1, b"second")] {
                let record = FetchRecord::Object(FetchObject::new(location(0, object), payload));
                writer.write(&mut buf, &record).expect("a writable record");
            }
            buf
        });
        stream.write_all(&buf).await.expect("writing the fetch");
        stream.finish().expect("finishing the fetch");
        (send, frames)
    };
    let ((_send, mut frames), _upstream) = tokio::join!(asking, answering);

    let frame = within("FETCH_OK", frames.expect()).await;
    assert_eq!(
        frame.message_type,
        MessageType::FetchOk,
        "refused: {:?}",
        frame.parse_in(D22, RequestError::decode)
    );
    let ok = frame.parse_in(D22, FetchOk::decode).expect("a FETCH_OK");
    assert_eq!(ok.end, location(0, 1), "draft-22's end is inclusive");
    let (named, records) = viewer.read_fetch_stream().await;
    assert_eq!(named, id);
    assert_eq!(
        payloads(&records),
        vec![Bytes::from_static(b"first"), Bytes::from_static(b"second")]
    );
}

#[tokio::test]
async fn what_the_fill_timeout_runs_out_on_is_reported_as_timed_out() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let _announced = publisher.announce(&namespace(&["room"])).await;
    let name = track(&["room"], "video");
    let alias = TrackAlias::new(VarInt::from_u32(1));
    let mut early = Client::connect(&relay).await;
    let (early_subscription, _served) =
        tokio::join!(early.subscribe(&name), publisher.answer_subscription(alias));
    let _early_subscription = early_subscription.expect("subscribed");
    publisher
        .publish_group(alias, GroupId::new(VarInt::from_u32(1)), &[b"held"])
        .await;
    early.read_subgroup().await;

    // Group 0 was never seen here, and the publisher never answers the
    // upstream FETCH for it.
    let mut viewer = Peer::connect(&relay).await;
    let id = viewer.request_id();
    let mut fetch = Fetch::new(id, FetchKind::Filtered { track: name });
    fetch.parameters.push(typed(
        p::LOCATION_FILTER,
        ParamValue::LocationFilter(
            LocationFilter::between(location(0, 0), location(1, 0)).expect("a range"),
        ),
    ));
    fetch.parameters.push(typed(
        p::FILL_TIMEOUT,
        ParamValue::VarInt(VarInt::from_u32(100)),
    ));
    let (_send, mut frames) = viewer.request(&fetch).await;

    let frame = within("FETCH_OK", frames.expect()).await;
    assert_eq!(frame.message_type, MessageType::FetchOk);
    let ok = frame.parse_in(D22, FetchOk::decode).expect("a FETCH_OK");
    assert_eq!(ok.end, location(1, 0));
    let (_, records) = viewer.read_fetch_stream().await;
    assert!(
        matches!(records.first(), Some(FetchRecord::EndOfTimedOutRange(at)) if at.group.get() == 0),
        "group 0 is reported as timed out, got {records:?}"
    );
    assert_eq!(payloads(&records), vec![Bytes::from_static(b"held")]);
}

#[tokio::test]
async fn publish_state_notify_reaches_a_draft_22_subscriber() {
    let relay = Relay::start();
    let mut publisher = Peer::connect(&relay).await;
    let _announced = publisher.announce(&namespace(&["room"])).await;
    let mut viewer = Peer::connect(&relay).await;
    let name = track(&["room"], "video");

    let alias = TrackAlias::new(VarInt::from_u32(9));
    let ((_, _, _send, mut frames), (_, mut upstream, _upstream_frames)) = tokio::join!(
        viewer.subscribe(&name, Vec::new()),
        publisher.answer_subscription(alias)
    );

    let mut notice = PublishStateNotify::default();
    notice.parameters.push(typed(
        p::LARGEST_OBJECT,
        ParamValue::Location(location(5, 2)),
    ));
    write(&mut upstream, &notice).await;

    let frame = within("PUBLISH_STATE_NOTIFY", frames.expect()).await;
    assert_eq!(frame.message_type, MessageType::PublishStateNotify);
    let passed = frame
        .parse_in(D22, PublishStateNotify::decode)
        .expect("a PUBLISH_STATE_NOTIFY");
    assert_eq!(
        passed
            .parameters
            .get(p::LARGEST_OBJECT)
            .and_then(Parameter::as_location),
        Some(location(5, 2))
    );
}

#[tokio::test]
async fn an_unknown_parameter_is_a_protocol_violation() {
    let relay = Relay::start();
    let mut viewer = Peer::connect(&relay).await;
    let mut request = Subscribe::new(viewer.request_id(), track(&["room"], "video"));
    // 0x3E is unregistered and not private.
    request
        .parameters
        .push(Parameter::varint(0x3E, VarInt::from_u32(1)).expect("an even type"));
    let _stream = viewer.request(&request).await;

    let closed = closed_reason(&viewer.session).await;
    assert_eq!(closed.code, 0x3, "PROTOCOL_VIOLATION (§12.1)");
}
