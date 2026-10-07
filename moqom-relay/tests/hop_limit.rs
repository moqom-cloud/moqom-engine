//! draft-elliottwave-moq-hop-limit, end to end.
//!
//! The draft's claims, each against relays that are really linked: a request is
//! forwarded through at most `MAX_HOP_LIMIT` relays, each spends one, the one that
//! would forward with nothing left refuses with `HOP_LIMIT_EXCEEDED`, the refusal
//! travels back down the chain, and a cycle ends in that refusal rather than in a
//! request waiting on itself.
//!
//! The draft-22 viewer here is written against the draft, for the reason
//! `drafts.rs` gives, and negotiates `HOP_LIMIT` by sending `HOP_LIMIT_SUPPORTED`.

mod support;

use bytes::{Bytes, BytesMut};
use moqom_proto::control::params::param_type;
use moqom_proto::control::setup::option_type;
use moqom_proto::control::{
    ControlFrame, MessageBody, MessageType, Parameter, Parameters, RequestError, RequestErrorCode,
    RequestId, Setup, Subscribe, write_message_in,
};
use moqom_proto::error::DecodeError;
use moqom_proto::model::{FullTrackName, TrackAlias};
use moqom_proto::{Draft, VarInt};
use moqom_transport::alpn;
use support::{Client, Relay, closed_reason, dial, namespace, track, within};
use web_transport_quinn::{RecvStream, SendStream};

const D22: Draft = Draft::D22;

/// A draft-22 viewer.
struct Peer {
    session: moqom_transport::Session,
    next_request: u64,
    /// The relay's SETUP.
    setup: Setup,
    _control: (SendStream, Frames),
    _endpoint: quinn::Endpoint,
}

impl Peer {
    /// Connect sending `HOP_LIMIT_SUPPORTED`, so `HOP_LIMIT` is negotiated.
    async fn connect(relay: &Relay) -> Self {
        let mut setup = Setup::new();
        setup
            .options
            .set_bytes(option_type::HOP_LIMIT_SUPPORTED, Bytes::new())
            .expect("an odd option");
        Self::connect_with(relay, setup).await
    }

    async fn connect_with(relay: &Relay, ours: Setup) -> Self {
        let (endpoint, session) = dial(relay, alpn::MOQT_DRAFT_22).await;
        let mut send = session
            .open_uni()
            .await
            .expect("opening our control stream");
        write(&mut send, &ours).await;
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

    /// SUBSCRIBE carrying `HOP_LIMIT` if `hop_limit` is given, and the answer.
    ///
    /// The request stream is returned with a success, since closing it is
    /// unsubscribing.
    async fn subscribe(
        &mut self,
        track: &FullTrackName,
        hop_limit: Option<u64>,
    ) -> Result<(SendStream, Frames), RequestError> {
        let mut request = Subscribe::new(self.request_id(), track.clone());
        if let Some(hop_limit) = hop_limit {
            request.parameters = Parameters::from_vec(vec![
                Parameter::varint(
                    param_type::HOP_LIMIT,
                    VarInt::new(hop_limit).expect("a varint"),
                )
                .expect("an even type"),
            ]);
        }
        let (mut send, recv) = self.session.open_bi().await.expect("a request stream");
        write(&mut send, &request).await;
        let mut frames = Frames::new(recv);
        let frame = within("an answer to SUBSCRIBE", frames.expect()).await;
        match frame.message_type {
            MessageType::SubscribeOk => Ok((send, frames)),
            MessageType::RequestError => Err(frame
                .parse_in(D22, RequestError::decode)
                .expect("a REQUEST_ERROR")),
            other => panic!("{other:?} in answer to SUBSCRIBE"),
        }
    }
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
        loop {
            let mut cursor = &self.buffer[..];
            match ControlFrame::decode_in(D22, &mut cursor) {
                Ok(frame) => {
                    let consumed = self.buffer.len() - cursor.len();
                    let _ = self.buffer.split_to(consumed);
                    return frame;
                }
                Err(DecodeError::Short { .. }) => {}
                Err(e) => panic!("undecodable draft-22 frame: {e}"),
            }
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk).await {
                Ok(Some(0) | None) | Err(_) => panic!("the stream closed before a message"),
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

/// Wait for an announcement to reach the fabric before subscribing to it.
async fn registered(relay: &Relay) {
    within("the announcement to register", async {
        while relay.fabric.namespaces().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

/// An origin holding a publisher, a middle relay and an edge, linked in a line.
struct Chain {
    origin: Relay,
    _middle: Relay,
    edge: Relay,
    publisher: Client,
    _announcement: support::Announcement,
    _links: Vec<tokio::task::JoinHandle<Result<(), String>>>,
}

impl Chain {
    async fn new() -> Self {
        let origin = Relay::start();
        let middle = Relay::start();
        let edge = Relay::start();
        let mut publisher = Client::connect(&origin).await;
        let announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
        registered(&origin).await;
        let links = vec![
            middle.attach_to(&origin, None).await,
            edge.attach_to(&middle, None).await,
        ];
        Self {
            origin,
            _middle: middle,
            edge,
            publisher,
            _announcement: announcement,
            _links: links,
        }
    }
}

#[tokio::test]
async fn the_relay_offers_hop_limit_in_its_draft_22_setup() {
    let relay = Relay::start();
    let peer = Peer::connect(&relay).await;
    let offered: Vec<_> = peer
        .setup
        .options
        .as_parameters()
        .as_slice()
        .iter()
        .filter(|option| option.type_value() == option_type::HOP_LIMIT_SUPPORTED)
        .collect();
    assert_eq!(offered.len(), 1, "HOP_LIMIT_SUPPORTED, once");
    assert_eq!(
        offered[0].as_bytes().map(Bytes::len),
        Some(0),
        "with an empty value"
    );
}

/// Each relay spends one: a budget of two crosses the edge and the middle and
/// is served by the origin's publisher, and a budget of one is spent by the
/// edge, so the middle has none left to forward with and refuses — and the
/// refusal reaches the viewer two relays away with the code it was given.
#[tokio::test]
async fn the_hop_limit_decrements_across_three_relays_and_refuses_at_zero() {
    let chain = Chain::new().await;
    let mut viewer = Peer::connect(&chain.edge).await;

    let video = track(&["acme", "room-42"], "video");
    let (_served, subscribed) = tokio::join!(
        chain.publisher.answer_subscription(TrackAlias::from(1_u32)),
        viewer.subscribe(&video, Some(2)),
    );
    let _subscription = subscribed.expect("two hops reach the origin");

    let audio = track(&["acme", "room-42"], "audio");
    let refused = viewer
        .subscribe(&audio, Some(1))
        .await
        .err()
        .expect("one hop runs out at the middle relay");
    assert_eq!(refused.code, RequestErrorCode::HOP_LIMIT_EXCEEDED);
    assert_eq!(refused.code.get(), 0x37);
    chain.publisher.asked_nothing_further().await;

    let screen = track(&["acme", "room-42"], "screen");
    let refused = viewer
        .subscribe(&screen, Some(0))
        .await
        .err()
        .expect("no hops is refused at the edge");
    assert_eq!(refused.code, RequestErrorCode::HOP_LIMIT_EXCEEDED);
    assert!(
        viewer.session.close_reason().is_none(),
        "HOP_LIMIT_EXCEEDED refuses the request, not the session"
    );
}

/// A viewer sends no budget and gets `MAX_HOP_LIMIT`, three, which is enough for
/// a chain of three; asking for more than three is clamped rather than honoured.
#[tokio::test]
async fn absent_is_the_maximum_and_more_is_clamped_to_it() {
    let chain = Chain::new().await;
    let mut viewer = Peer::connect(&chain.edge).await;

    let video = track(&["acme", "room-42"], "video");
    let (_served, subscribed) = tokio::join!(
        chain.publisher.answer_subscription(TrackAlias::from(1_u32)),
        viewer.subscribe(&video, None),
    );
    let _subscription = subscribed.expect("the default budget reaches the origin");

    let audio = track(&["acme", "room-42"], "audio");
    let (_served, subscribed) = tokio::join!(
        chain.publisher.answer_subscription(TrackAlias::from(2_u32)),
        viewer.subscribe(&audio, Some(1_000)),
    );
    let _subscription = subscribed.expect("a large budget is clamped, not refused");
    assert_eq!(chain.origin.fabric.hop_limit(), 3);
}

/// Draft-19 has no `HOP_LIMIT_EXCEEDED`, so a draft-19 viewer whose budget runs
/// out further up a draft-22 chain is told `DOES_NOT_EXIST`, as it always was.
#[tokio::test]
async fn a_draft_19_viewer_still_reads_a_spent_budget_as_does_not_exist() {
    let chain = Chain::new().await;
    let mut viewer = Client::connect(&chain.edge).await;
    let audio = track(&["acme", "room-42"], "audio");
    let Err(refused) = viewer
        .subscribe_with(&audio, &[(param_type::RELAY_HOPS, 1)])
        .await
    else {
        panic!("one hop runs out at the middle relay");
    };
    assert_eq!(refused, 0x10, "DOES_NOT_EXIST");
}

/// The aggregation rule is what makes this terminate. Two relays that each name
/// the other as parent forward a request for a track neither holds round the
/// cycle; when it comes back to the first relay with a smaller budget it must not
/// wait on the request it is itself part of, so it asks again, spends its budget,
/// and the refusal at zero unwinds the whole cycle back to the viewer.
#[tokio::test]
async fn a_cycle_of_relays_ends_in_hop_limit_exceeded() {
    let left = Relay::start();
    let right = Relay::start();
    let _left_link = left.attach_to(&right, None).await;
    let _right_link = right.attach_to(&left, None).await;

    let mut viewer = Peer::connect(&left).await;
    let nowhere = track(&["acme", "room-42"], "video");
    let refused = viewer
        .subscribe(&nowhere, None)
        .await
        .err()
        .expect("a cycle cannot serve a track nobody publishes");
    assert_eq!(refused.code, RequestErrorCode::HOP_LIMIT_EXCEEDED);
}

#[tokio::test]
async fn hop_limit_without_negotiating_it_is_a_protocol_violation() {
    let relay = Relay::start();
    let mut viewer = Peer::connect_with(&relay, Setup::new()).await;
    let mut request = Subscribe::new(viewer.request_id(), track(&["room"], "video"));
    request.parameters = Parameters::from_vec(vec![
        Parameter::varint(param_type::HOP_LIMIT, VarInt::from_u32(1)).expect("an even type"),
    ]);
    let (mut send, _recv) = viewer.session.open_bi().await.expect("a request stream");
    write(&mut send, &request).await;

    let closed = closed_reason(&viewer.session).await;
    assert_eq!(closed.code, 0x3, "PROTOCOL_VIOLATION");
}

#[tokio::test]
async fn hop_limit_supported_with_a_value_is_a_protocol_violation() {
    let relay = Relay::start();
    let (_endpoint, session) = dial(&relay, alpn::MOQT_DRAFT_22).await;
    let mut setup = Setup::new();
    setup
        .options
        .set_bytes(option_type::HOP_LIMIT_SUPPORTED, Bytes::from_static(b"x"))
        .expect("an odd option");
    let mut send = session.open_uni().await.expect("a control stream");
    write(&mut send, &setup).await;

    let closed = closed_reason(&session).await;
    assert_eq!(closed.code, 0x3, "PROTOCOL_VIOLATION");
}
