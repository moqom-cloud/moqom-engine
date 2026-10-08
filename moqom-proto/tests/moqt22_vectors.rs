//! Byte-exact draft-22 vectors, checked against `testdata/moqt-22/*.hex`.
//!
//! The fixtures are the contract with other implementations: plain text, one
//! `name hex` per line, `#` for comments, so another codec can be checked
//! against them without reading any Rust. Every vector here is produced by
//! this crate's encoder and must also decode back to the value that produced
//! it, so a fixture line is both "what MOQOM writes" and "what MOQOM reads".
//!
//! Control vectors are whole framed messages — Type (vi64), Length (16),
//! body — so the integer encoding of the type and every field is exercised.
//! Parameter vectors are a counted parameter block holding just that one
//! parameter: Number of Parameters (vi64), Type Delta (vi64), Value.
//!
//! `MOQOM_BLESS=1 cargo test -p moqom-proto --test moqt22_vectors` rewrites
//! the fixtures from the encoder. Do that only for a deliberate wire change,
//! and read the diff: a fixture that moves is a wire format that moved.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use bytes::Bytes;
use moqom_proto::control::messages::namespace::{Namespace, NamespaceDone};
use moqom_proto::control::params::param_type as p;
use moqom_proto::control::setup::option_type;
use moqom_proto::control::typed::{Context, LocationFilter, Token};
use moqom_proto::control::{
    ControlFrame, Fetch, FetchKind, FetchOk, Goaway, MessageBody, ParamValue, Parameter,
    Parameters, Properties, Publish, PublishDone, PublishDoneStatus, PublishNamespace,
    PublishSkipped, PublishStateNotify, ReasonPhrase, Redirect, RequestError, RequestErrorCode,
    RequestId, RequestOk, RequestUpdate, Setup, StreamCount, Subscribe, SubscribeNamespace,
    SubscribeOk, SubscribeTracks, TrackStatus, write_message_in,
};
use moqom_proto::data::fetch::{FetchHeader, FetchObject, FetchRecord, FetchWriter, GroupOrder};
use moqom_proto::data::{
    ObjectDatagram, SubgroupHeader, SubgroupObject, SubgroupReader, SubgroupSource, SubgroupWriter,
};
use moqom_proto::model::{
    FullTrackName, GroupId, Location, ObjectId, SubgroupId, TrackAlias, TrackNamespace,
};
use moqom_proto::{DecodeError, Draft, VarInt, varint};

const D22: Draft = Draft::D22;

fn v(n: u64) -> VarInt {
    VarInt::new(n).unwrap()
}

fn loc(group: u64, object: u64) -> Location {
    Location::new(GroupId::new(v(group)), ObjectId::new(v(object)))
}

fn ns() -> TrackNamespace {
    TrackNamespace::from_parts([&b"moqom"[..], b"room"]).unwrap()
}

fn track() -> FullTrackName {
    FullTrackName::new(ns(), Bytes::from_static(b"video")).unwrap()
}

fn rid(n: u64) -> RequestId {
    RequestId::new(n).unwrap()
}

fn typed(type_value: u64, value: ParamValue) -> Parameter {
    Parameter::typed(type_value, value).unwrap()
}

fn uint(type_value: u64, value: u64) -> Parameter {
    typed(type_value, ParamValue::VarInt(v(value)))
}

fn bytes(type_value: u64, value: &'static [u8]) -> Parameter {
    typed(type_value, ParamValue::Bytes(Bytes::from_static(value)))
}

fn filter(f: LocationFilter) -> Parameter {
    typed(p::LOCATION_FILTER, ParamValue::LocationFilter(f))
}

fn params(list: Vec<Parameter>) -> Parameters {
    Parameters::from_vec(list)
}

fn fill() -> Parameter {
    typed(
        p::FILL_PARAMETERS,
        ParamValue::Nested(params(vec![
            uint(p::FILL_TIMEOUT, 500),
            filter(LocationFilter::RelativeStart { groups: 1 }),
        ])),
    )
}

fn props() -> Properties {
    let mut properties = Properties::new();
    properties.push(Parameter::varint(0x10, v(1)).unwrap());
    properties
}

/// Frame `message`, check it decodes back to itself, and record it.
fn message<M>(
    out: &mut BTreeMap<String, Vec<u8>>,
    name: &str,
    message: &M,
    decode: impl FnOnce(&mut Bytes) -> Result<M, DecodeError>,
) where
    M: MessageBody + PartialEq + std::fmt::Debug,
{
    let mut wire = Vec::new();
    write_message_in(D22, &mut wire, message).unwrap();
    let frame = ControlFrame::decode_in(D22, &mut wire.as_slice()).unwrap();
    assert_eq!(frame.message_type, M::MESSAGE_TYPE, "{name}");
    let back = frame.parse_in(D22, decode).unwrap();
    assert_eq!(&back, message, "{name} does not round-trip");
    out.insert(name.to_owned(), wire);
}

#[allow(clippy::too_many_lines)] // one flat list of vectors reads best
fn control() -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let o = &mut out;

    let mut setup = Setup::new();
    message(o, "setup_empty", &setup, |b| Setup::decode(b, b.len()));
    setup
        .options
        .set_bytes(option_type::PATH, &b"/moq"[..])
        .unwrap();
    setup
        .options
        .set_bytes(option_type::AUTHORIZATION_TOKEN, &b"tok"[..])
        .unwrap();
    setup
        .options
        .set_varint(option_type::MAX_REQUEST_UPDATES, 4)
        .unwrap();
    setup
        .options
        .set_bytes(option_type::MOQT_IMPLEMENTATION, &b"moqom"[..])
        .unwrap();
    message(o, "setup_client", &setup, |b| Setup::decode(b, b.len()));

    message(o, "goaway", &Goaway::new(v(5000)), Goaway::decode);
    message(
        o,
        "goaway_redirect",
        &Goaway::redirect(&b"moqt://relay.example/x"[..], v(0)).unwrap(),
        Goaway::decode,
    );

    message(
        o,
        "subscribe_minimal",
        &Subscribe::new(rid(0), track()),
        Subscribe::decode,
    );
    let mut subscribe = Subscribe::new(rid(2), track());
    subscribe.parameters = params(vec![
        uint(p::OBJECT_DELIVERY_TIMEOUT, 2000),
        bytes(p::AUTHORIZATION_TOKEN, b"tok"),
        uint(p::RENDEZVOUS_TIMEOUT, 100),
        uint(p::SUBGROUP_DELIVERY_TIMEOUT, 3000),
        uint(p::FORWARD, 0),
        uint(p::SUBSCRIBER_PRIORITY, 200),
        filter(LocationFilter::NextObject),
        uint(p::GROUP_ORDER, 2),
        fill(),
        uint(p::NEW_GROUP_REQUEST, 0),
        uint(p::INCLUDE_PROPERTIES, 0),
    ]);
    message(o, "subscribe_full", &subscribe, Subscribe::decode);

    let mut ok = SubscribeOk::new(TrackAlias::new(v(7)));
    ok.parameters = params(vec![
        uint(p::EXPIRES, 60_000),
        typed(p::LARGEST_OBJECT, ParamValue::Location(loc(12, 3))),
    ]);
    ok.properties = props();
    message(o, "subscribe_ok", &ok, SubscribeOk::decode);

    message(
        o,
        "publish_state_notify",
        &PublishStateNotify {
            parameters: params(vec![
                typed(p::LARGEST_OBJECT, ParamValue::Location(loc(12, 4))),
                uint(p::FORWARD, 0),
            ]),
        },
        PublishStateNotify::decode,
    );

    let mut publish = Publish::new(rid(1), track(), TrackAlias::new(v(9)));
    publish.parameters = params(vec![
        uint(p::EXPIRES, 1000),
        typed(p::LARGEST_OBJECT, ParamValue::Location(loc(4, 0))),
        uint(p::FORWARD, 1),
        uint(p::SUBSCRIBER_PRIORITY, 128),
        filter(LocationFilter::NextObject),
        uint(p::GROUP_ORDER, 1),
    ]);
    publish.properties = props();
    message(o, "publish", &publish, Publish::decode);

    message(
        o,
        "publish_done",
        &PublishDone::new(PublishDoneStatus::TRACK_ENDED, StreamCount::Exact(3)),
        PublishDone::decode,
    );
    let mut done = PublishDone::new(PublishDoneStatus::TOO_FAR_BEHIND, StreamCount::Unknown);
    done.reason = ReasonPhrase::new(&b"slow"[..]).unwrap();
    message(o, "publish_done_unknown_count", &done, PublishDone::decode);

    let mut fetch = Fetch::new(rid(4), FetchKind::Filtered { track: track() });
    fetch.parameters = params(vec![
        uint(p::FILL_TIMEOUT, 0),
        uint(p::SUBSCRIBER_PRIORITY, 10),
        filter(LocationFilter::Range {
            start: loc(5, 0),
            end_group_delta: 2,
            end_object: 9,
        }),
        uint(p::GROUP_ORDER, 1),
        uint(p::INCLUDE_PROPERTIES, 1),
    ]);
    message(o, "fetch", &fetch, Fetch::decode);
    message(
        o,
        "fetch_whole_track",
        &Fetch::new(rid(6), FetchKind::Filtered { track: track() }),
        Fetch::decode,
    );

    let mut fetch_ok = FetchOk::new(loc(7, 9));
    fetch_ok.end_of_track = true;
    message(o, "fetch_ok", &fetch_ok, FetchOk::decode);

    let mut status = TrackStatus::new(rid(8), track());
    status.parameters = params(vec![uint(p::INCLUDE_PROPERTIES, 0)]);
    message(o, "track_status", &status, TrackStatus::decode);

    let mut announce = PublishNamespace::new(rid(10), ns());
    announce.parameters = params(vec![bytes(p::AUTHORIZATION_TOKEN, b"tok")]);
    message(o, "publish_namespace", &announce, PublishNamespace::decode);
    message(
        o,
        "subscribe_namespace",
        &SubscribeNamespace::new(rid(12), ns()),
        SubscribeNamespace::decode,
    );
    let mut tracks = SubscribeTracks::new(rid(14), ns());
    tracks.parameters = params(vec![uint(p::FORWARD, 0), uint(p::GROUP_ORDER, 1)]);
    message(o, "subscribe_tracks", &tracks, SubscribeTracks::decode);

    let suffix = TrackNamespace::from_parts([&b"alice"[..]]).unwrap();
    message(
        o,
        "namespace",
        &Namespace::new(suffix.clone()),
        Namespace::decode,
    );
    message(
        o,
        "namespace_done",
        &NamespaceDone::new(suffix),
        NamespaceDone::decode,
    );
    message(
        o,
        "publish_skipped",
        &PublishSkipped::new(
            FullTrackName::new(TrackNamespace::empty(), Bytes::from_static(b"audio")).unwrap(),
        ),
        PublishSkipped::decode,
    );

    let mut update = RequestUpdate::new(rid(16));
    update.parameters = params(vec![uint(p::FORWARD, 1), fill()]);
    message(
        o,
        "request_update_subscription",
        &update,
        RequestUpdate::decode,
    );
    let mut update = RequestUpdate::new(rid(18));
    update.parameters = params(vec![
        uint(p::FORWARD, 0),
        typed(
            p::TRACK_NAMESPACE_PREFIX,
            ParamValue::Namespace(TrackNamespace::from_parts([&b"moqom"[..]]).unwrap()),
        ),
    ]);
    Context::UpdateSubscribeTracks
        .check(&update.parameters)
        .unwrap();
    message(
        o,
        "request_update_subscribe_tracks",
        &update,
        RequestUpdate::decode,
    );

    let mut request_ok = RequestOk::new();
    request_ok.parameters = params(vec![
        uint(p::EXPIRES, 30_000),
        typed(p::LARGEST_OBJECT, ParamValue::Location(loc(2, 1))),
    ]);
    message(o, "request_ok", &request_ok, RequestOk::decode);

    message(
        o,
        "request_error",
        &RequestError::new(
            RequestErrorCode::DOES_NOT_EXIST,
            ReasonPhrase::new(&b"no such track"[..]).unwrap(),
        ),
        RequestError::decode,
    );
    message(
        o,
        "request_error_retry",
        &RequestError::retryable(
            RequestErrorCode::EXCESSIVE_LOAD,
            ReasonPhrase::empty(),
            1000,
        )
        .unwrap(),
        RequestError::decode,
    );
    message(
        o,
        "request_error_redirect",
        &RequestError::redirect(
            ReasonPhrase::empty(),
            Redirect::to_uri(&b"moqt://edge.example/"[..]).unwrap(),
        ),
        RequestError::decode,
    );

    out
}

/// A counted block of one parameter, decoded back and recorded.
fn parameter(out: &mut BTreeMap<String, Vec<u8>>, name: &str, param: Parameter) {
    let block = params(vec![param]);
    let mut wire = Vec::new();
    D22.scope(|| block.encode_counted(&mut wire));
    let back = D22
        .scope(|| Parameters::decode_counted(&mut wire.as_slice()))
        .unwrap();
    assert_eq!(back, block, "{name} does not round-trip");
    out.insert(name.to_owned(), wire);
}

#[allow(clippy::too_many_lines)] // one flat list of vectors reads best
fn parameters() -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let o = &mut out;
    parameter(
        o,
        "object_delivery_timeout",
        uint(p::OBJECT_DELIVERY_TIMEOUT, 2000),
    );
    parameter(
        o,
        "authorization_token",
        bytes(p::AUTHORIZATION_TOKEN, b"tok"),
    );
    let token = |t: Token| typed(p::AUTHORIZATION_TOKEN, t.into_param_value());
    parameter(
        o,
        "authorization_token_register",
        token(Token::Register {
            alias: 1,
            token_type: 0,
            value: Bytes::from_static(b"ticket"),
        }),
    );
    parameter(
        o,
        "authorization_token_use_alias",
        token(Token::UseAlias { alias: 1 }),
    );
    parameter(
        o,
        "authorization_token_delete",
        token(Token::Delete { alias: 1 }),
    );
    parameter(
        o,
        "authorization_token_typed_value",
        token(Token::UseValue {
            token_type: 2,
            value: Bytes::from_static(b"tok"),
        }),
    );
    parameter(o, "rendezvous_timeout", uint(p::RENDEZVOUS_TIMEOUT, 0));
    parameter(
        o,
        "subgroup_delivery_timeout",
        uint(p::SUBGROUP_DELIVERY_TIMEOUT, 16_384),
    );
    parameter(o, "expires", uint(p::EXPIRES, 60_000));
    parameter(
        o,
        "largest_object",
        typed(p::LARGEST_OBJECT, ParamValue::Location(loc(300, 2))),
    );
    parameter(o, "fill_timeout", uint(p::FILL_TIMEOUT, 250));
    parameter(o, "forward_0", uint(p::FORWARD, 0));
    parameter(o, "forward_1", uint(p::FORWARD, 1));
    parameter(o, "subscriber_priority", uint(p::SUBSCRIBER_PRIORITY, 255));
    parameter(o, "location_filter_none", filter(LocationFilter::None));
    parameter(
        o,
        "location_filter_relative_start",
        filter(LocationFilter::RelativeStart { groups: 2 }),
    );
    parameter(
        o,
        "location_filter_absolute_start",
        filter(LocationFilter::AbsoluteStart(loc(10, 5))),
    );
    parameter(
        o,
        "location_filter_group_end",
        filter(LocationFilter::GroupEnd {
            start: loc(10, 0),
            end_group_delta: 3,
        }),
    );
    parameter(
        o,
        "location_filter_range",
        filter(LocationFilter::Range {
            start: loc(10, 5),
            end_group_delta: 1,
            end_object: 200,
        }),
    );
    parameter(
        o,
        "location_filter_next_object",
        filter(LocationFilter::NextObject),
    );
    parameter(o, "group_order_descending", uint(p::GROUP_ORDER, 2));
    parameter(o, "fill_parameters", fill());
    parameter(
        o,
        "fill_parameters_empty",
        typed(p::FILL_PARAMETERS, ParamValue::Nested(Parameters::new())),
    );
    // Range filters: Length, SetID (8), then Ranges, each Start [End].
    parameter(
        o,
        "subgroup_filter",
        bytes(p::SUBGROUP_FILTER, &[0x01, 0x00, 0x00]),
    );
    parameter(
        o,
        "objectid_filter",
        bytes(p::OBJECTID_FILTER, &[0x01, 0x00, 0x05, 0x0a]),
    );
    parameter(
        o,
        "priority_filter",
        bytes(p::PRIORITY_FILTER, &[0x01, 0x00, 0x7f]),
    );
    parameter(
        o,
        "object_property_filter",
        bytes(p::OBJECT_PROPERTY_FILTER, &[0x01, 0x10, 0x01, 0x01]),
    );
    parameter(
        o,
        "track_property_filter",
        bytes(p::TRACK_PROPERTY_FILTER, &[]),
    );
    parameter(o, "new_group_request", uint(p::NEW_GROUP_REQUEST, 41));
    parameter(
        o,
        "track_namespace_prefix",
        typed(p::TRACK_NAMESPACE_PREFIX, ParamValue::Namespace(ns())),
    );
    parameter(o, "include_properties_0", uint(p::INCLUDE_PROPERTIES, 0));
    out
}

fn data() -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();

    for (name, value) in [
        ("vi64_0", 0u64),
        ("vi64_37", 37),
        ("vi64_127", 127),
        ("vi64_128", 128),
        ("vi64_15293", 15_293),
        ("vi64_16384", 16_384),
        ("vi64_226442877", 226_442_877),
        ("vi64_2_62_minus_1", varint::MAX),
        ("vi64_2_64_minus_1", u64::MAX),
    ] {
        let mut wire = Vec::new();
        D22.scope(|| varint::encode_u64(value, &mut wire));
        assert_eq!(
            D22.scope(|| varint::decode_u64(&mut wire.as_slice()))
                .unwrap(),
            value
        );
        out.insert(name.to_owned(), wire);
    }

    let mut header = SubgroupHeader::new(
        TrackAlias::new(v(7)),
        GroupId::new(v(300)),
        SubgroupSource::Explicit(SubgroupId::new(v(2))),
    );
    header.priority = Some(64);
    header.end_of_group = true;
    let mut wire = Vec::new();
    D22.scope(|| header.encode(&mut wire));
    let back = D22
        .scope(|| SubgroupHeader::decode(&mut wire.as_slice()))
        .unwrap();
    assert_eq!(back, header);
    let mut writer = SubgroupWriter::new(&header).in_draft(D22);
    let objects = [
        SubgroupObject::new(0u32, &b"key"[..]),
        SubgroupObject::new(1u32, &b""[..]),
        SubgroupObject::new(200u32, &b"later"[..]),
    ];
    for object in &objects {
        writer.write(&mut wire, object).unwrap();
    }
    let mut cursor = wire.as_slice();
    D22.scope(|| SubgroupHeader::decode(&mut cursor)).unwrap();
    let mut reader = SubgroupReader::new(&header).in_draft(D22);
    for object in &objects {
        assert_eq!(&reader.read(&mut cursor).unwrap(), object);
    }
    assert!(cursor.is_empty());
    out.insert("subgroup_stream".to_owned(), wire);

    let datagram = ObjectDatagram::new(
        TrackAlias::new(v(7)),
        GroupId::new(v(130)),
        ObjectId::new(v(0)),
        &b"dg"[..],
    );
    let mut wire = Vec::new();
    D22.scope(|| datagram.encode(&mut wire));
    assert_eq!(
        D22.scope(|| ObjectDatagram::decode(&mut wire.as_slice()))
            .unwrap(),
        datagram
    );
    out.insert("object_datagram".to_owned(), wire);

    let mut wire = Vec::new();
    D22.scope(|| FetchHeader::new(rid(4)).encode(&mut wire));
    let mut writer = FetchWriter::new(GroupOrder::Ascending).in_draft(D22);
    let records = [
        FetchRecord::Object(FetchObject::new(loc(5, 0), &b"a"[..])),
        FetchRecord::EndOfNonExistentRange(loc(5, 3)),
        FetchRecord::EndOfTimedOutRange(loc(6, 9)),
        FetchRecord::EndOfUnknownRange(loc(7, 0)),
        FetchRecord::Object(FetchObject::new(loc(7, 1), &b"b"[..])),
    ];
    for record in &records {
        writer.write(&mut wire, record).unwrap();
    }
    let mut cursor = wire.as_slice();
    assert_eq!(
        D22.scope(|| FetchHeader::decode(&mut cursor)).unwrap(),
        FetchHeader::new(rid(4))
    );
    let mut reader =
        moqom_proto::data::fetch::FetchReader::new(GroupOrder::Ascending).in_draft(D22);
    for record in &records {
        assert_eq!(&reader.read(&mut cursor).unwrap(), record);
    }
    assert!(cursor.is_empty());
    out.insert("fetch_stream".to_owned(), wire);

    out
}

fn fixture(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/moqt-22")
        .join(file)
}

fn render(header: &str, vectors: &BTreeMap<String, Vec<u8>>) -> String {
    let mut text = String::new();
    for line in header.lines() {
        writeln!(text, "# {line}").unwrap();
    }
    for (name, wire) in vectors {
        write!(text, "{name} ").unwrap();
        for b in wire {
            write!(text, "{b:02x}").unwrap();
        }
        text.push('\n');
    }
    text
}

fn parse(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (name, hex) = l.split_once(' ').unwrap_or((l, ""));
            (name.to_owned(), hex.trim().to_owned())
        })
        .collect()
}

fn check(file: &str, header: &str, vectors: &BTreeMap<String, Vec<u8>>) {
    let path = fixture(file);
    let rendered = render(header, vectors);
    if std::env::var_os("MOQOM_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, rendered).unwrap();
        return;
    }
    let on_disk = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; MOQOM_BLESS=1 creates it", path.display()));
    let expected = parse(&on_disk);
    let actual = parse(&rendered);
    for (name, hex) in &expected {
        assert_eq!(actual.get(name), Some(hex), "{file}: {name}");
    }
    assert_eq!(
        expected.keys().collect::<Vec<_>>(),
        actual.keys().collect::<Vec<_>>(),
        "{file}: vector names differ"
    );
}

const COMMON: &str = "Integers are vi64 (leading ones give the length, 1-9 bytes).\n\
    Generated and checked by moqom-proto/tests/moqt22_vectors.rs.";

#[test]
fn control_messages() {
    check(
        "control.hex",
        &format!(
            "draft-ietf-moq-transport-22 control messages, framed:\n\
             Message Type (vi64), Message Length (16), Message Body.\n\
             AUTHORIZATION_TOKEN is a Token structure, USE_VALUE (0x3), Token Type 0.\n\
             FILL_PARAMETERS holds Number of Parameters (vi64) then the parameters.\n{COMMON}"
        ),
        &control(),
    );
}

#[test]
fn message_parameters() {
    check(
        "params.hex",
        &format!(
            "draft-ietf-moq-transport-22 Message Parameters, each alone in a block:\n\
             Number of Parameters (vi64) = 1, Type Delta (vi64), Value.\n{COMMON}"
        ),
        &parameters(),
    );
}

#[test]
fn data_plane() {
    check(
        "data.hex",
        &format!(
            "draft-ietf-moq-transport-22 integers and data streams.\n\
             subgroup_stream: SUBGROUP_HEADER then three objects.\n\
             fetch_stream: FETCH_HEADER then objects and End of Range markers,\n\
             including End of Timed-Out Range (0x20C).\n{COMMON}"
        ),
        &data(),
    );
}

/// What a draft-22 receiver must refuse, byte for byte.
#[test]
fn draft22_rejections() {
    let reject = |bytes: &[u8]| {
        D22.scope(|| Parameters::decode_counted(&mut &bytes[..]))
            .expect_err("must not decode")
    };
    // Unknown parameter type 0x0C.
    assert!(reject(&[0x01, 0x0c, 0x00]).is_fatal());
    // FORWARD = 2.
    assert!(reject(&[0x01, 0x10, 0x02]).is_fatal());
    // GROUP_ORDER = 0.
    assert!(reject(&[0x01, 0x22, 0x00]).is_fatal());
    // Location Filter Type 0x06.
    assert!(reject(&[0x01, 0x21, 0x06]).is_fatal());
    // EXPIRES twice.
    assert!(reject(&[0x02, 0x08, 0x01, 0x00, 0x02]).is_fatal());
    // FILL_PARAMETERS holding FORWARD, which it does not allow.
    assert!(reject(&[0x01, 0x23, 0x03, 0x01, 0x10, 0x01]).is_fatal());
    // A Token with undefined Alias Type 0x4.
    assert!(reject(&[0x01, 0x03, 0x02, 0x04, 0x01]).is_fatal());
    // USE_ALIAS carrying a value after its alias.
    assert!(reject(&[0x01, 0x03, 0x03, 0x02, 0x05, 0x00]).is_fatal());
    // REGISTER with no Token Type.
    assert!(reject(&[0x01, 0x03, 0x02, 0x01, 0x05]).is_fatal());

    // FORWARD in a FETCH.
    let mut fetch = Fetch::new(rid(0), FetchKind::Filtered { track: track() });
    fetch.parameters = params(vec![uint(p::FORWARD, 1)]);
    let mut wire = Vec::new();
    write_message_in(D22, &mut wire, &fetch).unwrap();
    let frame = ControlFrame::decode_in(D22, &mut wire.as_slice()).unwrap();
    assert!(frame.parse_in(D22, Fetch::decode).unwrap_err().is_fatal());

    // PUBLISH_STATE_NOTIFY does not exist before draft-22.
    let mut wire = Vec::new();
    write_message_in(D22, &mut wire, &PublishStateNotify::default()).unwrap();
    assert!(ControlFrame::decode_in(Draft::D19, &mut wire.as_slice()).is_err());

    // End of Timed-Out Range is not a draft-19 marker.
    let mut wire = Vec::new();
    FetchWriter::new(GroupOrder::Ascending)
        .in_draft(D22)
        .write(&mut wire, &FetchRecord::EndOfTimedOutRange(loc(1, 1)))
        .unwrap();
    let mut wire19 = Vec::new();
    Draft::D19.scope(|| varint::encode_u64(0x20c, &mut wire19));
    wire19.extend_from_slice(&[0x01, 0x01, 0x00]);
    let err = moqom_proto::data::fetch::FetchReader::new(GroupOrder::Ascending)
        .in_draft(Draft::D19)
        .read(&mut wire19.as_slice())
        .unwrap_err();
    assert!(err.is_fatal());

    // Datagram Type with bit 0x10, and subgroup type with bit 0x80.
    assert!(
        D22.scope(|| ObjectDatagram::decode(&mut &[0x10u8, 0, 0, 0][..]))
            .is_err()
    );
    assert!(
        D22.scope(|| SubgroupHeader::decode(&mut &[0x80u8, 0x90, 0, 0][..]))
            .is_err()
    );
}

/// The same message is a different byte string under each draft, and each
/// draft reads only its own.
#[test]
fn draft19_and_draft22_differ_on_the_wire() {
    let mut subscribe = Subscribe::new(rid(0), track());
    subscribe.parameters = params(vec![uint(p::FORWARD, 1)]);
    let mut d19 = Vec::new();
    write_message_in(Draft::D19, &mut d19, &Subscribe::new(rid(200), track())).unwrap();
    let mut d22 = Vec::new();
    write_message_in(D22, &mut d22, &Subscribe::new(rid(200), track())).unwrap();
    // Request ID 200 is 0x40c8 as a QUIC varint and 0x80c8 as vi64.
    assert_eq!(&d19[3..5], &[0x40, 0xc8]);
    assert_eq!(&d22[3..5], &[0x80, 0xc8]);
}

/// The Swift codec's token vectors (`moqom-swift/Tests/Fixtures/moqt-22`),
/// byte for byte: each must decode to the structure it was written from and
/// encode back unchanged.
#[test]
fn swift_token_alias_fixtures_round_trip() {
    let cases: [(&str, &[u8], Token); 3] = [
        (
            "param-authorization-token-register",
            &[
                0x01, 0x03, 0x09, 0x01, 0x01, 0x00, b't', b'i', b'c', b'k', b'e', b't',
            ],
            Token::Register {
                alias: 1,
                token_type: 0,
                value: Bytes::from_static(b"ticket"),
            },
        ),
        (
            "param-authorization-token-use-alias",
            &[0x01, 0x03, 0x02, 0x02, 0x01],
            Token::UseAlias { alias: 1 },
        ),
        (
            "param-authorization-token",
            &[
                0x01, 0x03, 0x08, 0x03, 0x00, b't', b'i', b'c', b'k', b'e', b't',
            ],
            Token::UseValue {
                token_type: 0,
                value: Bytes::from_static(b"ticket"),
            },
        ),
    ];
    for (name, wire, expected) in cases {
        let block = D22
            .scope(|| Parameters::decode_counted(&mut &wire[..]))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let tokens: Vec<Token> = block.token_structures().collect();
        assert_eq!(tokens, vec![expected], "{name}");
        let mut again = Vec::new();
        D22.scope(|| block.encode_counted(&mut again));
        assert_eq!(again, wire, "{name} re-encodes differently");
    }
}

/// Every parameter fixture of the Swift codec, when its checkout sits beside
/// this one, decodes and re-encodes unchanged here too. Skipped without it.
#[test]
fn every_swift_parameter_fixture_round_trips_when_present() {
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../moqom-swift/Tests/Fixtures/moqt-22");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!("no Swift fixtures at {}", dir.display());
        return;
    };
    let mut checked = 0;
    for entry in entries {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.starts_with("param-") || path.extension().is_none_or(|e| e != "hex") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        // One vector per uncommented line; some files hold several.
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let hex: String = line.split_whitespace().collect();
            let wire: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            let block = D22
                .scope(|| Parameters::decode_counted(&mut wire.as_slice()))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let mut again = Vec::new();
            D22.scope(|| block.encode_counted(&mut again));
            assert_eq!(again, wire, "{name} re-encodes differently");
            checked += 1;
        }
    }
    assert!(checked > 0, "no parameter fixtures in {}", dir.display());
}

/// §9.1.4: SETUP may register a token -- read as its value, MOQOM keeping no
/// cache -- but may not refer to an alias, there being none yet.
#[test]
fn setup_reads_a_registration_as_its_value_and_refuses_alias_references() {
    let body = |token: &Token| {
        let mut value = Vec::new();
        token.encode(&mut value);
        let mut options = Parameters::new();
        options.push(Parameter::bytes(option_type::AUTHORIZATION_TOKEN, value).unwrap());
        let mut wire = Vec::new();
        D22.scope(|| options.encode(&mut wire));
        wire
    };
    let decode = |wire: &[u8]| D22.scope(|| Setup::decode(&mut &wire[..], wire.len()));

    let registered = decode(&body(&Token::Register {
        alias: 1,
        token_type: 0,
        value: Bytes::from_static(b"ticket"),
    }))
    .expect("a registration in SETUP decodes");
    let tokens: Vec<_> = registered.options.authorization_tokens().collect();
    assert_eq!(tokens, vec![&Bytes::from_static(b"ticket")]);

    for reference in [Token::UseAlias { alias: 1 }, Token::Delete { alias: 1 }] {
        assert!(decode(&body(&reference)).is_err(), "{reference:?}");
    }
}
