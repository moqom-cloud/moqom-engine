//! What a session does differently by draft.
//!
//! The relay speaks MOQOM's draft-19 and draft-ietf-moq-transport-22 on the
//! same port, and a track published in one is watched in the other. Most of
//! the session does not care: its tasks are bound to its draft
//! ([`Draft::bind`]) and the codec follows. What is here is what does care:
//!
//! - Subgroups crossing drafts are re-encoded rather than copied, because
//!   every integer in them is spelled differently.
//! - Draft-22 FETCH names its range with a Location filter, reports an
//!   inclusive end, and obliges a relay to FETCH upstream what it cannot
//!   vouch for (§3.2.3), reporting what the Fill Timeout runs out on as
//!   timed-out gaps.
//! - Draft-22 subscriptions can ask for a fill fetch stream (§3.4) and
//!   receive `PUBLISH_STATE_NOTIFY`.
//!
//! Draft-19 requests keep their existing behaviour exactly; nothing here
//! runs for them except the re-encoding, which they receive.

use std::time::Duration;

use moqom_proto::control::params::param_type;
use moqom_proto::control::typed::{Context, LocationFilter};
use moqom_proto::control::{Parameters, PublishStateNotify, RequestOk};
use moqom_proto::data::FetchReader;

use super::{
    Bytes, BytesMut, Command, DecodeError, Draft, Fetch, FetchEnd, FetchHeader, FetchKind,
    FetchRecord, FetchWriter, Frames, FullTrackName, GroupOrder, Location, MessageType, Metrics,
    ObjectId, Outlet, RequestError, RequestId, SendStream, Session, SessionError, SubgroupHeader,
    SubgroupReader, SubgroupWriter, VarInt, fan_out, oneshot, send,
};
use crate::fabric::{GroupWindow, Upstreamed};
use moqom_proto::model::GroupId;

/// The stream type of a fetch data stream (§6.4.1).
pub(super) const FETCH_HEADER: u64 = 0x05;

/// How long a draft-22 request without a Fill Timeout waits upstream.
///
/// §9.20.5 leaves it to the implementation. Long enough for one round trip
/// to a publisher on a poor uplink, short enough that a viewer asking for
/// history is not left looking at nothing.
const DEFAULT_FILL_TIMEOUT: Duration = Duration::from_millis(1500);

/// The most this relay waits upstream, whatever the request asks for.
const MAX_FILL_TIMEOUT: Duration = Duration::from_secs(5);

/// Read a unidirectional stream's type without consuming it.
pub(super) async fn stream_type(frames: &mut Frames) -> Result<u64, SessionError> {
    loop {
        let mut cursor = &frames.buffer[..];
        match moqom_proto::varint::decode_u64(&mut cursor) {
            Ok(kind) => return Ok(kind),
            Err(DecodeError::Short { .. }) => {}
            Err(e) => return Err(e.into()),
        }
        frames.fill().await?;
        if frames.ended {
            return Err(SessionError::Truncated);
        }
    }
}

/// Decode one value off the front of `frames`, reading more until it is whole.
async fn read_prefix<T>(
    frames: &mut Frames,
    mut decode: impl FnMut(&mut &[u8]) -> Result<T, DecodeError>,
) -> Result<T, SessionError> {
    loop {
        let mut cursor = &frames.buffer[..];
        match decode(&mut cursor) {
            Ok(value) => {
                let consumed = frames.buffer.len() - cursor.len();
                bytes::Buf::advance(&mut frames.buffer, consumed);
                return Ok(value);
            }
            Err(DecodeError::Short { .. }) => {}
            Err(e) => return Err(e.into()),
        }
        if frames.ended {
            return Err(SessionError::Truncated);
        }
        frames.fill().await?;
    }
}

/// One subgroup, re-encoded from the publisher's draft into a subscriber's.
///
/// Parses objects as they complete and writes each again, so it keeps the
/// reader's delta state and the tail of a partial object between chunks.
/// Once the input stops parsing it stays stopped, and its subscribers'
/// copies are abandoned rather than finished: a stream that ends early
/// looks complete, and one that is reset says it is not.
pub(super) struct Transcoder {
    reader: SubgroupReader,
    writer: SubgroupWriter,
    pending: BytesMut,
    target: Draft,
}

impl Transcoder {
    pub(super) fn new(header: &SubgroupHeader, from: Draft, to: Draft) -> Self {
        Self {
            reader: SubgroupReader::new(header).in_draft(from),
            writer: SubgroupWriter::new(header).in_draft(to),
            pending: BytesMut::new(),
            target: to,
        }
    }

    /// The draft this writes.
    pub(super) const fn target(&self) -> Draft {
        self.target
    }

    /// The re-encoding of whatever objects `bytes` completes, or `None` if
    /// the stream stopped parsing.
    fn feed(&mut self, bytes: &[u8]) -> Option<Bytes> {
        self.pending.extend_from_slice(bytes);
        let mut out = BytesMut::new();
        loop {
            let mut cursor = &self.pending[..];
            match self.reader.read(&mut cursor) {
                Ok(object) => {
                    let consumed = self.pending.len() - cursor.len();
                    bytes::Buf::advance(&mut self.pending, consumed);
                    self.writer.write(&mut out, &object).ok()?;
                }
                Err(DecodeError::Short { .. }) => return Some(out.freeze()),
                Err(_) => return None,
            }
        }
    }
}

/// [`fan_out`] for the subscribers in other drafts, each group through its
/// own re-encoding.
pub(super) fn fan_out_foreign(
    foreign: &mut Vec<(Transcoder, Vec<Outlet>)>,
    bytes: &Bytes,
    metrics: &Metrics,
) {
    foreign.retain_mut(|(transcoder, outlets)| {
        if let Some(out) = transcoder.feed(bytes) {
            if !out.is_empty() {
                fan_out(outlets, &out, metrics);
            }
            !outlets.is_empty()
        } else {
            tracing::debug!("subgroup does not re-encode, abandoning its copies");
            for outlet in outlets.iter() {
                outlet.abandon.notify_one();
            }
            false
        }
    });
}

/// The Fill Timeout a request carries, clamped to what this relay will wait.
pub(super) fn fill_timeout(parameters: &Parameters) -> Duration {
    parameters
        .get(param_type::FILL_TIMEOUT)
        .and_then(moqom_proto::control::Parameter::as_varint)
        .map_or(DEFAULT_FILL_TIMEOUT, |ms| Duration::from_millis(ms.get()))
        .min(MAX_FILL_TIMEOUT)
}

/// The Location filter a parameter block carries.
pub(super) fn location_filter(parameters: &Parameters) -> Option<LocationFilter> {
    parameters
        .get(param_type::LOCATION_FILTER)
        .and_then(moqom_proto::control::Parameter::as_location_filter)
}

/// The location just before `location`, for a gap marker ending there.
fn before(location: Location) -> Option<Location> {
    match location.object.get() {
        0 => {
            let group = location.group.get().checked_sub(1)?;
            Some(Location::new(
                GroupId::new(VarInt::new(group).ok()?),
                ObjectId::new(VarInt::MAX),
            ))
        }
        object => Some(Location::new(
            location.group,
            ObjectId::new(VarInt::new(object - 1).ok()?),
        )),
    }
}

/// Whether cached records answer `start..` with nothing of unknown status.
///
/// The cache leaves groups it does not hold out silently, so a first record
/// in a later group than `start` is as much a gap as a marker is.
fn vouched_for(records: &[FetchRecord], start: Location) -> bool {
    records
        .first()
        .is_some_and(|first| first.location().group == start.group)
        && !records
            .iter()
            .any(|r| matches!(r, FetchRecord::EndOfUnknownRange(_)))
}

/// Cached records with what is not there reported as timed out, which is
/// what §3.2.3 says of objects the Fill Timeout ran out on.
fn timed_out(mut records: Vec<FetchRecord>, start: Location) -> Vec<FetchRecord> {
    for record in &mut records {
        if let FetchRecord::EndOfUnknownRange(at) = *record {
            *record = FetchRecord::EndOfTimedOutRange(at);
        }
    }
    if let Some(first) = records.first().map(FetchRecord::location)
        && first > start
        && let Some(gap) = before(first).filter(|gap| *gap >= start)
    {
        records.insert(0, FetchRecord::EndOfTimedOutRange(gap));
    }
    records
}

/// The parameters a downstream `PUBLISH_STATE_NOTIFY` repeats from upstream.
///
/// The Location filter is the upstream subscription's, which no subscriber
/// of this relay set; the rest describes the track and passes through.
fn passed_on(mut parameters: Parameters) -> Parameters {
    parameters.retain(|p| {
        matches!(
            p.type_value(),
            param_type::LARGEST_OBJECT | param_type::FORWARD
        )
    });
    parameters
}

/// What a draft-22 subscription holds besides the route.
pub(super) struct Extras {
    /// The publisher's state notifications, passed on to the subscriber.
    pub(super) notices: Option<tokio::sync::mpsc::UnboundedReceiver<Parameters>>,
    /// Fill fetch streams being written. Aborting one drops its stream,
    /// which resets it, as §3.4.1 requires when the subscription ends.
    pub(super) fills: Vec<tokio::task::JoinHandle<()>>,
    /// The subscription's Location filter, which a fill without its own
    /// falls back to.
    pub(super) filter: Option<LocationFilter>,
}

impl Extras {
    pub(super) const fn none() -> Self {
        Self {
            notices: None,
            fills: Vec::new(),
            filter: None,
        }
    }
}

impl Drop for Extras {
    fn drop(&mut self) {
        for fill in &self.fills {
            fill.abort();
        }
    }
}

impl Session {
    /// The groups a draft-22 subscription's Location filter admits.
    ///
    /// # Errors
    /// [`SessionError::Decode`] for a filter whose end does not fit, which
    /// §9.20.9 makes a protocol violation.
    pub(super) fn window_for(
        &self,
        track: &FullTrackName,
        filter: Option<LocationFilter>,
    ) -> Result<GroupWindow, SessionError> {
        let Some(filter) = filter else {
            return Ok(GroupWindow::ALL);
        };
        let largest = self.fabric.cache().largest(track);
        Ok(match filter.resolve_subscribe(largest)? {
            None => GroupWindow::ALL,
            Some((start, end)) => GroupWindow {
                first: start.group.get(),
                last: match end {
                    moqom_proto::control::typed::FilterEnd::Open => None,
                    moqom_proto::control::typed::FilterEnd::Group(group) => Some(group.get()),
                    moqom_proto::control::typed::FilterEnd::At(at) => Some(at.group.get()),
                },
            },
        })
    }

    /// Set a draft-22 subscription's route up from its SUBSCRIBE: the window
    /// its Location filter admits, the pause a FORWARD of 0 asks for, and a
    /// channel for the publisher's state notifications.
    pub(super) fn prepare_route(
        &self,
        route: super::Route,
        request: &moqom_proto::control::Subscribe,
        track: &FullTrackName,
        extras: &mut Extras,
    ) -> Result<super::Route, SessionError> {
        extras.filter = location_filter(&request.parameters);
        *route
            .window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            self.window_for(track, extras.filter)?;
        if Self::starts_paused(&request.parameters) {
            route
                .forward
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }
        let (notices, heard) = tokio::sync::mpsc::unbounded_channel();
        extras.notices = Some(heard);
        Ok(route.notifying(notices))
    }

    /// Open the fill a request's `FILL_PARAMETERS` asks for, if any.
    pub(super) fn fill_requested(
        &self,
        request_id: RequestId,
        parameters: &Parameters,
        track: &FullTrackName,
        extras: &mut Extras,
    ) {
        if let Some(fill) = parameters
            .get(param_type::FILL_PARAMETERS)
            .and_then(moqom_proto::control::Parameter::as_nested)
            && let Some(task) = self.open_fill(request_id, track, fill, extras.filter)
        {
            extras.fills.push(task);
        }
    }

    /// `SUBSCRIBE_OK` or `REQUEST_OK` parameters: `LARGEST_OBJECT`, which a
    /// draft-22 publisher must include when objects exist (§9.20.17).
    pub(super) fn largest_parameters(&self, track: &FullTrackName) -> Parameters {
        let mut parameters = Parameters::new();
        if let Some(largest) = self.fabric.cache().largest(track)
            && let Ok(param) = moqom_proto::control::Parameter::typed(
                param_type::LARGEST_OBJECT,
                moqom_proto::control::ParamValue::Location(largest),
            )
        {
            parameters.push(param);
        }
        parameters
    }

    /// Answer a draft-22 FETCH: resolve its Location filter, gather the
    /// records (from upstream where the cache cannot vouch for them), and
    /// send `FETCH_OK` with the inclusive end and the objects on their own
    /// stream.
    pub(super) async fn on_fetch_filtered(
        &self,
        request: Fetch,
        track: FullTrackName,
        send_stream: &mut SendStream,
    ) -> Result<(), SessionError> {
        let refuse = |code, reason: &str| {
            RequestError::new(code, moqom_proto::control::ReasonPhrase::truncating(reason))
        };
        if let Err(denial) = self.permission().may_read(track.namespace()) {
            let refusal = self.denied(denial, "fetch", track.namespace());
            return send(send_stream, &refusal).await;
        }

        let filter = location_filter(&request.parameters).unwrap_or(LocationFilter::None);
        let largest = self.fabric.cache().largest(&track);
        let range = filter.resolve_fetch(largest)?;
        let budget = fill_timeout(&request.parameters);
        let records = match range {
            Some((start, end)) => self.gather(&track, start, Some(end), budget).await,
            // Nothing cached to bound the range by: the publisher may still
            // have it, and is asked for whatever the filter starts at.
            None if largest.is_none() => {
                let start = match filter {
                    LocationFilter::AbsoluteStart(start)
                    | LocationFilter::GroupEnd { start, .. }
                    | LocationFilter::Range { start, .. } => start,
                    _ => Location::ZERO,
                };
                self.gather(&track, start, None, budget).await
            }
            None => Vec::new(),
        };

        let Some(end) = records.iter().map(FetchRecord::location).max() else {
            return send(
                send_stream,
                &refuse(
                    moqom_proto::control::RequestErrorCode::DOES_NOT_EXIST,
                    "nothing in that range is available here",
                ),
            )
            .await;
        };
        send(send_stream, &moqom_proto::control::FetchOk::new(end)).await?;

        let request_id = request.request_id;
        let session = self.clone();
        tokio::spawn(self.draft.bind(async move {
            if let Err(e) = session
                .write_fetch(request_id, &records, GroupOrder::Ascending)
                .await
            {
                tracing::debug!(session = %session.id, error = %e, "fetch delivery failed");
            }
        }));
        Ok(())
    }

    /// The records for `start..=end` of `track`: the cache's answer if it
    /// vouches for the whole range, else upstream's within `budget`, else
    /// the cache's with what it lacks reported as timed out.
    async fn gather(
        &self,
        track: &FullTrackName,
        start: Location,
        end: Option<Location>,
        budget: Duration,
    ) -> Vec<FetchRecord> {
        let through = end.map_or(
            FetchEnd::Through(Location::new(
                GroupId::new(VarInt::MAX),
                ObjectId::new(VarInt::MAX),
            )),
            FetchEnd::Through,
        );
        let cached = self
            .fabric
            .cache()
            .fetch(track, start, through, GroupOrder::Ascending);
        if vouched_for(&cached, start) {
            return cached;
        }

        // A Fill Timeout of zero means only what is immediately available.
        if !budget.is_zero()
            && let Some(publisher) = self.fabric.publisher(track.namespace())
        {
            let deadline = tokio::time::Instant::now() + budget;
            let (reply, answer) = oneshot::channel();
            let asked = publisher
                .send(Command::Fetch {
                    track: track.clone(),
                    start,
                    end,
                    deadline,
                    reply,
                })
                .await;
            if asked.is_ok()
                && let Ok(Ok(upstream)) =
                    tokio::time::timeout_at(deadline + Duration::from_millis(100), answer).await
            {
                if upstream.complete && !upstream.records.is_empty() {
                    return upstream.records;
                }
                if cached.is_empty() && !upstream.records.is_empty() {
                    let mut records = upstream.records;
                    if let Some(end) = end
                        && records.last().is_some_and(|r| r.location() < end)
                    {
                        records.push(FetchRecord::EndOfTimedOutRange(end));
                    }
                    return records;
                }
            }
        }
        timed_out(cached, start)
    }

    /// FETCH `start..=end` of `track` from this session's peer, collecting
    /// records until `deadline`.
    pub(super) async fn fetch_upstream(
        &self,
        track: FullTrackName,
        start: Location,
        end: Option<Location>,
        deadline: tokio::time::Instant,
    ) -> Upstreamed {
        let request_id = self.allocate_request_id();
        let (arrived, stream) = oneshot::channel();
        self.lock_fetching().insert(request_id, arrived);
        let mut out = Upstreamed::default();
        let finished = tokio::time::timeout_at(
            deadline,
            self.fetch_upstream_into(request_id, track, start, end, stream, &mut out.records),
        )
        .await;
        self.lock_fetching().remove(&request_id);
        out.complete = matches!(finished, Ok(Ok(())));
        if let Ok(Err(e)) = finished {
            tracing::debug!(session = %self.id, error = %e, "upstream fetch failed");
        }
        out
    }

    async fn fetch_upstream_into(
        &self,
        request_id: RequestId,
        track: FullTrackName,
        start: Location,
        end: Option<Location>,
        stream: oneshot::Receiver<Frames>,
        records: &mut Vec<FetchRecord>,
    ) -> Result<(), SessionError> {
        let end = match end {
            Some(end) => FetchEnd::Through(end)
                .wire()
                .ok_or(SessionError::Protocol("fetch end is unnameable"))?,
            None => Location::new(GroupId::new(VarInt::MAX), ObjectId::ZERO),
        };
        let mut request = Fetch::new(request_id, FetchKind::Standalone { track, start, end });
        self.outgoing(&mut request.parameters);
        let (mut send_stream, recv) = self.transport.open_bi().await?;
        send(&mut send_stream, &request).await?;

        let mut answer = Frames::new(recv);
        let frame = answer.expect().await?;
        match frame.message_type {
            MessageType::FetchOk => {}
            MessageType::RequestError => {
                return Err(SessionError::Protocol("upstream refused the fetch"));
            }
            _ => return Err(SessionError::Protocol("unexpected answer to FETCH")),
        }

        let mut data = stream
            .await
            .map_err(|_| SessionError::Protocol("fetch stream never arrived"))?;
        let mut reader = FetchReader::new(GroupOrder::Ascending).in_draft(self.draft);
        loop {
            match read_prefix(&mut data, |cursor| reader.read(cursor)).await {
                Ok(record) => records.push(record),
                Err(SessionError::Truncated) if data.buffer.is_empty() => {
                    drop(send_stream);
                    return Ok(());
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Hand a fetch data stream to the upstream FETCH waiting for it.
    pub(super) async fn accept_fetch_stream(&self, mut frames: Frames) {
        let header = match read_prefix(&mut frames, |cursor| FetchHeader::decode(cursor)).await {
            Ok(header) => header,
            Err(e) => {
                tracing::debug!(session = %self.id, error = %e, "unreadable fetch header");
                return;
            }
        };
        let waiting = self.lock_fetching().remove(&header.request_id);
        if let Some(waiting) = waiting {
            let _ = waiting.send(frames);
        } else {
            tracing::debug!(
                session = %self.id,
                request = %header.request_id,
                "fetch stream for no outstanding fetch"
            );
        }
    }

    /// Open a fill fetch stream for a draft-22 subscription (§3.4), unless
    /// the fill range is empty.
    ///
    /// `request_id` is the SUBSCRIBE's or the `REQUEST_UPDATE`'s, which the
    /// `FETCH_HEADER` carries. `subscription_order` is the subscription's group
    /// order, against which the fill's own is compared for scheduling.
    pub(super) fn open_fill(
        &self,
        request_id: RequestId,
        track: &FullTrackName,
        fill: &Parameters,
        subscription: Option<LocationFilter>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let filter = location_filter(fill)
            .or(subscription)
            .unwrap_or(LocationFilter::None);
        let largest = self.fabric.cache().largest(track);
        let (start, end) = filter.resolve_fetch(largest).ok()??;
        let budget = fill_timeout(fill);
        // §5.1.2: within a group a fill-delivered object goes before a
        // subscription-delivered one. Subgroup streams are written at the
        // default priority, so the fill stream goes above them; a fill
        // asking for descending order runs against the subscription's
        // ascending groups, and then the subscription's objects go first.
        let descending = fill
            .get(param_type::GROUP_ORDER)
            .and_then(moqom_proto::control::Parameter::as_varint)
            .is_some_and(|order| order.get() == 2);
        let priority = if descending { -1 } else { 1 };

        let session = self.clone();
        let track = track.clone();
        Some(tokio::spawn(self.draft.bind(async move {
            let Ok(mut stream) = session.transport.open_uni().await else {
                return;
            };
            let _ = stream.set_priority(priority);
            let mut buf = BytesMut::new();
            FetchHeader::new(request_id).encode(&mut buf);
            let records = session.gather(&track, start, Some(end), budget).await;
            if records.is_empty() {
                // §3.4.1: a fill that fails is opened and reset, since
                // there is no REQUEST_ERROR to carry it.
                let _ = stream.write_all(&buf).await;
                let _ = stream.reset(moqom_proto::control::codes::reset::UNKNOWN_OBJECT_STATUS);
                return;
            }
            let mut writer = FetchWriter::new(GroupOrder::Ascending);
            for record in &records {
                if writer.write(&mut buf, record).is_err() {
                    break;
                }
            }
            if stream.write_all(&buf).await.is_ok() {
                if let Some(meter) = session.meter.get() {
                    meter.egress(buf.len());
                }
                let _ = stream.finish();
            }
        })))
    }

    /// Act on a draft-22 `REQUEST_UPDATE` of a subscription: move its
    /// window, open a fill if asked and not paused, and answer `REQUEST_OK`.
    pub(super) async fn update_subscription(
        &self,
        frame: &super::ControlFrame,
        track: &FullTrackName,
        window: &std::sync::Mutex<GroupWindow>,
        paused: bool,
        extras: &mut Extras,
        send_stream: &mut SendStream,
    ) -> Result<(), SessionError> {
        let update = moqom_proto::control::RequestUpdate::decode(&mut frame.body.clone())?;
        Context::UpdateSubscription.check(&update.parameters)?;
        if let Some(filter) = location_filter(&update.parameters) {
            let moved = self.window_for(track, Some(filter))?;
            *window
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = moved;
            extras.filter = Some(filter);
        }
        if !paused {
            self.fill_requested(update.request_id, &update.parameters, track, extras);
        }
        let mut ok = RequestOk::new();
        ok.parameters = self.largest_parameters(track);
        send(send_stream, &ok).await
    }

    /// Pass a publisher's state notification on to a draft-22 subscriber.
    pub(super) async fn notify_subscriber(
        &self,
        track: &FullTrackName,
        upstream: Parameters,
        send_stream: &mut SendStream,
    ) -> Result<(), SessionError> {
        let mut parameters = passed_on(upstream);
        if parameters.get(param_type::LARGEST_OBJECT).is_none() {
            for param in self.largest_parameters(track).as_slice() {
                parameters.push(param.clone());
            }
        }
        send(send_stream, &PublishStateNotify { parameters }).await
    }

    /// Hand a `PUBLISH_STATE_NOTIFY` from upstream to every route of the
    /// subscription it arrived on.
    pub(super) fn relay_notice(&self, upstream: super::TrackAlias, frame: &super::ControlFrame) {
        let Ok(notice) = PublishStateNotify::decode(&mut frame.body.clone()) else {
            return;
        };
        for route in self.routes_for(upstream) {
            if let Some(notices) = &route.notices {
                let _ = notices.send(notice.parameters.clone());
            }
        }
    }

    fn lock_fetching(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<RequestId, oneshot::Sender<Frames>>>
    {
        self.fetching
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether a FORWARD parameter on a subscription asks for it paused.
    pub(super) fn starts_paused(parameters: &Parameters) -> bool {
        parameters
            .get(param_type::FORWARD)
            .and_then(moqom_proto::control::Parameter::as_varint)
            .is_some_and(|forward| forward.get() == 0)
    }
}
