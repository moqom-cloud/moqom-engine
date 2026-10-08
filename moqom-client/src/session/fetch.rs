//! FETCH, for objects a subscription started too late to deliver.
//!
//! A subscription starts at the next subgroup, so whoever subscribes to a live
//! track mid-group misses the start of the group in flight. The relay keeps a
//! few groups for exactly this, and a fetch reads them back. The objects come
//! on a stream of their own, opened with the request's ID rather than a track
//! alias, which the session's reader routes here.

use std::collections::HashMap;
use std::sync::Mutex;

use bytes::{Buf, BytesMut};
use moqom_proto::Draft;
use moqom_proto::control::params::param_type;
use moqom_proto::control::typed::LocationFilter;
use moqom_proto::control::{
    Fetch, FetchKind, MessageType, ParamValue, Parameter, RequestError, RequestId,
};
use moqom_proto::data::{FetchHeader, FetchReader, FetchRecord, GroupOrder};
use moqom_proto::error::DecodeError;
use moqom_proto::model::{FetchEnd, FullTrackName, Location};
use moqom_proto::varint::VarInt;
use tokio::sync::mpsc;
use web_transport_quinn::{RecvStream, SendStream};

use super::{Frames, INBOX_DEPTH, Object, Session, Subscription, fill, write};
use crate::Error;
use crate::properties::ObjectProperties;

/// Fetches waiting for their data stream, by request.
pub(super) type Fetches = HashMap<RequestId, mpsc::Sender<Result<Object, Error>>>;

/// What to fetch.
#[derive(Clone)]
pub enum FetchRange<'a> {
    /// The group in flight on a subscription, from its first object to the
    /// relay's live edge for the track: what the subscription will not deliver.
    ///
    /// A joining fetch under draft-19. Draft-22 has none, so there it is the
    /// track's current group by `LOCATION_FILTER`, which ends at the same edge.
    InFlight(&'a Subscription),
    /// A range of `track`, from `start` to `end`.
    Range {
        /// The track.
        track: FullTrackName,
        /// The first location, inclusive.
        start: Location,
        /// Where it ends.
        end: FetchEnd,
    },
}

/// An accepted fetch. Its objects arrive in ascending order and end when the
/// relay finishes the stream; dropping this cancels whatever is left.
pub struct Fetched {
    rx: mpsc::Receiver<Result<Object, Error>>,
    _send: SendStream,
    _recv: RecvStream,
}

impl Fetched {
    /// The next object, or `None` once the relay has sent everything.
    ///
    /// # Errors
    /// A stream that cannot be decoded.
    pub async fn next_object(&mut self) -> Result<Option<Object>, Error> {
        match self.rx.recv().await {
            Some(result) => result.map(Some),
            None => Ok(None),
        }
    }
}

impl Session {
    /// Ask the relay for objects already published.
    ///
    /// # Errors
    /// [`Error::Refused`] when the relay holds nothing in the range, which is
    /// the ordinary answer for a track that has no group in flight; otherwise
    /// the request could not be made or was answered with the wrong message.
    pub async fn fetch(&mut self, range: FetchRange<'_>) -> Result<Fetched, Error> {
        let draft = self.draft;
        draft.bind(self.fetch_in_draft(range)).await
    }

    async fn fetch_in_draft(&mut self, range: FetchRange<'_>) -> Result<Fetched, Error> {
        let request_id = self.next_request()?;
        let message = match range {
            FetchRange::InFlight(subscription) if self.draft == Draft::D22 => {
                let mut message = Fetch::new(
                    request_id,
                    FetchKind::Filtered {
                        track: subscription.track.clone(),
                    },
                );
                // One group back from the next, which is the current group.
                let filter = LocationFilter::RelativeStart { groups: 1 };
                message.parameters.push(
                    Parameter::typed(
                        param_type::LOCATION_FILTER,
                        ParamValue::LocationFilter(filter),
                    )
                    .map_err(|failure| Error::Setup(failure.to_string()))?,
                );
                message
            }
            FetchRange::InFlight(subscription) => Fetch::new(
                request_id,
                FetchKind::RelativeJoining {
                    request_id: subscription.request,
                    preceding_groups: VarInt::ZERO,
                },
            ),
            FetchRange::Range { track, start, end } => {
                let end = end
                    .wire()
                    .ok_or_else(|| Error::Setup("a fetch range end that cannot be named".into()))?;
                Fetch::new(request_id, FetchKind::Standalone { track, start, end })
            }
        };

        // Registered before the request goes out: the relay may open the data
        // stream before its FETCH_OK arrives here.
        let (tx, rx) = mpsc::channel(INBOX_DEPTH);
        lock(&self.fetches).insert(request_id, tx);
        let answer = self.ask(&message).await;
        let (send, frames) = match answer {
            Ok(streams) => streams,
            Err(failure) => {
                lock(&self.fetches).remove(&request_id);
                return Err(failure);
            }
        };
        Ok(Fetched {
            rx,
            _send: send,
            _recv: frames.into_inner(),
        })
    }

    async fn ask(&self, message: &Fetch) -> Result<(SendStream, Frames), Error> {
        let (mut send, recv) = self.transport.open_bi().await?;
        write(&mut send, message).await?;
        let mut frames = Frames::new(recv);
        let frame = frames.next().await?.ok_or(Error::Closed)?;
        match frame.message_type {
            MessageType::FetchOk => Ok((send, frames)),
            MessageType::RequestError => {
                let error = RequestError::decode(&mut frame.body.clone())?;
                Err(Error::Refused {
                    code: error.code.get(),
                    reason: error.reason.to_string(),
                })
            }
            found => Err(Error::Unexpected {
                found,
                during: "FETCH",
            }),
        }
    }
}

/// Whether a data stream that begins with `buffer` is a fetch's, once enough
/// of it has arrived to say. `None` means more bytes are needed.
pub(super) fn is_fetch_stream(buffer: &[u8]) -> Option<bool> {
    let mut cursor = buffer;
    match VarInt::decode(&mut cursor) {
        Ok(code) => Some(code.get() == moqom_proto::data::FETCH_HEADER_TYPE),
        Err(_) => None,
    }
}

/// Read one fetch stream into the fetch it answers.
pub(super) async fn read_fetch(
    mut recv: RecvStream,
    mut buffer: BytesMut,
    fetches: &Mutex<Fetches>,
) -> Result<(), Error> {
    let header = loop {
        let mut cursor = &buffer[..];
        match FetchHeader::decode(&mut cursor) {
            Ok(header) => {
                let consumed = buffer.len() - cursor.len();
                buffer.advance(consumed);
                break header;
            }
            Err(DecodeError::Short { .. }) => {}
            Err(error) => return Err(error.into()),
        }
        if !fill(&mut recv, &mut buffer).await? {
            return Ok(());
        }
    };
    // Taken, not borrowed: a fetch has one stream, and its end is the end of
    // the fetch.
    let Some(tx) = lock(fetches).remove(&header.request_id) else {
        return Ok(());
    };
    let mut reader = FetchReader::new(GroupOrder::Ascending);
    loop {
        let mut cursor = &buffer[..];
        match reader.read(&mut cursor) {
            Ok(record) => {
                let consumed = buffer.len() - cursor.len();
                buffer.advance(consumed);
                let FetchRecord::Object(object) = record else {
                    continue;
                };
                let delivered = Object {
                    group: object.location.group,
                    object: object.location.object.get(),
                    payload: object.payload,
                    properties: ObjectProperties::from_wire(&object.properties),
                };
                if tx.send(Ok(delivered)).await.is_err() {
                    return Ok(());
                }
                continue;
            }
            Err(DecodeError::Short { .. }) => {}
            Err(error) => {
                let _ = tx.send(Err(error.into())).await;
                return Ok(());
            }
        }
        if !fill(&mut recv, &mut buffer).await? {
            return Ok(());
        }
    }
}

fn lock(fetches: &Mutex<Fetches>) -> std::sync::MutexGuard<'_, Fetches> {
    fetches
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
