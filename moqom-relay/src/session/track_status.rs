//! Draft-22 `TRACK_STATUS` (§9.13): what a `SUBSCRIBE` would have been told,
//! without the subscription.
//!
//! The relay answers from what it already holds. It runs the checks a
//! subscription would — read permission, then a force-mute, then whether
//! anybody publishes the track here — so a status query cannot tell a
//! refusal from an absent track any more than a subscription can. Then it
//! sends `REQUEST_OK` carrying the `LARGEST_OBJECT` a `SUBSCRIBE_OK` would
//! carry, which is the cache's, and finishes the stream.
//!
//! It neither forwards the query nor opens a subscription to answer it, both
//! of which §9.13 allows but neither of which it requires. A track reached
//! only through an upstream relay is therefore answered only while this
//! relay is already pulling it, and is otherwise reported as unpublished.

use moqom_proto::control::{ReasonPhrase, RequestErrorCode, RequestOk, TrackStatus};

use super::{ControlFrame, RequestError, SendStream, Session, SessionError, send, ticket_peer};

impl Session {
    pub(super) async fn on_track_status(
        &self,
        frame: &ControlFrame,
        send_stream: &mut SendStream,
    ) -> Result<(), SessionError> {
        let request = TrackStatus::decode(&mut frame.body.clone())?;
        let track = request.track;

        if ticket_peer(&track).is_some() {
            return send(
                send_stream,
                &RequestError::new(
                    RequestErrorCode::NOT_SUPPORTED,
                    ReasonPhrase::truncating("direct tickets are only subscribed to"),
                ),
            )
            .await;
        }
        if let Err(denial) = self.permission().may_read(track.namespace()) {
            let refusal = self.denied(denial, "track status", track.namespace());
            return send(send_stream, &refusal).await;
        }
        if self.withheld(&track) {
            return Self::unpublished(send_stream).await;
        }

        let parameters = self.largest_parameters(&track);
        let published_here = self.fabric.publisher(track.namespace()).is_some();
        let pulled_from_upstream = self.fabric.upstream().is_some() && !parameters.is_empty();
        if !published_here && !pulled_from_upstream {
            return Self::unpublished(send_stream).await;
        }

        tracing::debug!(session = %self.id, %track, "track status answered");
        let ok = RequestOk {
            parameters,
            ..RequestOk::new()
        };
        send(send_stream, &ok).await
    }
}
