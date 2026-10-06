//! Learning which namespaces exist under a prefix, as they come and go.
//!
//! What a recorder needs and a viewer that already knows whom to watch does not:
//! the room's participants are not known in advance, and the only way a relay
//! will say who is publishing is in answer to `SUBSCRIBE_NAMESPACE`. A watch is
//! also the stream a session renews its credential on, since it is the one
//! request that lasts as long as the session.

use bytes::Bytes;
use moqom_proto::control::params::{Parameter, param_type};
use moqom_proto::control::{
    MessageType, Namespace, NamespaceDone, RequestError, RequestId, RequestUpdate,
};
use moqom_proto::model::TrackNamespace;
use web_transport_quinn::SendStream;

use crate::Error;
use crate::device::Credentials;
use crate::session::{Frames, relay_identity, write};

/// What a watch reports, with suffixes already resolved to whole namespaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceEvent {
    /// Something is being published under this namespace.
    Available(TrackNamespace),
    /// It no longer is.
    Gone(TrackNamespace),
}

/// A live `SUBSCRIBE_NAMESPACE`. Dropping it withdraws the watch.
pub struct NamespaceWatch {
    prefix: TrackNamespace,
    request: RequestId,
    send: SendStream,
    frames: Frames,
    transport: moqom_transport::Session,
}

impl NamespaceWatch {
    pub(crate) fn new(
        prefix: TrackNamespace,
        request: RequestId,
        send: SendStream,
        frames: Frames,
        transport: moqom_transport::Session,
    ) -> Self {
        Self {
            prefix,
            request,
            send,
            frames,
            transport,
        }
    }

    /// The prefix this watch was opened with.
    #[must_use]
    pub const fn prefix(&self) -> &TrackNamespace {
        &self.prefix
    }

    /// The next change, or `None` once the relay has closed the watch.
    ///
    /// A refusal arrives here rather than from [`crate::Session::watch`]: a
    /// relay that admits a watch answers with silence until something exists,
    /// so only a refusal has anything to wait for.
    ///
    /// # Errors
    /// The relay refused the watch, sent something undecodable, or sent a
    /// suffix that cannot sit under the prefix.
    pub async fn next(&mut self) -> Result<Option<NamespaceEvent>, Error> {
        let Some(frame) = self.frames.next().await? else {
            return Ok(None);
        };
        let mut body = frame.body.clone();
        match frame.message_type {
            MessageType::Namespace => {
                let message = Namespace::decode(&mut body)?;
                let full = message
                    .resolve(&self.prefix)
                    .map_err(|_| Error::Unexpected {
                        found: MessageType::Namespace,
                        during: "resolving a namespace suffix",
                    })?;
                Ok(Some(NamespaceEvent::Available(full)))
            }
            MessageType::NamespaceDone => {
                let message = NamespaceDone::decode(&mut body)?;
                let full = message
                    .resolve(&self.prefix)
                    .map_err(|_| Error::Unexpected {
                        found: MessageType::NamespaceDone,
                        during: "resolving a namespace suffix",
                    })?;
                Ok(Some(NamespaceEvent::Gone(full)))
            }
            MessageType::RequestError => {
                let error = RequestError::decode(&mut body)?;
                Err(Error::Refused {
                    code: error.code.get(),
                    reason: error.reason.to_string(),
                })
            }
            found => Err(Error::Unexpected {
                found,
                during: "SUBSCRIBE_NAMESPACE",
            }),
        }
    }

    /// Hand the relay a fresh credential, so the session outlives the token it
    /// opened with.
    ///
    /// The proof is made here for the same reason it is made at connect: it
    /// commits to the relay's certificate, which only the connection knows. A
    /// renewal the relay refuses is not reported back -- the relay logs it and
    /// keeps the old deadline -- so a caller that cares renews well before
    /// expiry and treats the session closing as the failure signal.
    ///
    /// # Errors
    /// Signing the proof, or writing the update.
    pub async fn renew(&mut self, credentials: &Credentials<'_>) -> Result<(), Error> {
        let mut update = RequestUpdate::new(self.request);
        update.parameters.push(
            Parameter::bytes(
                param_type::AUTHORIZATION_TOKEN,
                Bytes::copy_from_slice(credentials.token),
            )
            .map_err(Error::setup)?,
        );
        if let Some(key) = credentials.key {
            let relay = relay_identity(&self.transport).ok_or(Error::NoRelayIdentity)?;
            let proof = key.prove(credentials.token, &relay)?;
            update.parameters.push(
                Parameter::bytes(param_type::AUTHORIZATION_PROOF, Bytes::from(proof))
                    .map_err(Error::setup)?,
            );
        }
        write(&mut self.send, &update).await
    }
}
