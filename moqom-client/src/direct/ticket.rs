//! Direct tickets: what keeps a direct path honest about the relay session
//! beside it.
//!
//! Direct time is billed, and direct media never touches a relay, so a relay
//! cannot count it. What it counts is tickets: while a participant is on a
//! direct path it holds a subscription to its own `.direct/{peer}` track on its
//! relay, and the relay answers with a signed ticket about once a minute and
//! meters the time. Each side presents its tickets to the other over the direct
//! session, and each ends the direct path when the other's ticket is missing,
//! does not verify or runs out. An app that drops its relay session therefore
//! loses its direct path as well.
//!
//! The first ticket is also the credential each side is admitted on: the
//! direct SETUP carries it, with a proof of possession over it, in place of the
//! MOQOM token (see [`super::DirectEndpoint`]). That is why it carries the
//! holder's key thumbprint (`jkt`) and publish bits (`pub`) as well as who it
//! is: they are what a peer would otherwise have read off the token.
//!
//! A ticket is checked as a token is, a compact JWS by `kid`, against the
//! ticket keys each side takes from its own relay's ticket objects. A key the
//! peer handed over would prove nothing. The check is the relay's
//! (`moqom_relay::ticket::verify`), and `MoqomKit`'s `DirectTicketCheck`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use moqom_proto::model::{FullTrackName, TrackNamespace};
use moqom_token::PublicKey;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::VerifiedPeer;
use crate::session::{OutgoingObject, Session, Subscription};

/// The JWS `typ` every ticket carries and a token never does.
pub const TICKET_TYPE: &str = "moqom-direct-ticket";

/// Longer than any ticket the relay signs, and short enough to refuse junk.
const LONGEST: usize = 8192;

/// A ticket, as this participant's relay issued it.
#[derive(Debug, Clone)]
pub struct DirectTicket {
    /// The compact JWS, presented to the peer as is.
    pub compact: String,
    /// When it stops being accepted, before clock skew.
    pub expires: SystemTime,
    /// The relay's ticket keys, which the peer's tickets are checked against.
    pub keys: Vec<PublicKey>,
}

impl DirectTicket {
    /// Read one object of the relay's ticket track.
    ///
    /// # Errors
    /// [`TicketRefusal::Malformed`] for anything that is not the relay's
    /// ticket object with at least one key.
    pub fn from_object(payload: &[u8]) -> Result<Self, TicketRefusal> {
        #[derive(Deserialize)]
        struct Object {
            version: u32,
            ticket: String,
            expires: u64,
            keys: serde_json::Value,
        }
        let object: Object =
            serde_json::from_slice(payload).map_err(|_| TicketRefusal::Malformed)?;
        if object.version != 1 {
            return Err(TicketRefusal::Malformed);
        }
        let keys =
            PublicKey::parse_set(&object.keys.to_string()).map_err(|_| TicketRefusal::Malformed)?;
        if keys.is_empty() {
            return Err(TicketRefusal::Malformed);
        }
        Ok(Self {
            compact: object.ticket,
            expires: UNIX_EPOCH + Duration::from_secs(object.expires),
            keys,
        })
    }
}

/// Why a peer's ticket was refused. Every one ends the direct path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TicketRefusal {
    /// No ticket arrived in time.
    #[error("the peer presented no direct ticket")]
    Missing,
    /// Not a compact JWS, or not the relay's ticket object.
    #[error("the ticket is malformed")]
    Malformed,
    /// Signed with another algorithm, or a token rather than a ticket.
    #[error("not a direct ticket")]
    Unsupported,
    /// Signed by a key outside this side's ticket keys.
    #[error("the ticket's key is not a ticket key")]
    UnknownKey,
    /// The signature does not verify.
    #[error("the ticket's signature does not verify")]
    BadSignature,
    /// Past its expiry, allowing for skew.
    #[error("the ticket has expired")]
    Expired,
    /// Issued in the future, allowing for skew.
    #[error("the ticket is not valid yet")]
    NotYetValid,
    /// For another tenant, room or participant than the one verified at setup.
    #[error("the ticket names somebody other than the peer")]
    WrongHolder,
    /// For a direct path to somebody else.
    #[error("the ticket is for a direct path to somebody else")]
    WrongPeer,
}

/// Check `ticket`, presented by `holder` on a direct path to `me`
/// (`user/device`), and return when it expires.
///
/// # Errors
/// The [`TicketRefusal`] that ends the path.
pub fn verify_ticket(
    ticket: &[u8],
    keys: &[PublicKey],
    holder: &VerifiedPeer,
    me: &str,
    now: SystemTime,
    skew: Duration,
) -> Result<SystemTime, TicketRefusal> {
    #[derive(Deserialize)]
    struct Header {
        alg: String,
        typ: String,
        kid: String,
    }
    // `jkt` and `pub` are the setup check's, which the relay's verifier does;
    // a ticket later in the path is judged on who it names and when it lapses.
    #[derive(Deserialize)]
    struct Claims {
        ten: String,
        room: String,
        sub: String,
        dev: String,
        peer: String,
        iat: u64,
        exp: u64,
    }

    if ticket.len() > LONGEST {
        return Err(TicketRefusal::Malformed);
    }
    let mut segments = ticket.split(|&byte| byte == b'.');
    let (Some(header), Some(body), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(TicketRefusal::Malformed);
    };
    let decode = |segment: &[u8]| {
        URL_SAFE_NO_PAD
            .decode(segment)
            .map_err(|_| TicketRefusal::Malformed)
    };
    let parsed: Header =
        serde_json::from_slice(&decode(header)?).map_err(|_| TicketRefusal::Malformed)?;
    if parsed.typ != TICKET_TYPE {
        return Err(TicketRefusal::Unsupported);
    }
    let key = keys
        .iter()
        .find(|key| key.id == parsed.kid)
        .ok_or(TicketRefusal::UnknownKey)?;
    if parsed.alg != key.algorithm.jose() {
        return Err(TicketRefusal::Unsupported);
    }
    if !key.verifies(
        &ticket[..header.len() + 1 + body.len()],
        &decode(signature)?,
    ) {
        return Err(TicketRefusal::BadSignature);
    }

    let claims: Claims =
        serde_json::from_slice(&decode(body)?).map_err(|_| TicketRefusal::Malformed)?;
    let now = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let skew = skew.as_secs();
    if now > claims.exp.saturating_add(skew) {
        return Err(TicketRefusal::Expired);
    }
    if now.saturating_add(skew) < claims.iat {
        return Err(TicketRefusal::NotYetValid);
    }
    if claims.ten != holder.tenant
        || holder.room.as_deref() != Some(claims.room.as_str())
        || claims.sub != holder.user
        || claims.dev != holder.device
    {
        return Err(TicketRefusal::WrongHolder);
    }
    if claims.peer != me {
        return Err(TicketRefusal::WrongPeer);
    }
    Ok(UNIX_EPOCH + Duration::from_secs(claims.exp))
}

/// How patient a direct path is with the peer's tickets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TicketSettings {
    /// How long the peer has to present its first ticket.
    pub grace: Duration,
    /// How often the current ticket is presented again, so a peer that
    /// subscribed late is not left waiting for the next renewal.
    pub represent: Duration,
    /// Clock skew allowed on the peer's tickets.
    pub skew: Duration,
}

impl Default for TicketSettings {
    /// Ten seconds' grace, presented every five, thirty seconds of skew, as in
    /// `MoqomKit`.
    fn default() -> Self {
        Self {
            grace: Duration::from_secs(10),
            represent: Duration::from_secs(5),
            skew: Duration::from_secs(30),
        }
    }
}

/// The track a participant asks its relay for tickets on: `.direct/{peer}`
/// under its own slot, stage or backstage.
pub(crate) fn relay_track(slot: TrackNamespace, peer: &str) -> Option<FullTrackName> {
    FullTrackName::new(slot, Bytes::from(format!(".direct/{peer}"))).ok()
}

/// Where `holder` presents its tickets on the direct session: the stage slot's
/// shape whatever the room, as `MoqomKit` names it, so the two interoperate.
fn direct_track(tenant: &str, room: &str, holder: &str, peer: &str) -> Option<FullTrackName> {
    let (user, device) = holder.split_once('/')?;
    let namespace = TrackNamespace::from_parts([tenant, "r", room, user, device]).ok()?;
    relay_track(namespace, peer)
}

/// Present this side's tickets to the peer on `direct` and hold the peer to
/// its own, until a ticket of the peer's is refused.
///
/// `first` is the ticket this side was admitted on, read off `tickets` before
/// the path was established; later ones follow on `tickets`.
///
/// Runs until it returns the refusal; the caller ends the direct path with it.
/// Dropped, it stops presenting and checking, and drops `tickets`, which is
/// what stops the relay metering.
pub(crate) async fn guard(
    direct: Session,
    mut tickets: Subscription,
    first: DirectTicket,
    peer: VerifiedPeer,
    me: String,
    settings: TicketSettings,
) -> TicketRefusal {
    let Some(room) = peer.room.clone() else {
        return TicketRefusal::WrongHolder;
    };
    let holder = format!("{}/{}", peer.user, peer.device);
    let (Some(own), Some(theirs)) = (
        direct_track(&peer.tenant, &room, &me, &holder),
        direct_track(&peer.tenant, &room, &holder, &me),
    ) else {
        return TicketRefusal::Malformed;
    };
    let Ok(publication) = direct.publish(own) else {
        return TicketRefusal::Malformed;
    };

    let (seen, mut presented_by_peer) = mpsc::channel::<Bytes>(8);
    let watcher = super::room::Task::spawn({
        let mut direct = direct.clone();
        async move {
            // The peer may not have published its track yet.
            let mut subscription = loop {
                if let Ok(subscription) = direct.subscribe(theirs.clone()).await {
                    break subscription;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            };
            while let Ok(Some(object)) = subscription.next_object().await {
                if seen.send(object.payload).await.is_err() {
                    return;
                }
            }
        }
    });

    let mut current: Option<DirectTicket> = Some(first);
    let mut pending: Option<Bytes> = None;
    let mut peer_expires: Option<SystemTime> = None;
    let mut deadline = Instant::now() + settings.grace;
    let mut presented = 0u64;
    let mut feeding = true;

    let check = |ticket: &[u8],
                 current: &Option<DirectTicket>,
                 peer_expires: &mut Option<SystemTime>,
                 deadline: &mut Instant|
     -> Result<(), TicketRefusal> {
        let keys = current.as_ref().map(|ticket| ticket.keys.as_slice());
        let Some(keys) = keys else {
            return Ok(());
        };
        let expires = verify_ticket(ticket, keys, &peer, &me, SystemTime::now(), settings.skew)?;
        if peer_expires.is_none_or(|known| expires > known) {
            *peer_expires = Some(expires);
            let left = expires
                .duration_since(SystemTime::now())
                .unwrap_or_default();
            *deadline = Instant::now() + left + settings.skew;
        }
        Ok(())
    };

    let refusal = loop {
        // Until the first presentation lands, look often: the peer's grace
        // period runs from the moment it subscribes.
        let pause = if presented == 0 {
            Duration::from_millis(50)
        } else {
            settings.represent
        };
        tokio::select! {
            ticket = tickets.next_object(), if feeding => match ticket {
                Ok(Some(object)) => {
                    if let Ok(ticket) = DirectTicket::from_object(&object.payload) {
                        current = Some(ticket);
                        if let Some(waiting) = pending.take()
                            && let Err(refusal) = check(&waiting, &current, &mut peer_expires, &mut deadline)
                        {
                            break refusal;
                        }
                        present(&direct, &publication, current.as_ref(), &mut presented).await;
                    }
                }
                // The relay stopped issuing; the peer's patience decides.
                Ok(None) | Err(_) => feeding = false,
            },
            Some(ticket) = presented_by_peer.recv() => {
                if current.is_none() {
                    // Nothing to check against until this side's own relay
                    // has said what the ticket keys are.
                    pending = Some(ticket);
                } else if let Err(refusal) = check(&ticket, &current, &mut peer_expires, &mut deadline) {
                    break refusal;
                }
            }
            () = tokio::time::sleep(pause) => {
                present(&direct, &publication, current.as_ref(), &mut presented).await;
            }
            () = tokio::time::sleep_until(deadline) => {
                break if peer_expires.is_none() {
                    TicketRefusal::Missing
                } else {
                    TicketRefusal::Expired
                };
            }
        }
    };
    drop(watcher);
    refusal
}

/// Write the current ticket as a new group, once somebody is listening.
async fn present(
    direct: &Session,
    publication: &crate::session::Publication,
    current: Option<&DirectTicket>,
    presented: &mut u64,
) {
    let Some(current) = current else { return };
    if !publication.has_subscribers() {
        return;
    }
    let group = *presented;
    *presented += 1;
    let _ = direct
        .publish_objects(
            publication.alias(),
            group,
            &[OutgoingObject::new(current.compact.as_bytes())],
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> VerifiedPeer {
        VerifiedPeer {
            tenant: "acme".to_owned(),
            user: "ada".to_owned(),
            device: "OuXpLpEHW7dCPqjK".to_owned(),
            room: Some("room-42".to_owned()),
            may_publish: true,
        }
    }

    #[test]
    fn junk_is_malformed_and_a_token_is_not_a_ticket() {
        let now = SystemTime::now();
        let skew = Duration::from_secs(30);
        assert_eq!(
            verify_ticket(b"not a jws", &[], &peer(), "bob/dev", now, skew),
            Err(TicketRefusal::Malformed)
        );
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ML-DSA-87","typ":"JWT","kid":"k"}"#);
        let token = format!("{header}.e30.c2ln");
        assert_eq!(
            verify_ticket(token.as_bytes(), &[], &peer(), "bob/dev", now, skew),
            Err(TicketRefusal::Unsupported)
        );
        let header =
            URL_SAFE_NO_PAD.encode(br#"{"alg":"ML-DSA-87","typ":"moqom-direct-ticket","kid":"k"}"#);
        let unknown = format!("{header}.e30.c2ln");
        assert_eq!(
            verify_ticket(unknown.as_bytes(), &[], &peer(), "bob/dev", now, skew),
            Err(TicketRefusal::UnknownKey)
        );
    }

    #[test]
    fn a_ticket_object_without_keys_is_malformed() {
        assert!(DirectTicket::from_object(b"{}").is_err());
        assert_eq!(
            DirectTicket::from_object(br#"{"version":1,"ticket":"a.b.c","expires":1,"keys":[]}"#)
                .err(),
            Some(TicketRefusal::Malformed)
        );
    }
}
