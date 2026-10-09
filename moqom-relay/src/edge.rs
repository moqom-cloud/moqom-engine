//! An edge's links to its parent, one per room, each on a credential the control
//! plane minted for that room alone.
//!
//! [`crate::upstream`] attaches a relay to its parent on one credential fixed at
//! startup, which is either unscoped — a read of every room the parent carries,
//! from whoever holds it — or scoped to one room and useless for the rest. Here
//! instead each room an edge is asked for gets a link of its own:
//!
//! 1. The edge asks the control plane ([`Minter`]) for a link credential for the
//!    room, bound to an ML-DSA-87 key the edge generated at startup and holds
//!    only in memory. The credential carries `moqt.rly` and the room, nothing
//!    else, and `cnf.jkt` names the key.
//! 2. It dials the parent, reads the parent's leaf certificate off the handshake,
//!    and signs a proof of possession bound to the token and to that certificate
//!    (`ath`, `rel`, a fresh `jti`) — the client's proof, from
//!    [`moqom_client::device::DeviceKey`]. A parent requiring possession checks it
//!    exactly as it checks a client's, so a token without the key, a proof made
//!    for another relay, or a proof already spent is refused at setup.
//! 3. The parent scopes the session to the room the token names, and refuses
//!    anything asked on the link outside it.
//! 4. Before the credential lapses the edge mints another and hands it to the
//!    parent on the link, with a fresh proof, so the link outlives any one token.
//!    Renewal starts when a third of the lifetime remains, moved by up to a tenth
//!    of the lifetime either way so a fleet started together does not renew
//!    together; a failed attempt is retried with jittered exponential backoff.
//!    Meanwhile the link serves on the token it has.
//!
//! Revocation is the control plane refusing to mint: the room has ended, or the
//! relay's account was withdrawn. The edge stops renewing, the link carries on
//! until its current credential expires, and then the parent closes it. So a
//! revocation takes at most one credential lifetime plus the parent's clock skew
//! to take effect, which is why link credentials are short-lived. After that the
//! room is marked refused for a while, and subscriptions in it are refused
//! without asking again.
//!
//! A link nobody pulls anything over for [`Timing::idle`] ends, and the next
//! subscription in its room starts another.
//!
//! # The credential is opaque here
//!
//! The edge never reads the token it is given. It may be sealed, encrypted to
//! the relays that verify it, and an edge is not one of those for its own link
//! credential: it is the holder, and a holder that could read its credential
//! would be one that could be made to depend on what it says. What the edge
//! needs — when to renew — comes from the mint response's `expiresAt`, beside
//! the token, and the lifetime is measured from when the response arrived
//! rather than from the token's `iat`, which costs at most the request's
//! round trip of renewal margin. The proof of possession is over the token's
//! bytes as received. The parent is what reads the claims, room and pool
//! included.
//!
//! A pool relay's parent must be in the same pool. The control plane mints a
//! pool edge's link credentials for that pool, and a parent in another pool, or
//! in the shared fleet, refuses them (`wrong_pool`): the edge does not check
//! where it is linking, because it cannot read what it would check against,
//! and the parent's refusal is the check that cannot be skipped.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use moqom_client::device::DeviceKey;
use tokio::sync::mpsc;

use crate::fabric::{Fabric, LinkState, RoomKey};
use crate::upstream::{self, Dialer, Idle, Introduction, Parent, Renewal};
use crate::usage::report::{self, Endpoint};

/// A link credential, with the times it was minted for.
#[derive(Debug, Clone)]
pub struct Credential {
    /// The token, sealed or not, exactly as the control plane returned it.
    pub token: String,
    /// When it arrived, which is when its lifetime is counted from.
    pub issued: SystemTime,
    /// When the control plane said it expires.
    pub expires: SystemTime,
}

impl Credential {
    /// `token`, received now, expiring at `expires` as the mint response said.
    ///
    /// # Errors
    /// [`MintError::Unavailable`] for an empty token or one already expired,
    /// which a link could not be started on.
    pub fn received(token: String, expires: SystemTime) -> Result<Self, MintError> {
        let issued = SystemTime::now();
        if token.is_empty() {
            return Err(MintError::Unavailable(
                "an empty link credential".to_owned(),
            ));
        }
        if expires <= issued {
            return Err(MintError::Unavailable(
                "a link credential that has already expired".to_owned(),
            ));
        }
        Ok(Self {
            token,
            issued,
            expires,
        })
    }
}

/// Why no credential was minted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MintError {
    /// The control plane said no: the room is gone or ended, or this relay may
    /// not link. Not worth asking again soon.
    #[error("the control plane refused a link credential: {0}")]
    Revoked(String),
    /// The control plane could not be asked, or failed. Worth asking again.
    #[error("no link credential from the control plane: {0}")]
    Unavailable(String),
}

/// The key a credential is to be bound to.
#[derive(Debug, Clone, Copy)]
pub struct Holder<'a> {
    /// Its public JWK, in RFC 7638 member order.
    pub jwk: &'a str,
    /// Its thumbprint, what `cnf.jkt` must say.
    pub thumbprint: &'a str,
}

/// What a [`Minter`] returns.
pub type Minting<'a> = Pin<Box<dyn Future<Output = Result<Credential, MintError>> + Send + 'a>>;

/// Where link credentials come from.
pub trait Minter: Send + Sync + 'static {
    /// A credential to link into `room`, bound to `holder`.
    fn mint<'a>(&'a self, room: &'a RoomKey, holder: Holder<'a>) -> Minting<'a>;
}

/// The control plane's `/relay/link`.
#[derive(Debug)]
pub struct ControlPlane {
    endpoint: Endpoint,
}

impl ControlPlane {
    /// Mint at `url`, authenticating with the relay service account's
    /// `credential`.
    ///
    /// # Errors
    /// If the URL is not `http` or `https` with a host.
    pub fn new(url: &str, credential: report::Credential) -> Result<Self, String> {
        Ok(Self {
            endpoint: Endpoint::at(url, credential)?,
        })
    }

    /// Also trust the authorities in `pem`, for a control plane on a private
    /// name.
    ///
    /// # Errors
    /// If `pem` holds no certificates.
    pub fn trusting(self, pem: &[u8]) -> Result<Self, String> {
        Ok(Self {
            endpoint: self.endpoint.trusting(pem)?,
        })
    }
}

impl Minter for ControlPlane {
    fn mint<'a>(&'a self, room: &'a RoomKey, holder: Holder<'a>) -> Minting<'a> {
        Box::pin(async move {
            let quoted = |value: &str| {
                serde_json::to_string(value).unwrap_or_else(|_| unreachable!("a string"))
            };
            let body = format!(
                r#"{{"tenant":{},"room":{},"key":{}}}"#,
                quoted(&room.tenant),
                quoted(&room.room),
                holder.jwk
            );
            let (status, answer) = self
                .endpoint
                .post_json(Bytes::from(body))
                .await
                .map_err(MintError::Unavailable)?;
            let message = || {
                let text = String::from_utf8_lossy(&answer);
                format!(
                    "{status}: {}",
                    text.trim().chars().take(200).collect::<String>()
                )
            };
            match status.as_u16() {
                200..=299 => {
                    #[derive(serde::Deserialize)]
                    struct Answer {
                        token: String,
                        #[serde(rename = "expiresAt")]
                        expires_at: String,
                    }
                    let answer: Answer = serde_json::from_slice(&answer).map_err(|_| {
                        MintError::Unavailable("an unreadable link credential".to_owned())
                    })?;
                    let expires =
                        crate::usage::parse_rfc3339(&answer.expires_at).ok_or_else(|| {
                            MintError::Unavailable(format!(
                                "a link credential expiring at {:?}",
                                answer.expires_at
                            ))
                        })?;
                    Credential::received(answer.token, expires)
                }
                // Unauthorised, forbidden, no such room, room ended.
                401 | 403 | 404 | 410 => Err(MintError::Revoked(message())),
                _ => Err(MintError::Unavailable(message())),
            }
        })
    }
}

/// When links renew, retry and give up.
#[derive(Debug, Clone)]
pub struct Timing {
    /// Renew once this fraction of a credential's lifetime remains.
    pub renew_remaining: f64,
    /// Move each renewal by up to this fraction of the lifetime, either way.
    pub jitter: f64,
    /// The first wait after a failure.
    pub first_retry: Duration,
    /// The longest wait after failures.
    pub longest_retry: Duration,
    /// End a link that carries nothing for this long.
    pub idle: Duration,
    /// How long a refused room stays refused before it is asked about again.
    pub refused_for: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            renew_remaining: 1.0 / 3.0,
            jitter: 0.1,
            first_retry: Duration::from_secs(1),
            longest_retry: Duration::from_mins(1),
            idle: Duration::from_mins(1),
            refused_for: Duration::from_secs(30),
        }
    }
}

impl Timing {
    /// When to start renewing `credential`.
    fn renewal_due(&self, credential: &Credential) -> SystemTime {
        let lifetime = credential
            .expires
            .duration_since(credential.issued)
            .unwrap_or_default();
        let early = lifetime.mul_f64(self.renew_remaining.clamp(0.0, 1.0));
        let swing = lifetime.mul_f64(self.jitter.clamp(0.0, 1.0));
        let due = credential
            .expires
            .checked_sub(early)
            .unwrap_or(credential.issued);
        // Uniform in [due - swing, due + swing].
        let moved = swing.mul_f64(2.0 * report::jitter());
        due.checked_sub(swing)
            .map_or(due, |earliest| earliest + moved)
            .min(credential.expires)
    }

    /// How long to wait before attempt `failures + 1`: doubling to the
    /// longest, drawn from the upper half.
    fn backoff(&self, failures: u32) -> Duration {
        let doubled = self
            .first_retry
            .saturating_mul(1 << failures.saturating_sub(1).min(16));
        let half = doubled.min(self.longest_retry) / 2;
        half + half.mul_f64(report::jitter())
    }
}

/// Links an edge to its parent per room.
pub struct Edge {
    inner: Arc<Inner>,
}

struct Inner {
    dialer: Dialer,
    parent: Parent,
    fabric: Fabric,
    minter: Arc<dyn Minter>,
    key: DeviceKey,
    jwk: String,
    thumbprint: String,
    timing: Timing,
}

impl std::fmt::Debug for Edge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Edge")
            .field("parent", &self.inner.parent.to_string())
            .field("thumbprint", &self.inner.thumbprint)
            .finish_non_exhaustive()
    }
}

impl Edge {
    /// An edge linking `fabric` to `parent` through `dialer`, on credentials
    /// from `minter`, with a key generated now.
    ///
    /// The key lives only in this process. A restart is a new key, which the
    /// next credential is simply bound to; there is nothing to store or rotate.
    ///
    /// # Errors
    /// If no key can be generated.
    pub fn new(
        dialer: Dialer,
        parent: Parent,
        fabric: Fabric,
        minter: impl Minter,
        timing: Timing,
    ) -> Result<Self, String> {
        let (key, _pkcs8) = DeviceKey::generate().map_err(|e| e.to_string())?;
        Ok(Self {
            inner: Arc::new(Inner {
                dialer,
                parent,
                fabric,
                minter: Arc::new(minter),
                jwk: key.public_key_jwk(),
                thumbprint: key.thumbprint(),
                key,
                timing,
            }),
        })
    }

    /// The thumbprint every credential this edge asks for is bound to.
    #[must_use]
    pub fn thumbprint(&self) -> &str {
        &self.inner.thumbprint
    }

    /// Start linking: from now on a subscription for a room nobody here
    /// publishes asks for that room's link. Runs until the fabric is dropped.
    #[must_use]
    pub fn start(self) -> tokio::task::JoinHandle<()> {
        let (linker, mut asked) = mpsc::unbounded_channel();
        self.inner.fabric.link_rooms(linker);
        tokio::spawn(async move {
            while let Some(room) = asked.recv().await {
                tokio::spawn(Arc::clone(&self.inner).link(room));
            }
        })
    }
}

/// How one link attempt ended.
enum Ended {
    /// Nothing was pulled over it for long enough.
    Idle,
    /// The control plane will not mint for the room.
    Revoked(String),
    /// Anything else, after the link had been up or not.
    Failed { was_up: bool, why: String },
}

impl Inner {
    fn holder(&self) -> Holder<'_> {
        Holder {
            jwk: &self.jwk,
            thumbprint: &self.thumbprint,
        }
    }

    /// Keep `room` linked until it idles or is refused.
    async fn link(self: Arc<Self>, room: RoomKey) {
        let mut failures = 0;
        let mut last_up = Instant::now();
        loop {
            match self.once(&room).await {
                Ended::Idle => {
                    tracing::info!(%room, "room link idle; closed");
                    self.fabric.forget_link(&room);
                    return;
                }
                Ended::Revoked(why) => {
                    tracing::warn!(%room, %why, "room link refused");
                    self.fabric.set_link(&room, LinkState::Refused);
                    tokio::time::sleep(self.timing.refused_for).await;
                    self.fabric.forget_link(&room);
                    return;
                }
                Ended::Failed { was_up, why } => {
                    if was_up {
                        failures = 0;
                        last_up = Instant::now();
                    }
                    failures += 1;
                    tracing::warn!(%room, %why, failures, "room link failed");
                    self.fabric.set_link(&room, LinkState::Connecting);
                    // Nobody has had this link for as long as an idle one is
                    // kept: whoever wanted it has been refused, and the next to
                    // want it will ask again.
                    if last_up.elapsed() >= self.timing.idle {
                        self.fabric.forget_link(&room);
                        return;
                    }
                    tokio::time::sleep(self.timing.backoff(failures)).await;
                }
            }
        }
    }

    /// Mint, dial, prove, and serve one link until it ends.
    async fn once(self: &Arc<Self>, room: &RoomKey) -> Ended {
        let credential = match self.minter.mint(room, self.holder()).await {
            Ok(credential) => credential,
            Err(MintError::Revoked(why)) => return Ended::Revoked(why),
            Err(MintError::Unavailable(why)) => return Ended::Failed { was_up: false, why },
        };
        let failed = |why: String| Ended::Failed { was_up: false, why };
        let connection = match upstream::connect(&self.dialer, &self.parent).await {
            Ok(connection) => connection,
            Err(e) => return failed(e.to_string()),
        };
        let Some(relay) = upstream::certificate_identity(&connection) else {
            return failed("the parent presented no certificate".to_owned());
        };
        let proof = match self.key.prove(credential.token.as_bytes(), &relay) {
            Ok(proof) => proof,
            Err(e) => return failed(e.to_string()),
        };

        let (renewals, renewals_in) = mpsc::channel(1);
        let revoked = Arc::new(AtomicBool::new(false));
        let renewer = tokio::spawn(Arc::clone(self).renew(
            room.clone(),
            relay,
            credential.clone(),
            renewals,
            Arc::clone(&revoked),
        ));
        let idled = Arc::new(AtomicBool::new(false));
        let result = upstream::attach_over(
            connection,
            self.fabric.clone(),
            Introduction {
                token: Some(credential.token.into_bytes()),
                proof: Some(proof),
                room: Some(room.clone()),
                renewals: Some(renewals_in),
                idle: Some(Idle {
                    after: self.timing.idle,
                    idled: Arc::clone(&idled),
                }),
            },
        )
        .await;
        renewer.abort();

        if idled.load(Ordering::Relaxed) {
            return Ended::Idle;
        }
        if revoked.load(Ordering::Relaxed) {
            return Ended::Revoked(
                "renewal refused; the link ended with its credential".to_owned(),
            );
        }
        Ended::Failed {
            was_up: matches!(self.fabric.link(room), Some(LinkState::Up(_))),
            why: result
                .err()
                .map_or_else(|| "closed".to_owned(), |e| e.to_string()),
        }
    }

    /// Renew `credential` on the link until the link ends or renewal is refused.
    async fn renew(
        self: Arc<Self>,
        room: RoomKey,
        relay: String,
        mut credential: Credential,
        renewals: mpsc::Sender<Renewal>,
        revoked: Arc<AtomicBool>,
    ) {
        let mut due = self.timing.renewal_due(&credential);
        let mut failures = 0;
        loop {
            if let Ok(wait) = due.duration_since(SystemTime::now()) {
                tokio::time::sleep(wait).await;
            }
            match self.minter.mint(&room, self.holder()).await {
                Ok(fresh) => {
                    let Ok(proof) = self.key.prove(fresh.token.as_bytes(), &relay) else {
                        failures += 1;
                        due = SystemTime::now() + self.timing.backoff(failures);
                        continue;
                    };
                    let renewal = Renewal {
                        token: fresh.token.clone().into_bytes(),
                        proof,
                    };
                    if renewals.send(renewal).await.is_err() {
                        return;
                    }
                    tracing::debug!(%room, "room link credential renewed");
                    credential = fresh;
                    failures = 0;
                    due = self.timing.renewal_due(&credential);
                }
                Err(MintError::Revoked(why)) => {
                    tracing::warn!(
                        %room,
                        %why,
                        "room link renewal refused; serving until the credential expires"
                    );
                    revoked.store(true, Ordering::Relaxed);
                    return;
                }
                Err(MintError::Unavailable(why)) => {
                    failures += 1;
                    tracing::warn!(%room, %why, failures, "room link renewal failed; retrying");
                    due = SystemTime::now() + self.timing.backoff(failures);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::UNIX_EPOCH;

    fn lasting(issued: u64, expires: u64) -> Credential {
        Credential {
            token: String::new(),
            issued: UNIX_EPOCH + Duration::from_secs(issued),
            expires: UNIX_EPOCH + Duration::from_secs(expires),
        }
    }

    #[test]
    fn renewal_is_due_with_a_third_left_give_or_take_a_tenth() {
        let timing = Timing::default();
        let credential = lasting(1_000, 1_300);
        for _ in 0..200 {
            let due = timing
                .renewal_due(&credential)
                .duration_since(UNIX_EPOCH)
                .expect("after the epoch")
                .as_secs_f64();
            assert!((1_170.0..=1_230.0).contains(&due), "{due}");
        }
    }

    #[test]
    fn a_credential_already_past_its_point_is_due_now() {
        let timing = Timing::default();
        let credential = lasting(1_000, 1_000);
        assert!(timing.renewal_due(&credential) <= credential.expires);
    }

    #[test]
    fn backoff_doubles_to_the_longest_and_stays_in_its_upper_half() {
        let timing = Timing::default();
        for (failures, ceiling) in [(1, 1), (2, 2), (3, 4), (7, 60), (40, 60)] {
            let wait = timing.backoff(failures);
            let ceiling = Duration::from_secs(ceiling);
            assert!(
                wait >= ceiling / 2 && wait <= ceiling,
                "{failures}: {wait:?}"
            );
        }
    }

    #[test]
    fn the_times_come_from_the_mint_response_not_the_token() {
        let expires = SystemTime::now() + Duration::from_mins(5);
        let credential =
            Credential::received("an opaque, sealed token".to_owned(), expires).expect("usable");
        assert_eq!(credential.expires, expires);
        assert!(credential.issued <= SystemTime::now());
        assert!(Credential::received(String::new(), expires).is_err());
        assert!(
            Credential::received(
                "lapsed".to_owned(),
                SystemTime::now() - Duration::from_secs(1)
            )
            .is_err()
        );
    }
}
