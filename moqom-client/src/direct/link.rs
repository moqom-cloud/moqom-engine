//! The direct endpoint: one socket, one certificate, one peer.
//!
//! # Who dials
//!
//! Both sides call [`DirectEndpoint::establish`] at about the same time, and both
//! send probes so that each NAT opens towards the other. Only one of them dials,
//! though, so that exactly one QUIC connection results: the side whose
//! certificate fingerprint sorts lower. Both know both fingerprints from the
//! offers, so they agree without another message.
//!
//! # What each side checks
//!
//! TLS is mutual and pinned in both directions to the fingerprints in the
//! offers, which arrived sealed under the room secret. Nobody outside the room
//! can therefore complete the handshake as either peer, whatever the relay or
//! the network does.
//!
//! Then MOQT SETUP, in both directions this time, each carrying the sender's
//! MOQOM token and proof of possession. Each side hands what it received to the
//! [`PeerVerifier`], which runs the relay's own checks, and then requires the
//! token to be for this room, to grant publishing, and to name the participant
//! the offer came from. A failure closes the connection with the reason, as a
//! relay would.
//!
//! The dialler sends SETUP first and checks the answer last, so it ends the
//! exchange by opening one empty unidirectional stream: the acceptor's only
//! evidence that its own credentials passed. Neither side returns a session
//! the other has refused.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use moqom_proto::control::{MessageType, Role, Setup};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use super::punch::Puncher;
use super::verify::admissible;
use super::{CandidateOffer, Eligibility, IpExposure, PeerCredentials, PeerVerifier, VerifiedPeer};
use crate::device::{Credentials, certificate_identity};
use crate::session::{Frames, IMPLEMENTATION, Session, placeholder_url, relay_identity, write};
use crate::tls::install_crypto_provider;
use crate::Error;

/// The name in each endpoint's certificate. Nothing checks it -- both sides pin
/// the certificate itself -- but TLS needs a server name to send.
const SERVER_NAME: &str = "moqom-direct";

/// The MOQT session close code for refused credentials, as the relay uses it.
const UNAUTHORIZED: u32 = 0x03;

/// How a direct endpoint behaves.
#[derive(Debug, Clone)]
pub struct DirectConfig {
    /// This side's tenant, which the peer's token must share.
    pub tenant: String,
    /// The room, which the peer's token must admit them to.
    pub room: String,
    /// This participant, as `user/device`. Offers are addressed by it.
    pub me: String,
    /// Where to bind. The default is every interface on an ephemeral port.
    pub bind: SocketAddr,
    /// A STUN server to learn the public address from, if any.
    ///
    /// Without one, only this device's own interface addresses are offered,
    /// which reach a peer on the same network or one with a public address and
    /// nothing behind a NAT.
    pub stun: Option<SocketAddr>,
    /// Whether to send probes to open this side's NAT.
    ///
    /// On by default and only worth turning off to measure what it buys: two
    /// address-restricted NATs cannot be crossed without it.
    pub punching: bool,
    /// How often to probe each of the peer's candidates while establishing.
    pub punch_interval: Duration,
    /// How long [`DirectEndpoint::establish`] may take before giving up.
    pub patience: Duration,
    /// How long a direct connection may be silent before QUIC declares it dead.
    ///
    /// Short, because the relay is always there to fall back to and a dead
    /// direct path is worth noticing quickly. Keep-alives go out at a third of
    /// it, which also keeps both NAT mappings open.
    pub idle_timeout: Duration,
}

impl DirectConfig {
    /// Defaults for `me` in `room` of `tenant`.
    #[must_use]
    pub fn new(tenant: impl Into<String>, room: impl Into<String>, me: impl Into<String>) -> Self {
        Self {
            tenant: tenant.into(),
            room: room.into(),
            me: me.into(),
            bind: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            stun: None,
            punching: true,
            punch_interval: Duration::from_millis(25),
            patience: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(3),
        }
    }
}

/// A socket ready to reach one peer directly.
pub struct DirectEndpoint {
    config: DirectConfig,
    /// A second handle on the socket QUIC owns, for the probes.
    socket: UdpSocket,
    endpoint: quinn::Endpoint,
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    fingerprint: [u8; 32],
    identity: String,
    candidates: Vec<SocketAddr>,
}

impl std::fmt::Debug for DirectEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectEndpoint")
            .field("me", &self.config.me)
            .field("candidates", &self.candidates)
            .finish_non_exhaustive()
    }
}

impl DirectEndpoint {
    /// Bind a socket, find its candidate addresses, and make a certificate.
    ///
    /// Refuses before touching the network if the room does not allow direct
    /// paths. `exposure` is the caller's acknowledgement that the peer will
    /// learn the addresses this finds; see [`IpExposure`].
    ///
    /// # Errors
    /// [`Error::Ineligible`], or binding, certificate generation, or QUIC
    /// configuration failing. A STUN server that does not answer is not an
    /// error: the endpoint is still useful on a local network.
    pub async fn bind(
        config: DirectConfig,
        eligibility: &Eligibility,
        exposure: IpExposure,
    ) -> Result<Self, Error> {
        let _ = exposure;
        eligibility.check()?;
        install_crypto_provider();

        let socket = UdpSocket::bind(config.bind)?;
        let mut candidates = host_candidates(&socket)?;
        if let Some(stun) = config.stun {
            let probe = socket.try_clone()?;
            let reflexive = tokio::task::spawn_blocking(move || {
                super::stun::reflexive(&probe, stun, Duration::from_secs(1))
            })
            .await
            .map_err(|error| Error::Io(std::io::Error::other(error)))?;
            if let Ok(address) = reflexive
                && !candidates.contains(&address)
            {
                candidates.push(address);
            }
        }

        let generated = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()])
            .map_err(Error::tls)?;
        let certificate = generated.cert.der().clone();
        let key = PrivateKeyDer::try_from(generated.signing_key.serialize_der())
            .map_err(Error::tls)?;
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, certificate.as_ref());
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(digest.as_ref());
        let identity = certificate_identity(certificate.as_ref());

        let probes = socket.try_clone()?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| Error::Io(std::io::Error::other("no async runtime")))?;
        let endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)?;

        Ok(Self {
            config,
            socket: probes,
            endpoint,
            certificate,
            key,
            fingerprint,
            identity,
            candidates,
        })
    }

    /// The addresses this endpoint offers, best first.
    #[must_use]
    pub fn candidates(&self) -> &[SocketAddr] {
        &self.candidates
    }

    /// This endpoint's certificate identity: base64url SHA-256 of its leaf
    /// certificate, which a peer's proof of possession must name.
    ///
    /// What a [`PeerVerifier`] built on the relay's checks is constructed with.
    #[must_use]
    pub fn certificate_identity(&self) -> &str {
        &self.identity
    }

    /// The local address the socket is bound to.
    ///
    /// # Errors
    /// The socket refusing to say.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// An offer telling `peer` how to reach this endpoint.
    #[must_use]
    pub fn offer_to(&self, peer: &str) -> CandidateOffer {
        CandidateOffer {
            from: self.config.me.clone(),
            to: peer.to_owned(),
            certificate: self.fingerprint,
            candidates: self.candidates.clone(),
        }
    }

    /// Open a direct, verified MOQT session with the peer that sent `offer`.
    ///
    /// Both peers call this after exchanging offers. `credentials` are this
    /// side's, exactly as presented to the relay; the proof is made afresh for
    /// the peer. Returns the session and who the peer's token says they are.
    ///
    /// # Errors
    /// [`Error::Unreachable`] if no path opened within the configured patience,
    /// [`Error::PeerUnverified`] if the peer's credentials were refused here,
    /// [`Error::PeerRejected`] if ours were refused there. The relay session is
    /// untouched in every case.
    pub async fn establish(
        &self,
        offer: &CandidateOffer,
        credentials: &Credentials<'_>,
        verifier: &dyn PeerVerifier,
    ) -> Result<(Session, VerifiedPeer), Error> {
        if offer.to != self.config.me {
            return Err(Error::Offer("addressed to another participant"));
        }
        if offer.certificate == self.fingerprint {
            return Err(Error::Offer("this is our own offer"));
        }
        let dialling = self.fingerprint < offer.certificate;

        let _puncher = self.config.punching.then(|| {
            self.socket
                .try_clone()
                .map(|socket| {
                    Puncher::start(socket, offer.candidates.clone(), self.config.punch_interval)
                })
                .ok()
        });

        let patience = self.config.patience;
        let attempt = async {
            if dialling {
                self.dial(offer, credentials, verifier).await
            } else {
                self.accept(offer, credentials, verifier).await
            }
        };
        tokio::time::timeout(patience, attempt)
            .await
            .map_err(|_| Error::Unreachable(patience))?
    }

    fn transport(&self) -> Arc<quinn::TransportConfig> {
        let mut transport = quinn::TransportConfig::default();
        if let Ok(idle) = quinn::IdleTimeout::try_from(self.config.idle_timeout) {
            transport.max_idle_timeout(Some(idle));
        }
        transport.keep_alive_interval(Some(self.config.idle_timeout / 3));
        // A hole-punched path is usually short, and the default initial RTT of
        // a third of a second would make the first retransmission -- the one
        // that crosses once the far NAT has opened -- wait far longer than the
        // path needs.
        transport.initial_rtt(Duration::from_millis(50));
        Arc::new(transport)
    }

    async fn dial(
        &self,
        offer: &CandidateOffer,
        credentials: &Credentials<'_>,
        verifier: &dyn PeerVerifier,
    ) -> Result<(Session, VerifiedPeer), Error> {
        let mut tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned(offer.certificate)))
            .with_client_auth_cert(vec![self.certificate.clone()], self.key.clone_key())
            .map_err(Error::tls)?;
        crate::tls::apply_alpn(&mut tls);
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(Error::tls)?;
        let mut client = quinn::ClientConfig::new(Arc::new(crypto));
        client.transport_config(self.transport());

        // Every candidate at once. Whichever completes first is the path; the
        // rest are dropped, which closes them.
        let mut attempts = tokio::task::JoinSet::new();
        for candidate in &offer.candidates {
            let connecting = self
                .endpoint
                .connect_with(client.clone(), *candidate, SERVER_NAME)?;
            attempts.spawn(connecting);
        }
        let mut last = None;
        let connection = loop {
            match attempts.join_next().await {
                Some(Ok(Ok(connection))) => break connection,
                Some(Ok(Err(error))) => last = Some(error),
                Some(Err(_)) => {}
                None => {
                    return Err(match last {
                        Some(error) => Error::Handshake(error),
                        None => Error::Unreachable(self.config.patience),
                    });
                }
            }
        };
        drop(attempts);

        let peer_identity = relay_identity(&connection).ok_or(Error::NoRelayIdentity)?;
        let quic = connection.clone();
        let transport = raw(connection);
        let (mut send, recv) = transport.open_bi().await?;
        write(&mut send, &setup(credentials, &peer_identity)?).await?;

        let mut frames = Frames::new(recv);
        let Some(frame) = frames.next().await? else {
            return Err(peer_rejection(&quic).await);
        };
        if frame.message_type != MessageType::Setup {
            return Err(Error::Unexpected {
                found: frame.message_type,
                during: "direct SETUP",
            });
        }
        let theirs = decode_setup(&frame.body)?;
        let peer = self.check(&transport, &theirs, offer, verifier)?;

        // The accepting side spoke last, so it cannot know from SETUP alone
        // that its credentials passed here. An empty unidirectional stream says
        // so: it is the first stream either side opens, and a session reads an
        // empty stream as a subgroup with no header and ignores it.
        let mut admitted = transport.open_uni().await?;
        admitted.finish().map_err(Error::write)?;

        let session = Session::assemble(
            transport,
            (send, frames.into_inner()),
            self.endpoint.clone(),
            Role::Client,
        );
        Ok((session, peer))
    }

    async fn accept(
        &self,
        offer: &CandidateOffer,
        credentials: &Credentials<'_>,
        verifier: &dyn PeerVerifier,
    ) -> Result<(Session, VerifiedPeer), Error> {
        let mut tls = rustls::ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(Pinned(offer.certificate)))
            .with_single_cert(vec![self.certificate.clone()], self.key.clone_key())
            .map_err(Error::tls)?;
        tls.alpn_protocols = vec![moqom_transport::alpn::MOQT_DRAFT_19.to_vec()];
        let crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(Error::tls)?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server.transport_config(self.transport());
        self.endpoint.set_server_config(Some(server));

        // Anything that is not the pinned peer fails the handshake and is
        // ignored; the wait continues for the one that matters.
        let connection = loop {
            let incoming = self.endpoint.accept().await.ok_or(Error::Closed)?;
            if let Ok(connection) = incoming.await {
                break connection;
            }
        };
        self.endpoint.set_server_config(None);

        let peer_identity = relay_identity(&connection).ok_or(Error::NoRelayIdentity)?;
        let quic = connection.clone();
        let transport = raw(connection);
        let (mut send, recv) = transport.accept_bi().await?;
        let mut frames = Frames::new(recv);
        let frame = frames.next().await?.ok_or(Error::Closed)?;
        if frame.message_type != MessageType::Setup {
            return Err(Error::Unexpected {
                found: frame.message_type,
                during: "direct SETUP",
            });
        }
        let theirs = decode_setup(&frame.body)?;
        let peer = self.check(&transport, &theirs, offer, verifier)?;
        write(&mut send, &setup(credentials, &peer_identity)?).await?;

        // Not admitted until the dialler says so; a refusal arrives as the
        // connection closing with its reason instead.
        if transport.accept_uni().await.is_err() {
            return Err(peer_rejection(&quic).await);
        }

        let session = Session::assemble(
            transport,
            (send, frames.into_inner()),
            self.endpoint.clone(),
            Role::Server,
        );
        Ok((session, peer))
    }

    /// Verify the peer's SETUP, closing the connection with the reason if it
    /// does not pass.
    fn check(
        &self,
        transport: &moqom_transport::Session,
        theirs: &Setup,
        offer: &CandidateOffer,
        verifier: &dyn PeerVerifier,
    ) -> Result<VerifiedPeer, Error> {
        let result = (|| {
            let token = theirs
                .options
                .authorization_tokens()
                .next()
                .ok_or_else(|| "a direct session needs a MOQOM token".to_owned())?;
            let presented = PeerCredentials {
                token,
                proof: theirs.options.authorization_proof().map(Bytes::as_ref),
                local_certificate: &self.identity,
            };
            let peer = verifier.verify(&presented)?;
            admissible(&peer, &self.config.tenant, &self.config.room, &offer.from)?;
            Ok(peer)
        })();
        result.map_err(|reason: String| {
            transport.close(UNAUTHORIZED, reason.as_bytes());
            Error::PeerUnverified(reason)
        })
    }
}

fn raw(connection: quinn::Connection) -> moqom_transport::Session {
    moqom_transport::Session::raw(
        connection,
        web_transport_quinn::proto::ConnectRequest::new(placeholder_url()),
        web_transport_quinn::proto::ConnectResponse::OK,
    )
}

/// This side's SETUP: the token, and a proof bound to the peer's certificate.
fn setup(credentials: &Credentials<'_>, peer_identity: &str) -> Result<Setup, Error> {
    use moqom_proto::control::setup::option_type;
    let mut ours = Setup::new();
    ours.options
        .set_bytes(option_type::MOQT_IMPLEMENTATION, IMPLEMENTATION)
        .map_err(Error::setup)?;
    ours.options
        .set_bytes(
            option_type::AUTHORIZATION_TOKEN,
            Bytes::copy_from_slice(credentials.token),
        )
        .map_err(Error::setup)?;
    if let Some(key) = credentials.key {
        let proof = key.prove(credentials.token, peer_identity)?;
        ours.options
            .set_bytes(option_type::AUTHORIZATION_PROOF, Bytes::from(proof))
            .map_err(Error::setup)?;
    }
    Ok(ours)
}

fn decode_setup(body: &Bytes) -> Result<Setup, Error> {
    let mut body = body.clone();
    let len = body.len();
    Ok(Setup::decode(&mut body, len)?)
}

/// Why the peer closed, worded as the peer's refusal rather than a relay's.
async fn peer_rejection(connection: &quinn::Connection) -> Error {
    match crate::session::rejection(connection).await {
        Error::Rejected { code, reason } => Error::PeerRejected { code, reason },
        other => other,
    }
}

/// This socket's own addresses, for a peer on the same network.
///
/// A socket bound to every interface reports `0.0.0.0`, which is no use to a
/// peer, so the interface the default route leaves by is asked for instead: a
/// UDP `connect` picks it without sending anything.
fn host_candidates(socket: &UdpSocket) -> std::io::Result<Vec<SocketAddr>> {
    let bound = socket.local_addr()?;
    if !bound.ip().is_unspecified() {
        return Ok(vec![bound]);
    }
    let mut candidates = Vec::new();
    let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    // TEST-NET-1: never routed, so nothing is sent, but the kernel still picks
    // the interface it would use for the internet.
    if probe.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).is_ok()
        && let Ok(local) = probe.local_addr()
        && !local.ip().is_unspecified()
    {
        candidates.push(SocketAddr::new(local.ip(), bound.port()));
    }
    if candidates.is_empty() {
        candidates.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bound.port()));
    }
    Ok(candidates)
}

/// Trusts exactly the certificate whose SHA-256 is pinned, in either direction.
#[derive(Debug)]
struct Pinned([u8; 32]);

impl Pinned {
    fn matches(&self, end_entity: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, end_entity.as_ref());
        if digest.as_ref() == self.0 {
            Ok(())
        } else {
            Err(rustls::Error::General(
                "certificate is not the one the peer's offer named".into(),
            ))
        }
    }

    fn verify_signature(
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn schemes() -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.matches(end_entity)?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not used over QUIC".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Self::verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        Self::schemes()
    }
}

impl rustls::server::danger::ClientCertVerifier for Pinned {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        self.matches(end_entity)?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not used over QUIC".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Self::verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        Self::schemes()
    }
}
