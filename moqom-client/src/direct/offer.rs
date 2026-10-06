//! Candidate offers: where to reach a peer, and which certificate it will show.
//!
//! An offer travels through the relay on a room track, and the relay must not be
//! able to read it: the addresses in it are exactly what direct mode is careful
//! about, and the certificate fingerprint is what stops anybody else answering
//! for the peer. So it is sealed with AES-256-GCM under a key derived from the
//! room's end-to-end secret. Whoever cannot decrypt the room's media cannot read
//! an offer, and cannot forge one either, since a forged offer would not open.
//!
//! The wire form, before sealing, is deliberately plain:
//!
//! ```text
//! version(1) | len(1) from | len(1) to | certificate sha-256(32)
//!            | count(1) | count * (family(1) address(4|16) port(2))
//! ```
//!
//! and after: `"MQD1" | nonce(12) | ciphertext and tag`. The room's identifier
//! is authenticated alongside, so an offer sealed for one room does not open in
//! another that happens to share a secret.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use crate::Error;

const MAGIC: &[u8; 4] = b"MQD1";
const VERSION: u8 = 1;
const SALT: &[u8] = b"moqom direct candidate offer v1";
/// More than any real host has, and few enough that an offer stays one packet.
const MAX_CANDIDATES: usize = 16;

/// The room's end-to-end secret, as far as candidate offers are concerned.
///
/// Supplied by whatever manages the room's encryption: for an MLS room, an
/// exporter secret from the participants' group. It must be a secret viewers do
/// not hold, since an offer carries the participants' network addresses.
pub struct RoomSecret {
    key: LessSafeKey,
    room: Vec<u8>,
}

impl RoomSecret {
    /// Derive the offer key for `room` from `secret`.
    ///
    /// # Errors
    /// [`Error::Offer`] for a secret shorter than 16 bytes, which is too short
    /// to be one.
    pub fn new(secret: &[u8], room: &str) -> Result<Self, Error> {
        if secret.len() < 16 {
            return Err(Error::Offer("the room secret is shorter than 16 bytes"));
        }
        let info = [room.as_bytes()];
        let unbound: UnboundKey = Salt::new(HKDF_SHA256, SALT)
            .extract(secret)
            .expand(&info, &AES_256_GCM)
            .map_err(|_| Error::Offer("deriving the offer key failed"))?
            .into();
        Ok(Self {
            key: LessSafeKey::new(unbound),
            room: room.as_bytes().to_vec(),
        })
    }

    fn aad(&self) -> Vec<u8> {
        let mut aad = MAGIC.to_vec();
        aad.extend_from_slice(&self.room);
        aad
    }
}

impl std::fmt::Debug for RoomSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoomSecret").finish_non_exhaustive()
    }
}

/// Where one participant can be reached, addressed to one other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateOffer {
    /// The sender, as `user/device`.
    pub from: String,
    /// The one participant this offer is for, as `user/device`.
    pub to: String,
    /// SHA-256 of the certificate the sender's endpoint will present.
    pub certificate: [u8; 32],
    /// Addresses to try, best first.
    pub candidates: Vec<SocketAddr>,
}

impl CandidateOffer {
    /// Seal this offer for the room.
    ///
    /// # Errors
    /// [`Error::Offer`] if a name is longer than 255 bytes, there are more than
    /// sixteen candidates, or the random source failed.
    pub fn seal(&self, secret: &RoomSecret) -> Result<Vec<u8>, Error> {
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| Error::Offer("the random source failed"))?;
        self.seal_with(secret, nonce)
    }

    fn seal_with(&self, secret: &RoomSecret, nonce: [u8; NONCE_LEN]) -> Result<Vec<u8>, Error> {
        let mut plain = self.encode()?;
        secret
            .key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(secret.aad()),
                &mut plain,
            )
            .map_err(|_| Error::Offer("sealing failed"))?;

        let mut sealed = Vec::with_capacity(MAGIC.len() + NONCE_LEN + plain.len());
        sealed.extend_from_slice(MAGIC);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&plain);
        Ok(sealed)
    }

    /// Open an offer sealed for the room, refusing one not addressed to `me`.
    ///
    /// # Errors
    /// [`Error::Offer`] if the bytes are not an offer, do not open under this
    /// room's secret, or are addressed to somebody else.
    pub fn open(sealed: &[u8], secret: &RoomSecret, me: &str) -> Result<Self, Error> {
        let rest = sealed
            .strip_prefix(MAGIC.as_slice())
            .ok_or(Error::Offer("not a candidate offer"))?;
        if rest.len() < NONCE_LEN {
            return Err(Error::Offer("truncated"));
        }
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| Error::Offer("truncated"))?;
        let mut buffer = ciphertext.to_vec();
        let plain = secret
            .key
            .open_in_place(nonce, Aad::from(secret.aad()), &mut buffer)
            .map_err(|_| Error::Offer("does not open under this room's secret"))?;

        let offer = Self::decode(plain)?;
        if offer.to != me {
            return Err(Error::Offer("addressed to another participant"));
        }
        Ok(offer)
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.candidates.len() > MAX_CANDIDATES {
            return Err(Error::Offer("more than sixteen candidates"));
        }
        let mut out = vec![VERSION];
        for name in [&self.from, &self.to] {
            let len = u8::try_from(name.len()).map_err(|_| Error::Offer("name too long"))?;
            out.push(len);
            out.extend_from_slice(name.as_bytes());
        }
        out.extend_from_slice(&self.certificate);
        out.push(self.candidates.len() as u8);
        for candidate in &self.candidates {
            match candidate.ip() {
                IpAddr::V4(ip) => {
                    out.push(4);
                    out.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.push(6);
                    out.extend_from_slice(&ip.octets());
                }
            }
            out.extend_from_slice(&candidate.port().to_be_bytes());
        }
        Ok(out)
    }

    fn decode(mut bytes: &[u8]) -> Result<Self, Error> {
        const SHORT: Error = Error::Offer("truncated");
        fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Result<&'a [u8], Error> {
            if bytes.len() < n {
                return Err(SHORT);
            }
            let (head, tail) = bytes.split_at(n);
            *bytes = tail;
            Ok(head)
        }
        fn name(bytes: &mut &[u8]) -> Result<String, Error> {
            let len = take(bytes, 1)?[0] as usize;
            String::from_utf8(take(bytes, len)?.to_vec())
                .map_err(|_| Error::Offer("a name is not UTF-8"))
        }

        if take(&mut bytes, 1)?[0] != VERSION {
            return Err(Error::Offer("unknown offer version"));
        }
        let from = name(&mut bytes)?;
        let to = name(&mut bytes)?;
        let mut certificate = [0u8; 32];
        certificate.copy_from_slice(take(&mut bytes, 32)?);
        let count = take(&mut bytes, 1)?[0] as usize;
        if count > MAX_CANDIDATES {
            return Err(Error::Offer("more than sixteen candidates"));
        }
        let mut candidates = Vec::with_capacity(count);
        for _ in 0..count {
            let ip = match take(&mut bytes, 1)?[0] {
                4 => {
                    let octets: [u8; 4] = take(&mut bytes, 4)?.try_into().map_err(|_| SHORT)?;
                    IpAddr::V4(Ipv4Addr::from(octets))
                }
                6 => {
                    let octets: [u8; 16] = take(&mut bytes, 16)?.try_into().map_err(|_| SHORT)?;
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
                _ => return Err(Error::Offer("unknown address family")),
            };
            let port = take(&mut bytes, 2)?;
            candidates.push(SocketAddr::new(ip, u16::from_be_bytes([port[0], port[1]])));
        }
        if !bytes.is_empty() {
            return Err(Error::Offer("trailing bytes"));
        }
        Ok(Self {
            from,
            to,
            certificate,
            candidates,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> CandidateOffer {
        CandidateOffer {
            from: "ada/dev-a".to_owned(),
            to: "bob/dev-b".to_owned(),
            certificate: [9u8; 32],
            candidates: vec![
                "192.0.2.1:4433".parse().expect("v4"),
                "[2001:db8::1]:4433".parse().expect("v6"),
            ],
        }
    }

    #[test]
    fn an_offer_opens_for_its_addressee_under_the_same_room_secret() {
        let secret = RoomSecret::new(&[1u8; 32], "acme/room-42").expect("secret");
        let sealed = offer().seal(&secret).expect("sealed");
        let opened = CandidateOffer::open(&sealed, &secret, "bob/dev-b").expect("opens");
        assert_eq!(opened, offer());
    }

    #[test]
    fn the_relay_cannot_read_the_addresses() {
        let secret = RoomSecret::new(&[1u8; 32], "acme/room-42").expect("secret");
        let sealed = offer().seal(&secret).expect("sealed");
        assert!(!sealed.windows(4).any(|w| w == [192, 0, 2, 1]));
        assert!(!sealed.windows(5).any(|w| w == b"ada/d"));
    }

    #[test]
    fn an_offer_does_not_open_under_another_secret_or_room_or_addressee() {
        let secret = RoomSecret::new(&[1u8; 32], "acme/room-42").expect("secret");
        let sealed = offer().seal(&secret).expect("sealed");

        let other_secret = RoomSecret::new(&[2u8; 32], "acme/room-42").expect("secret");
        assert!(CandidateOffer::open(&sealed, &other_secret, "bob/dev-b").is_err());
        let other_room = RoomSecret::new(&[1u8; 32], "acme/room-43").expect("secret");
        assert!(CandidateOffer::open(&sealed, &other_room, "bob/dev-b").is_err());
        assert!(CandidateOffer::open(&sealed, &secret, "eve/dev-e").is_err());
    }

    #[test]
    fn a_tampered_offer_does_not_open() {
        let secret = RoomSecret::new(&[1u8; 32], "acme/room-42").expect("secret");
        let mut sealed = offer().seal(&secret).expect("sealed");
        let last = sealed.len() - 20;
        sealed[last] ^= 1;
        assert!(CandidateOffer::open(&sealed, &secret, "bob/dev-b").is_err());
    }

    /// The same bytes `MoqomKit`'s `CandidateOffer` seals with this nonce, so an
    /// offer from either SDK opens in the other.
    const VECTOR: &str = "4d514431030303030303030303030303c830f752e602077e6902cf60202483a4477a576bb7baac25fe0cbc9ddd1f24a64841c7fdeb7dbb33374c7920c42d5e2a46ce6520940c91af81fc6d85bb163c934fcccfb8aad2913266668ceb2d5877401d8ea0c6ce5808c27997bc0452de5fb6";

    #[test]
    fn an_offer_sealed_with_a_known_nonce_matches_the_shared_vector() {
        let secret = RoomSecret::new(&[1u8; 32], "acme/room-42").expect("secret");
        let sealed = offer().seal_with(&secret, [3u8; NONCE_LEN]).expect("sealed");
        let hex = sealed.iter().fold(String::new(), |mut hex, byte| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
            hex
        });
        assert_eq!(hex, VECTOR);
        let opened = CandidateOffer::open(&sealed, &secret, "bob/dev-b").expect("opened");
        assert_eq!(opened, offer());
    }

    #[test]
    fn a_short_secret_is_refused() {
        assert!(RoomSecret::new(&[1u8; 8], "room").is_err());
    }
}
