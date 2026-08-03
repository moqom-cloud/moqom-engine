//! A moderator's call, the Go control plane, this relay, and a real connection.
//!
//! `supervision.rs` proves the relay does the right thing once its policy says
//! somebody is banned, and `link.rs` proves the link speaks gRPC to a server
//! written in this crate. Between those two sits the seam neither can reach: two
//! implementations of one protobuf contract, one of which was written from the
//! Go side. A disagreement there — the wrong `oneof` arm read for a ban subject,
//! a device derived differently at each end, a directive answered with a result
//! the control plane does not match to its request — passes every test in both
//! repositories and shows up as a ban that does not land.
//!
//! So this runs the real control plane binary, attaches a real link to it, joins
//! a real client over QUIC with a token that control plane minted, and then bans
//! them through the admin API. Nothing here is a fixture, which is the point.
//!
//! Needs a Go toolchain, so these are `#[ignore]`d and run by
//! `moqom/tools/interop.sh`, which builds the binary and points
//! `MOQOM_CONTROL_BIN` at it. Asked to run without that variable they panic
//! rather than skip: a cross-language check that quietly excuses itself puts a
//! green tick over an untested seam.

mod support;

/// The control plane's admin API, generated for these tests only.
///
/// This is the customer's half of the contract — create a room, mint a token,
/// issue a ban — and a relay must never call it. See `build.rs` for why it is
/// generated apart from the link's own bindings rather than into the crate.
#[allow(clippy::all, clippy::pedantic, missing_docs, dead_code)]
mod admin {
    include!("generated/moqom.admin.v1.rs");
}

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use admin::moderation_client::ModerationClient;
use admin::rooms_client::RoomsClient;
use admin::tokens_client::TokensClient;
use moqom_relay::{Authenticator, Link, Supervisor, VerificationKey};
use support::{Client, Relay, within};

const TENANT: &str = "acme";
const ROOM: &str = "room-42";
const OWNER: &str = "interop-owner-key";
const RELAY: &str = "interop-relay-key";
const ISSUER: &str = "moqom-interop";

/// What the relay closes a session with when it will not have it.
const UNAUTHORIZED: u64 = 0x03;

/// A control plane on a loopback port, killed when this is dropped.
struct ControlPlane {
    process: Child,
    address: String,
    _accounts: TempFile,
}

impl ControlPlane {
    fn start() -> Result<Self, String> {
        let binary = std::env::var("MOQOM_CONTROL_BIN").map_err(|_| {
            "MOQOM_CONTROL_BIN is not set; run moqom/tools/interop.sh to build the control \
             plane and run this test against it"
                .to_owned()
        })?;

        // Two accounts, because the control plane refuses to let one credential
        // be both. A relay may not touch the admin API and an admin credential
        // may not hold the link open, and this test needs each half refused to
        // the other.
        let accounts = TempFile::write(
            "moqom-relay-interop-accounts.json",
            &format!(
                r#"{{"accounts":[
                    {{
                        "name":"interop-owner",
                        "credential":"{OWNER}",
                        "tenant":"{TENANT}",
                        "publish":["audio","video","screen_share","data"],
                        "preset":"owner",
                        "is_owner":true
                    }},
                    {{
                        "name":"interop-relay",
                        "credential":"{RELAY}",
                        "is_relay":true
                    }}
                ]}}"#
            ),
        )?;

        let mut process = Command::new(&binary)
            // Port zero, and the address is read back from the log. Reserving
            // one first would race with anything else on the machine doing the
            // same.
            .env("MOQOM_CONTROL_ADDR", "127.0.0.1:0")
            .env("MOQOM_CONTROL_ACCOUNTS", accounts.path())
            .env("MOQOM_CONTROL_STORE", "memory")
            .env("MOQOM_CONTROL_ISSUER", ISSUER)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("starting {binary}: {e}"))?;

        let stderr = process
            .stderr
            .take()
            .ok_or_else(|| "the control plane has no stderr".to_owned())?;

        // Drained on a thread, and drained to the end rather than until the
        // address is found. A Go process that writes to a closed stderr dies of
        // SIGPIPE, so stopping early would kill the server at its next log line.
        let (found, addresses) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if let Some(address) = listening_address(&line) {
                    let _ = found.send(address);
                }
            }
        });

        let Ok(address) = addresses.recv_timeout(Duration::from_secs(20)) else {
            let _ = process.kill();
            return Err("the control plane did not report an address within 20s".to_owned());
        };

        Ok(Self {
            process,
            address,
            _accounts: accounts,
        })
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }

    /// A connected channel. The control plane expects TLS to be terminated in
    /// front of it, and there is not one of those here.
    async fn channel(&self) -> tonic::transport::Channel {
        tonic::transport::Endpoint::from_shared(self.endpoint())
            .expect("a valid endpoint")
            .connect()
            .await
            .expect("connecting to the control plane")
    }
}

impl Drop for ControlPlane {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// Pulls the bound address out of the control plane's structured log.
fn listening_address(line: &str) -> Option<String> {
    if !line.contains("control plane listening") {
        return None;
    }
    let start = line.find(r#""address":""#)? + r#""address":""#.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

/// A file that removes itself.
struct TempFile(std::path::PathBuf);

impl TempFile {
    fn write(name: &str, contents: &str) -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!("{}-{name}", std::process::id()));
        std::fs::write(&path, contents).map_err(|e| format!("writing {}: {e}", path.display()))?;
        Ok(Self(path))
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// An admin call, carrying the owner's credential.
fn as_owner<T>(body: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(body);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {OWNER}").parse().expect("a header value"),
    );
    request
}

/// The relay's side of the same deployment.
fn supervisor(control: &ControlPlane) -> Supervisor {
    Supervisor {
        endpoint: control.endpoint(),
        credential: RELAY.to_owned(),
        relay_id: "interop-relay-1".to_owned(),
        region: "loopback".to_owned(),
        // A deployment authenticates the control plane with a certificate; this
        // one is a process on the same machine, reached over a loopback port
        // that nothing else can be on.
        tls: None,
    }
}

/// An authenticator holding the keys this control plane is signing with.
///
/// The relay is configured with its verifiers rather than told them over the
/// link, so this is the same fetch a deployment does at startup.
async fn keys_of(control: &ControlPlane) -> Authenticator {
    let mut tokens = TokensClient::new(control.channel().await);
    let published = tokens
        .list_verification_keys(as_owner(admin::ListVerificationKeysRequest {
            tenant: TENANT.to_owned(),
        }))
        .await
        .expect("listing verification keys")
        .into_inner();
    assert!(
        !published.keys.is_empty(),
        "the control plane published no verification keys, so nothing it mints can be verified"
    );

    let set = published
        .keys
        .iter()
        .map(|key| key.jwk.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Authenticator::new(
        ISSUER,
        VerificationKey::parse_set(&format!("[{set}]")).expect("the Go JWKs render as a JWK set"),
    )
}

/// A token for `username`, minted by the control plane the relay is attached to.
async fn mint(control: &ControlPlane, username: &str, thumbprint: &str) -> (String, String) {
    let mut tokens = TokensClient::new(control.channel().await);
    let minted = tokens
        .mint_client_token(as_owner(admin::MintClientTokenRequest {
            tenant: TENANT.to_owned(),
            username: username.to_owned(),
            device_thumbprint: thumbprint.to_owned(),
            room: ROOM.to_owned(),
            grants: Some(admin::Grants {
                publish: vec![
                    admin::PublishScope::Audio as i32,
                    admin::PublishScope::Video as i32,
                ],
                moderation: Vec::new(),
                is_owner: false,
            }),
            lifetime: Some(prost_types::Duration {
                seconds: 600,
                nanos: 0,
            }),
            ..Default::default()
        }))
        .await
        .expect("minting a client token")
        .into_inner();

    let identity = minted.identity.expect("a minted token names its holder");
    assert!(
        !identity.device.is_empty(),
        "the control plane derived no device from the thumbprint"
    );
    (minted.token, identity.device)
}

/// Wait until the relay has said hello and been welcomed.
///
/// Read from the exposition rather than from a handle on the link, because it is
/// what an operator has: a relay whose gauge says attached and whose stream is
/// not is the failure this waits on being able to see.
async fn attached(relay: &Relay) {
    support::eventually(
        "the relay to attach to the control plane",
        relay,
        |scrape| support::value(scrape, "moqom_relay_control_attached") == 1,
    )
    .await;
}

/// Wait until the control plane has been told about the session.
async fn reported(control: &ControlPlane, device: &str) {
    let mut rooms = RoomsClient::new(control.channel().await);
    within("the control plane to hear about the session", async {
        loop {
            let listed = rooms
                .list_participants(as_owner(admin::ListParticipantsRequest {
                    tenant: TENANT.to_owned(),
                    room: ROOM.to_owned(),
                    ..Default::default()
                }))
                .await
                .expect("listing participants")
                .into_inner();
            let here = listed.participants.iter().any(|participant| {
                participant
                    .identity
                    .as_ref()
                    .is_some_and(|identity| identity.device == device)
                    && participant.presence == admin::Presence::Connected as i32
            });
            if here {
                return listed;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

/// The whole path: a call to the admin API ends in a phone's connection closing.
#[tokio::test]
#[ignore = "needs a control plane binary; run moqom/tools/interop.sh"]
async fn a_ban_issued_through_the_admin_api_closes_a_session_here() {
    let control = ControlPlane::start().unwrap_or_else(|why| panic!("{why}"));
    let mut rooms = RoomsClient::new(control.channel().await);
    rooms
        .create_room(as_owner(admin::CreateRoomRequest {
            tenant: TENANT.to_owned(),
            room: ROOM.to_owned(),
            owner_username: "ada".to_owned(),
            ..Default::default()
        }))
        .await
        .expect("creating the room");

    let relay = Relay::verifying(keys_of(&control).await);
    let _link = Link::attach(supervisor(&control), relay.fabric.clone());
    attached(&relay).await;

    let (token, device) = mint(&control, "mallory", "thumbprint-of-mallorys-phone").await;
    let mallory = Client::connect_as(&relay, &token).await;

    // The device the relay derived from the token and the device the control
    // plane derived from the thumbprint have to be one string, or a ban keyed on
    // one misses a session keyed on the other.
    reported(&control, &device).await;

    let mut moderation = ModerationClient::new(control.channel().await);
    let entry = moderation
        .ban(as_owner(admin::BanRequest {
            tenant: TENANT.to_owned(),
            room: ROOM.to_owned(),
            scope: admin::BanScope::Room as i32,
            subject: Some(admin::BanSubject {
                key: Some(admin::ban_subject::Key::Username("mallory".to_owned())),
            }),
            code: admin::ModerationCode::Harassment as i32,
            ..Default::default()
        }))
        .await
        .expect("banning")
        .into_inner();

    // Not a formality. `enforced` is false unless this relay's `DirectiveResult`
    // came back and was matched to the directive that caused it, so a moderator
    // is told the truth about whether anything happened.
    assert!(
        entry.enforced,
        "the control plane did not hear this relay carry the ban out"
    );

    let closed = mallory.closed().await;
    assert_eq!(closed.code, UNAUTHORIZED);
    // Either directive may reach the session first — the ban sweeps the room,
    // the eject names the person — and both are correct. What matters is that
    // the reason says something a client can show.
    assert!(
        closed.reason == "banned" || closed.reason == "moderation_code_harassment",
        "unexpected close reason {:?}",
        closed.reason
    );

    // And the ban outlives the connection it closed. A fresh token for the same
    // person is a valid token; the relay refuses it from its own policy, without
    // asking the control plane anything.
    let (again, _) = mint(&control, "mallory", "thumbprint-of-mallorys-phone").await;
    let refused = Client::try_connect_as(&relay, &again)
        .await
        .err()
        .expect("a banned user reconnected");
    assert_eq!(refused.reason, "banned from this room");
}

/// Lifting a ban has to travel too, or a room accumulates people it will never
/// let back in and only a relay restart clears them.
#[tokio::test]
#[ignore = "needs a control plane binary; run moqom/tools/interop.sh"]
async fn an_unban_lets_them_back_in() {
    let control = ControlPlane::start().unwrap_or_else(|why| panic!("{why}"));
    let mut rooms = RoomsClient::new(control.channel().await);
    rooms
        .create_room(as_owner(admin::CreateRoomRequest {
            tenant: TENANT.to_owned(),
            room: ROOM.to_owned(),
            owner_username: "ada".to_owned(),
            ..Default::default()
        }))
        .await
        .expect("creating the room");

    let relay = Relay::verifying(keys_of(&control).await);
    let _link = Link::attach(supervisor(&control), relay.fabric.clone());
    attached(&relay).await;

    let (token, device) = mint(&control, "mallory", "thumbprint-of-mallorys-phone").await;
    let mallory = Client::connect_as(&relay, &token).await;
    reported(&control, &device).await;

    let subject = Some(admin::BanSubject {
        key: Some(admin::ban_subject::Key::Username("mallory".to_owned())),
    });
    let mut moderation = ModerationClient::new(control.channel().await);
    moderation
        .ban(as_owner(admin::BanRequest {
            tenant: TENANT.to_owned(),
            room: ROOM.to_owned(),
            scope: admin::BanScope::Room as i32,
            subject: subject.clone(),
            code: admin::ModerationCode::OperatorAction as i32,
            ..Default::default()
        }))
        .await
        .expect("banning");
    mallory.closed().await;

    let lifted = moderation
        .unban(as_owner(admin::UnbanRequest {
            tenant: TENANT.to_owned(),
            room: ROOM.to_owned(),
            scope: admin::BanScope::Room as i32,
            subject,
            ..Default::default()
        }))
        .await
        .expect("lifting the ban")
        .into_inner();
    assert!(
        lifted.enforced,
        "the control plane did not hear this relay lift the ban"
    );

    let (again, _) = mint(&control, "mallory", "thumbprint-of-mallorys-phone").await;
    let _back = Client::connect_as(&relay, &again).await;
}

/// Ending a broadcast has to end it for everybody watching, and their tokens are
/// still perfectly valid at the moment it happens.
#[tokio::test]
#[ignore = "needs a control plane binary; run moqom/tools/interop.sh"]
async fn closing_a_room_from_the_admin_api_empties_it() {
    let control = ControlPlane::start().unwrap_or_else(|why| panic!("{why}"));
    let mut rooms = RoomsClient::new(control.channel().await);
    rooms
        .create_room(as_owner(admin::CreateRoomRequest {
            tenant: TENANT.to_owned(),
            room: ROOM.to_owned(),
            owner_username: "ada".to_owned(),
            ..Default::default()
        }))
        .await
        .expect("creating the room");

    let relay = Relay::verifying(keys_of(&control).await);
    let _link = Link::attach(supervisor(&control), relay.fabric.clone());
    attached(&relay).await;

    let (token, device) = mint(&control, "ada", "thumbprint-of-adas-phone").await;
    let ada = Client::connect_as(&relay, &token).await;
    reported(&control, &device).await;

    // Taken now rather than after, because the control plane will not mint for a
    // room that has ended -- so the token a client tries to come back with is
    // always one it was already holding.
    let (held, _) = mint(&control, "ada", "thumbprint-of-adas-phone").await;

    let closed = rooms
        .close_room(as_owner(admin::CloseRoomRequest {
            tenant: TENANT.to_owned(),
            room: ROOM.to_owned(),
            code: admin::ModerationCode::OperatorAction as i32,
            ..Default::default()
        }))
        .await
        .expect("closing the room")
        .into_inner();
    assert_eq!(closed.lifecycle, admin::RoomLifecycle::Ended as i32);

    let ending = ada.closed().await;
    assert_eq!(ending.code, UNAUTHORIZED);
    assert_eq!(ending.reason, "moderation_code_operator_action");

    // The room stays shut here without another word from the control plane,
    // which is what stops a client reconnecting into a broadcast that is over.
    match Client::try_connect_as(&relay, &held).await {
        Err(refused) => assert_eq!(refused.reason, "this room is closed"),
        Ok(_) => panic!("the relay let somebody into a closed room"),
    }
}
