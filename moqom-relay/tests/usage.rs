//! Usage reporting against a stand-in for the billing endpoint.
//!
//! The stand-in is a raw socket rather than a framework so that what it sees is
//! what the relay sent, byte for byte, and so that what it answers can be any
//! status at all — the cases worth testing are the ones a real endpoint only
//! produces on a bad day.

mod support;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use moqom_relay::Usage;
use moqom_relay::usage::report::{Credential, Endpoint};
use moqom_relay::usage::{Config, Hosting};
use serde_json::Value;
use support::tokens::Grant;
use support::{Client, Relay, within};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// One request as the endpoint received it.
#[derive(Debug, Clone)]
struct Seen {
    authorization: String,
    body: Value,
}

impl Seen {
    fn ids(&self) -> Vec<String> {
        self.records()
            .iter()
            .map(|r| r["id"].as_str().expect("an id").to_owned())
            .collect()
    }

    fn records(&self) -> Vec<Value> {
        self.body["records"].as_array().cloned().unwrap_or_default()
    }
}

type Answer = Arc<dyn Fn(usize, &Seen) -> (u16, String) + Send + Sync>;

/// A billing endpoint that records every request and answers with `answer`,
/// which is given how many requests came before this one.
struct Billing {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Billing {
    async fn start(answer: Answer) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
        let url = format!("http://{}", listener.local_addr().expect("bound"));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let counted = Arc::new(AtomicUsize::new(0));
        let recording = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let answer = Arc::clone(&answer);
                let recording = Arc::clone(&recording);
                let counted = Arc::clone(&counted);
                tokio::spawn(async move {
                    let Some(request) = read_request(&mut socket).await else {
                        return;
                    };
                    let index = counted.fetch_add(1, Ordering::SeqCst);
                    let (status, body) = answer(index, &request);
                    recording.lock().expect("unpoisoned").push(request);
                    let response = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self { url, seen }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("unpoisoned").clone()
    }

    /// Wait until the requests so far satisfy `check`.
    async fn until(&self, what: &str, check: impl Fn(&[Seen]) -> bool) -> Vec<Seen> {
        within(what, async {
            loop {
                let seen = self.seen();
                if check(&seen) {
                    return seen;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
    }
}

async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<Seen> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..n]);
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let header = |name: &str| {
        head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    };
    let length: usize = header("content-length")?.parse().ok()?;
    while buffer.len() < head_end + length {
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
    Some(Seen {
        authorization: header("authorization").unwrap_or_default(),
        body: serde_json::from_slice(&buffer[head_end..head_end + length]).ok()?,
    })
}

/// Short enough that a test sees several intervals in a second or two.
fn quick(hosting: Hosting) -> Config {
    Config {
        interval: Duration::from_secs(1),
        first_retry: Duration::from_millis(50),
        longest_retry: Duration::from_millis(200),
        ..Config::new("relay-test", hosting)
    }
}

fn accepted(seen: &Seen) -> String {
    format!(
        r#"{{"charged":{n},"duplicates":0,"unbilled":0,"total":{n}}}"#,
        n = seen.records().len()
    )
}

#[tokio::test]
async fn a_child_relays_link_is_not_metered_and_cannot_be_claimed() {
    let usage = Usage::new(quick(Hosting::Cloud));
    let relay = Relay::metering(usage.clone());

    let _link = Client::connect_as(&relay, &Grant::relay_link().token()).await;
    let _viewer = Client::connect_as(&relay, &Grant::viewer().token()).await;
    within("both sessions to be admitted", async {
        while relay.fabric.roster().count() < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert_eq!(
        usage.stats().meters,
        1,
        "the viewer is metered and the link is not"
    );

    // Without the control plane's signature the claim is worth nothing: the
    // session is refused, so it is neither unmetered nor served.
    for (what, token) in [
        ("forged", Grant::relay_link().token_forged()),
        ("unsigned", Grant::relay_link().token_unsigned()),
    ] {
        assert!(
            Client::try_connect_as(&relay, &token).await.is_err(),
            "a {what} relay link was admitted"
        );
    }
    assert_eq!(usage.stats().meters, 1);
}

#[tokio::test]
async fn a_failed_report_is_retried_with_the_same_identifiers() {
    let billing = Billing::start(Arc::new(|index, seen: &Seen| {
        if index < 2 {
            (500, r#"{"error":"try later"}"#.to_owned())
        } else {
            (200, accepted(seen))
        }
    }))
    .await;
    let usage = Usage::new(quick(Hosting::Cloud));
    let relay = Relay::metering(usage.clone());
    let reporter = usage
        .report_to(
            Endpoint::new(&billing.url, Credential::Value("operator".to_owned())).expect("url"),
        )
        .expect("enabled");

    let _viewer = Client::connect_as(&relay, &Grant::viewer().token()).await;
    let seen = billing
        .until("a batch retried twice and accepted", |s| s.len() >= 3)
        .await;

    assert_eq!(seen[0].authorization, "Bearer operator");
    assert!(!seen[0].ids().is_empty());
    assert_eq!(seen[0].ids(), seen[1].ids(), "the retry is the same batch");
    assert_eq!(seen[1].ids(), seen[2].ids(), "and so is the one accepted");

    let record = &seen[0].records()[0];
    assert_eq!(record["tenant"], "acme");
    assert_eq!(record["room"], "room-42");
    assert_eq!(record["role"], "audience");
    assert_eq!(record["tier"], "audio", "watching nothing is the floor");
    assert!(
        record["participant"]
            .as_str()
            .is_some_and(|p| p.starts_with("ada/"))
    );
    assert!(
        record["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("relay-test:")),
        "{record}"
    );
    // An interval is a second here; the slack is for a loaded machine waking
    // the cutter late.
    assert!(
        record["seconds"]
            .as_u64()
            .is_some_and(|s| (1..=5).contains(&s)),
        "{record}"
    );

    // The billing server has seen the third request; the reporter may not have
    // read its answer yet.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let stats = loop {
        let stats = usage.stats();
        if stats.sent >= 1 || tokio::time::Instant::now() >= deadline {
            break stats;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(stats.reports_failed, 2);
    assert!(stats.sent >= 1);
    assert!(stats.last_success > 0);
    reporter.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn a_refused_batch_is_dropped_rather_than_retried() {
    let billing = Billing::start(Arc::new(|_, _: &Seen| {
        (400, r#"{"error":"record 0: unknown tier"}"#.to_owned())
    }))
    .await;
    let usage = Usage::new(quick(Hosting::Cloud));
    let relay = Relay::metering(usage.clone());
    let reporter = usage
        .report_to(
            Endpoint::new(&billing.url, Credential::Value("operator".to_owned())).expect("url"),
        )
        .expect("enabled");

    let _ada = Client::connect_as(&relay, &Grant::viewer().token()).await;
    let _bea = Client::connect_as(
        &relay,
        &Grant {
            user: "bea",
            ..Grant::viewer()
        }
        .token(),
    )
    .await;
    within("refused records to be dropped", async {
        while usage.stats().dropped_rejected < 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;

    // A record alone in a refused batch is the end of the search: it is never
    // sent alone twice.
    let alone: Vec<String> = billing
        .seen()
        .iter()
        .filter(|s| s.records().len() == 1)
        .flat_map(Seen::ids)
        .collect();
    let mut unique = alone.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(alone.len(), unique.len(), "{alone:?}");
    assert_eq!(usage.stats().sent, 0);
    reporter.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn a_tenant_not_admitting_stops_new_sessions_and_keeps_existing_ones() {
    let admitting = Arc::new(AtomicBool::new(true));
    let answering = Arc::clone(&admitting);
    let billing = Billing::start(Arc::new(move |_, seen: &Seen| {
        let records = seen.records().len();
        let admitted = answering.load(Ordering::SeqCst);
        (
            200,
            format!(
                r#"{{"charged":{records},"duplicates":0,"unbilled":0,"total":{records},"admitted":{admitted}}}"#
            ),
        )
    }))
    .await;

    // Not a real key: the relay sends whatever the file holds, and the stand-in
    // accepts anything.
    let key = std::env::temp_dir().join(format!("moqom-usage-test-{}.key", std::process::id()));
    std::fs::write(&key, "mqk_test\n").expect("writing the key file");

    let usage = Usage::new(quick(Hosting::SelfHosted));
    let relay = Relay::metering(usage.clone());
    let reporter = usage
        .report_to(Endpoint::new(&billing.url, Credential::File(key.clone())).expect("url"))
        .expect("enabled");

    let existing = Client::connect_as(&relay, &Grant::viewer().token()).await;
    admitting.store(false, Ordering::SeqCst);
    within("the relay to hear the tenant is not admitting", async {
        while usage.admitting() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;

    let refused = Client::try_connect_as(
        &relay,
        &Grant {
            user: "bea",
            ..Grant::viewer()
        }
        .token(),
    )
    .await
    .err()
    .expect("a new session while not admitting");
    assert_eq!(refused.reason, "this account is not admitting new sessions");
    assert!(
        tokio::time::timeout(Duration::from_millis(300), existing.closed())
            .await
            .is_err(),
        "the session already open must be left alone"
    );

    // Heard from the next report, which a self-hosted relay sends even with
    // nothing to report, so the gate reopens without a session to carry it.
    admitting.store(true, Ordering::SeqCst);
    within("the relay to hear the tenant is admitting again", async {
        while !usage.admitting() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let _carol = Client::connect_as(
        &relay,
        &Grant {
            user: "carol",
            ..Grant::viewer()
        }
        .token(),
    )
    .await;

    let seen = billing.seen();
    assert!(seen.iter().all(|s| s.authorization == "Bearer mqk_test"));
    assert!(
        seen.iter()
            .flat_map(Seen::records)
            .all(|r| r.get("tenant").is_none()),
        "a self-hosted relay leaves the tenant to the key"
    );
    reporter.shutdown(Duration::from_secs(5)).await;
    let _ = std::fs::remove_file(&key);
}

/// Direct time is ticket time: none before the participant asks for tickets,
/// all of it while it holds them, and none once it lets them go, while the
/// relay session it keeps as a fallback is billed throughout.
#[tokio::test]
async fn direct_time_is_metered_only_while_tickets_are_live() {
    let billing = Billing::start(Arc::new(|_, seen: &Seen| (200, accepted(seen)))).await;
    let usage = Usage::new(quick(Hosting::Cloud));
    let relay = Relay::ticketing(usage.clone(), Duration::from_millis(500));
    let reporter = usage
        .report_to(
            Endpoint::new(&billing.url, Credential::Value("operator".to_owned())).expect("url"),
        )
        .expect("enabled");

    let mut host = Client::connect_as(&relay, &Grant::default().token()).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let tickets = host
        .subscribe(&support::track(
            &["acme", "r", "room-42", "ada", support::tokens::DEVICE],
            ".direct/bob/0123456789abcdef",
        ))
        .await
        .expect("a cohost may hold tickets");
    tokio::time::sleep(Duration::from_millis(2500)).await;
    drop(tickets);

    let stopped = billing.seen().len();
    let seen = billing
        .until("three reports after the tickets stopped", |s| {
            s.len() >= stopped + 3
        })
        .await;
    let records: Vec<Value> = seen.iter().flat_map(Seen::records).collect();
    let direct: u64 = records
        .iter()
        .filter_map(|r| r["direct_seconds"].as_u64())
        .sum();
    let connected: u64 = records.iter().filter_map(|r| r["seconds"].as_u64()).sum();
    assert!((2..=3).contains(&direct), "direct {direct} of {records:?}");
    assert!(
        connected >= direct + 2,
        "the standby session is billed as well"
    );
    assert!(
        seen.last()
            .expect("a report")
            .records()
            .iter()
            .all(|r| r.get("direct_seconds").is_none()),
        "nothing direct once the tickets stop"
    );
    reporter.shutdown(Duration::from_secs(5)).await;
}
