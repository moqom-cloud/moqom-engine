//! `moqom cloudflare sub`: watch a broadcast on Cloudflare's draft-16 relay.
//!
//! Subscribe-only, as [`moqom_client::cloudflare`] is. The relay takes its
//! token in the setup's PATH, so the token is a value rather than a file
//! path here, and it is never printed.

use std::time::Duration;

use bytes::Bytes;
use moqom_client::cloudflare::{DEMO_HOST, DEMO_PORT, Filter, Session};
use moqom_client::{FullTrackName, Object};
use tokio::sync::mpsc;

use crate::{Fallible, namespace};

#[derive(clap::Args)]
pub struct CloudflareArgs {
    #[command(subcommand)]
    command: CloudflareCommand,
}

#[derive(clap::Subcommand)]
enum CloudflareCommand {
    /// Subscribe to tracks of a broadcast and print each object.
    Sub(SubArgs),
}

#[derive(clap::Args)]
struct SubArgs {
    /// The JWT the relay authorises against.
    ///
    /// Prefer the environment variable: a value on the command line is
    /// visible to every user of the machine for as long as this runs.
    #[arg(long, env = "MOQOM_CF_DEMO_TOKEN", hide_env_values = true)]
    token: String,
    /// Track namespace, fields separated by `/`.
    #[arg(long)]
    namespace: String,
    /// Track to subscribe to; repeat for several. moq-pub's layout is
    /// `0.mp4` for the init segment and `<track id>.m4s` for media.
    #[arg(long = "track", default_values = ["0.mp4", "1.m4s"])]
    tracks: Vec<String>,
    /// Where to start. `none` sends no filter and leaves it to the relay.
    #[arg(long, value_enum, default_value_t = Start::None)]
    filter: Start,
    /// Stop after this many objects across all tracks.
    #[arg(long)]
    count: Option<u64>,
    /// Relay host.
    #[arg(long, default_value = DEMO_HOST)]
    host: String,
    /// Relay port.
    #[arg(long, default_value_t = DEMO_PORT)]
    port: u16,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Start {
    None,
    Largest,
    Next,
}

impl Start {
    const fn filter(self) -> Option<Filter> {
        match self {
            Self::None => None,
            Self::Largest => Some(Filter::LargestObject),
            Self::Next => Some(Filter::NextGroupStart),
        }
    }
}

pub async fn run(args: CloudflareArgs) -> Fallible {
    match args.command {
        CloudflareCommand::Sub(args) => sub(args).await,
    }
}

async fn sub(args: SubArgs) -> Fallible {
    let namespace = namespace(&args.namespace)?;
    let session = Session::connect(&args.host, args.port, args.token.trim()).await?;
    eprintln!("connected to {}:{} (moqt-16)", args.host, args.port);

    let (tx, mut rx) = mpsc::channel::<(String, Event)>(64);
    for name in &args.tracks {
        let track = FullTrackName::new(namespace.clone(), Bytes::copy_from_slice(name.as_bytes()))?;
        let mut subscription = session.subscribe(track, args.filter.filter()).await?;
        eprintln!(
            "{name}: subscribed, alias {}, largest {}",
            subscription.alias,
            subscription.largest.map_or_else(
                || "unknown".to_owned(),
                |l| format!("{}/{}", l.group, l.object)
            )
        );
        let tx = tx.clone();
        let name = name.clone();
        tokio::spawn(async move {
            loop {
                let event = match subscription.next_object().await {
                    Ok(Some(object)) => Event::Object(object),
                    Ok(None) => Event::Ended(
                        subscription
                            .ended()
                            .map(|ended| format!("status {:#x} {:?}", ended.status, ended.reason)),
                    ),
                    Err(error) => Event::Failed(error.to_string()),
                };
                let last = !matches!(event, Event::Object(_));
                if tx.send((name.clone(), event)).await.is_err() || last {
                    return;
                }
            }
        });
    }
    drop(tx);

    let mut received = 0u64;
    loop {
        let (name, event) = tokio::select! {
            next = rx.recv() => match next {
                Some(next) => next,
                None => break,
            },
            _ = tokio::signal::ctrl_c() => {
                eprintln!("interrupted");
                break;
            }
            () = idle() => {
                eprintln!("nothing for 30 s");
                break;
            }
        };
        match event {
            Event::Object(object) => {
                print(&name, &object);
                received += 1;
                if args.count.is_some_and(|count| received >= count) {
                    break;
                }
            }
            Event::Ended(how) => {
                eprintln!(
                    "{name}: ended, {}",
                    how.as_deref().unwrap_or("no PUBLISH_DONE")
                );
            }
            Event::Failed(error) => eprintln!("{name}: {error}"),
        }
    }
    eprintln!("{received} objects");
    session.close();
    Ok(())
}

enum Event {
    Object(Object),
    Ended(Option<String>),
    Failed(String),
}

/// Restarted on every loop turn, so it measures the gap since the last event.
async fn idle() {
    tokio::time::sleep(Duration::from_secs(30)).await;
}

fn print(track: &str, object: &Object) {
    println!(
        "{track} group={} object={} bytes={}",
        object.group,
        object.object,
        object.payload.len()
    );
}
