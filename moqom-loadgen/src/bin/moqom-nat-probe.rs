//! Says whether a direct path can open from the network it runs on.
//!
//! A direct path needs the NAT in front of a device to keep one public port for
//! one socket, whoever it sends to (endpoint-independent mapping). Then the
//! address a STUN server reports is the address a peer can reach, and both
//! sides' probes meet. A symmetric NAT hands out a new port per destination, so
//! the reported address is useless to anyone else and the call stays on the
//! relay.
//!
//! One socket per address family asks every STUN server given at once. The
//! same public address from all of them means hole-punching can work; different
//! ports mean it can't. That takes servers on at least two different IP
//! addresses: two MOQOM relay regions, or any two public STUN servers.
//!
//! Run it on each network the field test covers and paste the line it prints
//! into the results table in `docs/FIELD-TEST-DIRECT.md` in the moqom repository.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use moqom_client::direct::stun;

#[derive(Parser)]
#[command(
    name = "moqom-nat-probe",
    about = "Whether a direct path can open from this network"
)]
struct Args {
    /// A STUN server as host:port. Give at least two on different addresses,
    /// for example two relay regions on port 3478.
    #[arg(long = "stun", required = true)]
    servers: Vec<String>,

    /// What this network is, for the results table ("home wifi, Comcast").
    #[arg(long, default_value = "unlabelled")]
    label: String,

    /// How long to wait for the servers, in milliseconds.
    #[arg(long, default_value_t = 3000)]
    patience_ms: u64,
}

/// What one address family's answers say about the NAT.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// No server answered, so UDP is blocked or the family has no route.
    NoAnswer,
    /// Only one server answered, so mapping can't be told apart.
    OneAnswer,
    /// The same public address from every server: hole-punching can work.
    Punchable,
    /// A different public port per server: direct paths stay on the relay.
    Symmetric,
}

impl Verdict {
    fn describe(&self) -> &'static str {
        match self {
            Self::NoAnswer => "no answer (UDP blocked, or no route in this family)",
            Self::OneAnswer => "one answer only (give a second server on another address)",
            Self::Punchable => "endpoint-independent mapping: hole-punching can work",
            Self::Symmetric => "symmetric NAT: direct paths stay on the relay",
        }
    }
}

fn judge(answers: &[Option<SocketAddr>]) -> Verdict {
    let reported: BTreeSet<SocketAddr> = answers.iter().flatten().copied().collect();
    match answers.iter().flatten().count() {
        0 => Verdict::NoAnswer,
        _ if reported.len() > 1 => Verdict::Symmetric,
        1 => Verdict::OneAnswer,
        _ => Verdict::Punchable,
    }
}

fn resolve(servers: &[String]) -> (Vec<SocketAddr>, Vec<SocketAddr>) {
    let mut v4 = BTreeSet::new();
    let mut v6 = BTreeSet::new();
    for server in servers {
        match server.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    if addr.is_ipv4() {
                        v4.insert(addr);
                    } else {
                        v6.insert(addr);
                    }
                }
            }
            Err(error) => eprintln!("{server}: {error}"),
        }
    }
    (v4.into_iter().collect(), v6.into_iter().collect())
}

fn probe(bind: IpAddr, servers: &[SocketAddr], patience: Duration) -> (Verdict, String) {
    if servers.is_empty() {
        return (Verdict::NoAnswer, "no servers in this family".into());
    }
    let socket = match UdpSocket::bind(SocketAddr::new(bind, 0)) {
        Ok(socket) => socket,
        Err(error) => return (Verdict::NoAnswer, format!("can't bind: {error}")),
    };
    let answers = match stun::reflexive_each(&socket, servers, patience) {
        Ok(answers) => answers,
        Err(error) => return (Verdict::NoAnswer, format!("socket error: {error}")),
    };
    let detail = servers
        .iter()
        .zip(&answers)
        .map(|(server, answer)| match answer {
            Some(mapped) => format!("{server} saw {mapped}"),
            None => format!("{server} silent"),
        })
        .collect::<Vec<_>>()
        .join("; ");
    (judge(&answers), detail)
}

fn main() -> ExitCode {
    let args = Args::parse();
    let patience = Duration::from_millis(args.patience_ms);
    let (v4, v6) = resolve(&args.servers);

    let (verdict_v4, detail_v4) = probe(IpAddr::V4(Ipv4Addr::UNSPECIFIED), &v4, patience);
    let (verdict_v6, detail_v6) = probe(IpAddr::V6(Ipv6Addr::UNSPECIFIED), &v6, patience);

    println!("IPv4: {} ({detail_v4})", verdict_v4.describe());
    println!("IPv6: {} ({detail_v6})", verdict_v6.describe());
    println!();
    println!("Results table row:");
    println!(
        "| {} | {} | {} |",
        args.label,
        verdict_v4.describe(),
        verdict_v6.describe()
    );

    if matches!(verdict_v4, Verdict::NoAnswer) && matches!(verdict_v6, Verdict::NoAnswer) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn the_same_mapping_from_every_server_is_punchable() {
        let mapped = Some(addr("203.0.113.7:40000"));
        assert_eq!(judge(&[mapped, mapped]), Verdict::Punchable);
    }

    #[test]
    fn a_new_port_per_server_is_symmetric() {
        let answers = [
            Some(addr("203.0.113.7:40000")),
            Some(addr("203.0.113.7:40001")),
        ];
        assert_eq!(judge(&answers), Verdict::Symmetric);
    }

    #[test]
    fn silence_and_a_single_answer_say_so() {
        assert_eq!(judge(&[None, None]), Verdict::NoAnswer);
        assert_eq!(
            judge(&[Some(addr("203.0.113.7:40000")), None]),
            Verdict::OneAnswer
        );
    }
}
