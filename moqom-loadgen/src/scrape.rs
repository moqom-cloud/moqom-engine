//! Reading the relay's own account of a run.
//!
//! A load generator that reports only what its own subscribers saw cannot tell a
//! relay that delivered everything from one that delivered to most people and
//! gave up on the rest, because the subscribers it gave up on are exactly the
//! ones whose numbers went missing. The relay counts what it did, so the two
//! views together say more than either: one measures arrival, the other measures
//! intent.
//!
//! HTTP by hand rather than through a client library. The surface is one GET
//! against a listener the relay serves with no framework, the response is text,
//! and a dependency whose changelog has to be followed is a poor trade for
//! forty lines. Written to be obviously insufficient for anything else: no
//! redirects, no chunked bodies, no TLS.

use std::collections::HashMap;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// How long to wait for a scrape before giving up on it.
///
/// A scrape competes for the relay's CPU with the load being applied to it, which
/// is the whole point of taking one, so this is generous. A run that fails
/// because a reading was slow would be a harness reporting on itself.
const PATIENCE: Duration = Duration::from_secs(10);

/// One reading of the relay's metrics.
///
/// Kept as the parsed numbers rather than the text, because every use is a
/// difference between two readings and subtracting text is not a thing.
pub struct Reading {
    values: HashMap<String, f64>,
}

impl Reading {
    /// Scrape `/metrics` from a relay's admin listener at `addr`.
    ///
    /// # Errors
    /// The listener refusing a connection, which usually means
    /// `MOQOM_RELAY_ADMIN_ADDR` was not set on the relay, or a response this
    /// deliberately simple reader cannot follow.
    pub async fn take(addr: &str) -> Result<Self, Error> {
        let body = tokio::time::timeout(PATIENCE, fetch(addr))
            .await
            .map_err(|_| Error::TimedOut)??;
        Ok(Self::parse(&body))
    }

    /// A reading made up of the series given, for testing the checks that read
    /// one without needing a relay to have emitted it.
    #[cfg(test)]
    pub fn of(series: &[(&str, f64)]) -> Self {
        Self {
            values: series
                .iter()
                .map(|(name, value)| ((*name).to_owned(), *value))
                .collect(),
        }
    }

    /// Read an exposition that has already been fetched.
    fn parse(body: &str) -> Self {
        let mut values = HashMap::new();
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // `name{labels} value`, and the labels are kept in the key rather
            // than parsed: a caller asking for a labelled series knows the label
            // it wants, and a map keyed by the whole series name means no
            // structure to get wrong.
            let Some((series, value)) = line.rsplit_once(' ') else {
                continue;
            };
            if let Ok(value) = value.parse::<f64>() {
                values.insert(series.to_owned(), value);
            }
        }
        Self { values }
    }

    /// One series, or zero if the relay has not emitted it.
    ///
    /// Absent reads as zero because a counter is only emitted once it has been
    /// touched, so "no such series" and "nothing happened" are the same claim
    /// about a relay that has just started.
    #[must_use]
    pub fn get(&self, series: &str) -> f64 {
        self.values.get(series).copied().unwrap_or(0.0)
    }

    /// How much `series` grew between this reading and a later one.
    ///
    /// Saturating at zero, because a counter that appears to have gone backwards
    /// means the relay restarted mid-run, and a negative delta reported as a rate
    /// would be a stranger thing to read than a zero.
    #[must_use]
    pub fn growth(&self, later: &Self, series: &str) -> f64 {
        (later.get(series) - self.get(series)).max(0.0)
    }
}

/// GET `/metrics` and return the body.
async fn fetch(addr: &str) -> Result<String, Error> {
    let mut stream = TcpStream::connect(addr).await?;
    let request = format!("GET /metrics HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;

    // HTTP/1.0 with `Connection: close`, so the body ends when the socket does
    // and there is no length header to honour and no chunking to decode.
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;

    let Some((head, body)) = response.split_once("\r\n\r\n") else {
        return Err(Error::Unreadable);
    };
    let status = head.lines().next().unwrap_or_default();
    if !status.contains("200") {
        return Err(Error::Status(status.to_owned()));
    }
    Ok(body.to_owned())
}

/// Why a scrape did not produce a reading.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not reach the relay's admin listener: {0}")]
    Unreachable(#[from] std::io::Error),
    #[error("the relay's admin listener did not answer within {}s", PATIENCE.as_secs())]
    TimedOut,
    #[error("the relay's admin listener sent something this cannot read")]
    Unreadable,
    #[error("the relay's admin listener refused the scrape: {0}")]
    Status(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counter values are small integers that arrived as text, so they are exact
    /// in an `f64` and a tolerance here is only to satisfy the lint that is right
    /// about floats in general.
    fn same(left: f64, right: f64) -> bool {
        (left - right).abs() < 0.000_001
    }

    const EXPOSITION: &str = "\
# HELP moqom_relay_sessions Sessions currently connected.
# TYPE moqom_relay_sessions gauge
moqom_relay_sessions 12
moqom_relay_subgroups_shed_total 0
moqom_relay_subscriptions_total{outcome=\"established\"} 1
moqom_relay_subscriptions_total{outcome=\"shared\"} 99
moqom_relay_egress_bytes_total 4096
";

    #[test]
    fn comments_are_skipped_and_labels_stay_in_the_key() {
        let reading = Reading::parse(EXPOSITION);
        assert!(same(reading.get("moqom_relay_sessions"), 12.0));
        assert!(same(
            reading.get("moqom_relay_subscriptions_total{outcome=\"shared\"}"),
            99.0
        ));
    }

    /// A counter the relay has never touched is not in the exposition at all, and
    /// that has to read as nothing having happened.
    #[test]
    fn a_series_the_relay_never_emitted_reads_as_zero() {
        let reading = Reading::parse(EXPOSITION);
        assert!(same(reading.get("moqom_relay_fanout_failures_total"), 0.0));
    }

    #[test]
    fn growth_is_the_difference_between_two_readings() {
        let before = Reading::parse(EXPOSITION);
        let after = Reading::parse("moqom_relay_egress_bytes_total 10240\n");
        assert!(same(
            before.growth(&after, "moqom_relay_egress_bytes_total"),
            6144.0
        ));
    }

    /// A relay that restarted mid-run resets its counters, and the honest report
    /// of that is zero rather than a negative rate.
    #[test]
    fn a_counter_that_went_backwards_does_not_grow_negatively() {
        let before = Reading::parse("moqom_relay_egress_bytes_total 10240\n");
        let after = Reading::parse("moqom_relay_egress_bytes_total 8\n");
        assert!(same(
            before.growth(&after, "moqom_relay_egress_bytes_total"),
            0.0
        ));
    }
}
