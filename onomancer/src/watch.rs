//! `onomancer watch`: the stateful pass on an interval.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use clap::Args;
use onomancy_dnssec::dns_name::DnsName;

use crate::{
    resolve::{ResolveError, stateful_pass},
    say,
};

/// Re-judge a hostname's evidence periodically, surfacing changes as
/// they happen. Errors are reported and the loop continues — a flaky
/// resolver must not kill the watcher.
#[derive(Debug, Args)]
pub(crate) struct Watch {
    /// The hostname to watch (display form accepted).
    #[arg(long)]
    hostname: String,

    /// The store directory (created if missing).
    #[arg(long)]
    store: PathBuf,

    /// Recursive resolver (default: system resolvers, then 1.1.1.1).
    #[arg(long)]
    resolver: Option<SocketAddr>,

    /// Seconds between passes.
    #[arg(long, default_value_t = 300)]
    interval: u64,

    /// Stop after this many passes (default: forever).
    #[arg(long)]
    passes: Option<u64>,
}

impl Watch {
    /// Run passes until interrupted (or `--passes` is exhausted).
    ///
    /// # Errors
    ///
    /// Returns [`ResolveError`] only for a malformed hostname —
    /// per-pass failures are printed, not fatal.
    pub(crate) fn run(&self) -> Result<(), ResolveError> {
        let hostname = DnsName::parse_display(&self.hostname)?;
        let mut remaining = self.passes;

        loop {
            if let Err(failure) = stateful_pass(self.resolver, &self.store, &hostname, None, &[]) {
                say(&format!("pass failed: {failure}"));
            }

            match &mut remaining {
                Some(0 | 1) => return Ok(()),
                Some(count) => *count -= 1,
                None => (),
            }

            std::thread::sleep(Duration::from_secs(self.interval));
        }
    }
}
