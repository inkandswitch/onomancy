//! The host chain courier: the sans-IO chain builder
//! (`onomancy_chain`) driven over the stub resolver, with upstream
//! failover.

use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use onomancy_chain::builder::{BuildError, ChainBuilder, Step};
use onomancy_core::{cert::chain::DnssecChain, name::dns::DnsName};
use onomancy_protocol::chain_provider::ChainProvider;

use crate::stub::{QueryError, StubResolver};

/// The fallback of last resort when no upstream is configured or
/// discoverable.
pub const FALLBACK_UPSTREAM: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);

/// The host chain courier: fetches a hostname's full DNSSEC chain
/// by querying recursive resolvers over UDP/TCP, trying each upstream
/// in order until one yields a framable chain.
///
/// Nonempty by construction: the first upstream is a dedicated field,
/// so no runtime emptiness check exists to fail.
#[derive(Debug, Clone)]
pub struct HickoryProvider {
    first: StubResolver,
    rest: Vec<StubResolver>,
}

impl HickoryProvider {
    /// A provider querying the single recursive resolver at `server`.
    #[must_use]
    pub const fn new(server: SocketAddr) -> Self {
        Self {
            first: StubResolver::new(server),
            rest: Vec::new(),
        }
    }

    /// The system's resolvers (`/etc/resolv.conf` `nameserver` lines,
    /// port 53), with [`FALLBACK_UPSTREAM`] appended as the last
    /// resort — so the provider works even where no resolv.conf
    /// exists or none of its entries parse.
    #[must_use]
    pub fn system() -> Self {
        let mut discovered = resolv_conf_upstreams().into_iter().map(StubResolver::new);
        let fallback = StubResolver::new(FALLBACK_UPSTREAM);

        match discovered.next() {
            Some(first) => Self {
                first,
                rest: discovered.chain([fallback]).collect(),
            },
            None => Self {
                first: fallback,
                rest: Vec::new(),
            },
        }
    }

    /// Add a fallback upstream, tried after the existing ones.
    #[must_use]
    pub fn or(mut self, server: SocketAddr) -> Self {
        self.rest.push(StubResolver::new(server));
        self
    }

    /// A provider over one pre-configured stub.
    #[must_use]
    pub const fn from_stub(stub: StubResolver) -> Self {
        Self {
            first: stub,
            rest: Vec::new(),
        }
    }

    /// Fetch and frame the full chain for `hostname`'s `_onomancy`
    /// owner name, failing over across upstreams.
    ///
    /// Failover advances only on transport or framing failure: an
    /// upstream that returns framable-but-bogus records "succeeds"
    /// here and is only unmasked by the validator — framability is
    /// not validity. Callers that validate can retry with a different
    /// provider if the verdict warrants it.
    ///
    /// # Errors
    ///
    /// Returns the LAST upstream's [`FetchChainError`] when every
    /// upstream fails.
    pub async fn fetch_chain(&self, hostname: &DnsName) -> Result<DnssecChain, FetchChainError> {
        let mut last_failure = match drive(&self.first, hostname).await {
            Ok(chain) => return Ok(chain),
            Err(failure) => {
                tracing::debug!(%hostname, %failure, "upstream failed, trying next");
                failure
            }
        };

        for upstream in &self.rest {
            match drive(upstream, hostname).await {
                Ok(chain) => return Ok(chain),
                Err(failure) => {
                    tracing::debug!(%hostname, %failure, "upstream failed, trying next");
                    last_failure = failure;
                }
            }
        }

        Err(last_failure)
    }
}

impl ChainProvider for HickoryProvider {
    type Error = FetchChainError;

    async fn chain(&self, hostname: &DnsName) -> Result<DnssecChain, FetchChainError> {
        self.fetch_chain(hostname).await
    }
}

/// The host courier failed to fetch a chain — in the machine or on
/// the wire, never a validity verdict (that is the validator's).
#[derive(Debug, thiserror::Error)]
pub enum FetchChainError {
    /// The answers could not be framed into a chain.
    #[error(transparent)]
    Build(#[from] BuildError),

    /// A query failed at the transport level.
    #[error(transparent)]
    Transport(#[from] QueryError),
}

/// Drive the sans-IO chain builder against one upstream: answer
/// each question over the socket until the chain is framed.
async fn drive(
    upstream: &StubResolver,
    hostname: &DnsName,
) -> Result<DnssecChain, FetchChainError> {
    let (mut builder, mut question) = ChainBuilder::start(hostname)?;

    loop {
        let records = upstream.query(&question).await?;

        match builder.answer(records)? {
            Step::Ask(next, asked) => {
                builder = next;
                question = asked;
            }
            Step::Done(chain) => return Ok(chain),
        }
    }
}

/// The `nameserver` entries of `/etc/resolv.conf`, in file order.
/// Unreadable files and unparsable entries (e.g. scoped IPv6) yield
/// nothing — discovery degrades, never errors.
fn resolv_conf_upstreams() -> Vec<SocketAddr> {
    let Ok(text) = fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };

    text.lines()
        .filter_map(|line| line.strip_prefix("nameserver"))
        .filter(|rest| rest.starts_with(char::is_whitespace))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(|address| address.parse::<IpAddr>().ok())
        .map(|address| SocketAddr::new(address, 53))
        .collect()
}
