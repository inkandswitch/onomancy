//! The host chain courier: the sans-IO assembly machine
//! (`onomancy_chain`) driven over the stub resolver, with upstream
//! failover.

use std::net::{IpAddr, SocketAddr};

use onomancy_chain::assembly::{AssembleError, Assembly, Step};
use onomancy_core::{cert::chain::DnssecChain, name::dns::DnsName};
use onomancy_protocol::chain_provider::ChainProvider;

use crate::stub::{QueryError, StubResolver};

/// The fallback of last resort when no upstream is configured or
/// discoverable.
pub const FALLBACK_UPSTREAM: SocketAddr =
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)), 53);

/// The host chain courier: assembles a hostname's full DNSSEC chain
/// by querying recursive resolvers over UDP/TCP, trying each upstream
/// in order until one yields a framable chain.
///
/// Nonempty by construction: every constructor guarantees at least
/// one upstream.
#[derive(Debug, Clone)]
pub struct HickoryProvider {
    upstreams: Vec<StubResolver>,
}

impl HickoryProvider {
    /// A provider querying the single recursive resolver at `server`.
    #[must_use]
    pub fn new(server: SocketAddr) -> Self {
        Self {
            upstreams: vec![StubResolver::new(server)],
        }
    }

    /// The system's resolvers (`/etc/resolv.conf` `nameserver` lines,
    /// port 53), with [`FALLBACK_UPSTREAM`] appended as the last
    /// resort — so the provider works even where no resolv.conf
    /// exists or none of its entries parse.
    #[must_use]
    pub fn system() -> Self {
        let mut servers = resolv_conf_upstreams();
        servers.push(FALLBACK_UPSTREAM);

        Self {
            upstreams: servers.into_iter().map(StubResolver::new).collect(),
        }
    }

    /// Add a fallback upstream, tried after the existing ones.
    #[must_use]
    pub fn or(mut self, server: SocketAddr) -> Self {
        self.upstreams.push(StubResolver::new(server));
        self
    }

    /// A provider over one pre-configured stub.
    #[must_use]
    pub fn from_stub(stub: StubResolver) -> Self {
        Self {
            upstreams: vec![stub],
        }
    }

    /// Fetch and frame the full chain for `hostname`'s `_onomancy`
    /// owner name, failing over across upstreams.
    ///
    /// # Errors
    ///
    /// Returns the LAST upstream's [`FetchChainError`] when every
    /// upstream fails. Framability is not validity: a framed chain
    /// may still fail the validator.
    ///
    /// # Panics
    ///
    /// Never: constructors guarantee at least one upstream.
    pub async fn assemble(&self, hostname: &DnsName) -> Result<DnssecChain, FetchChainError> {
        let mut last_failure: Option<FetchChainError> = None;

        for upstream in &self.upstreams {
            match drive(upstream, hostname).await {
                Ok(chain) => return Ok(chain),
                Err(failure) => {
                    tracing::debug!(%hostname, %failure, "upstream failed, trying next");
                    last_failure = Some(failure);
                }
            }
        }

        match last_failure {
            Some(failure) => Err(failure),
            None => unreachable!("constructors guarantee at least one upstream"),
        }
    }
}

impl ChainProvider for HickoryProvider {
    type Error = FetchChainError;

    async fn chain(&self, hostname: &DnsName) -> Result<DnssecChain, FetchChainError> {
        self.assemble(hostname).await
    }
}

/// Drive the sans-IO assembly machine against one upstream: answer
/// each question over the socket until the chain is framed.
async fn drive(
    upstream: &StubResolver,
    hostname: &DnsName,
) -> Result<DnssecChain, FetchChainError> {
    let (mut assembly, mut question) = Assembly::start(hostname)?;

    loop {
        let records = upstream.query(&question).await?;

        match assembly.answer(records)? {
            Step::Ask(next, asked) => {
                assembly = next;
                question = asked;
            }
            Step::Done(chain) => return Ok(chain),
        }
    }
}

/// The host courier failed to fetch a chain — in the machine or on
/// the wire, never a validity verdict (that is the validator's).
#[derive(Debug, thiserror::Error)]
pub enum FetchChainError {
    /// The answers could not be framed into a chain.
    #[error(transparent)]
    Assemble(#[from] AssembleError),

    /// A query failed at the transport level.
    #[error(transparent)]
    Query(#[from] QueryError),
}

/// The `nameserver` entries of `/etc/resolv.conf`, in file order.
/// Unreadable files and unparseable entries (e.g. scoped IPv6) yield
/// nothing — discovery degrades, never errors.
fn resolv_conf_upstreams() -> Vec<SocketAddr> {
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };

    text.lines()
        .filter_map(|line| line.strip_prefix("nameserver"))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(|address| address.parse::<IpAddr>().ok())
        .map(|address| SocketAddr::new(address, 53))
        .collect()
}
