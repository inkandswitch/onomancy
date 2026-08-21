//! The host chain courier: [`chain_assembly`](crate::chain_assembly) over the
//! stub resolver.

use std::net::SocketAddr;

use onomancy_core::{cert::chain::DnssecChain, name::dns::DnsName};
use onomancy_protocol::chain_provider::ChainProvider;

use crate::{
    chain_assembly::{self, AssembleError},
    stub::{QueryError, StubResolver},
};

/// The concrete error of the host courier's chain assembly.
pub type FetchChainError = AssembleError<QueryError>;

/// The host chain courier: assembles a hostname's full DNSSEC chain
/// by querying one recursive resolver over UDP/TCP.
#[derive(Debug, Clone, Copy)]
pub struct HickoryProvider {
    stub: StubResolver,
}

impl HickoryProvider {
    /// A provider querying the recursive resolver at `server`.
    #[must_use]
    pub const fn new(server: SocketAddr) -> Self {
        Self {
            stub: StubResolver::new(server),
        }
    }

    /// A provider over a pre-configured stub.
    #[must_use]
    pub const fn from_stub(stub: StubResolver) -> Self {
        Self { stub }
    }

    /// Fetch and frame the full chain for `hostname`'s `_onomancy`
    /// owner name.
    ///
    /// # Errors
    ///
    /// Returns [`FetchChainError`] for transport failures and for
    /// answers that cannot even be framed. Framability is not
    /// validity: a framed chain may still fail the validator.
    pub async fn assemble(&self, hostname: &DnsName) -> Result<DnssecChain, FetchChainError> {
        chain_assembly::assemble(&self.stub, hostname).await
    }
}

impl ChainProvider for HickoryProvider {
    type Error = FetchChainError;

    async fn chain(&self, hostname: &DnsName) -> Result<DnssecChain, FetchChainError> {
        self.assemble(hostname).await
    }
}
