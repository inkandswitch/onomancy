//! The Onomancy agent: publisher and verifier glue over the pure
//! crates.
//!
//! ```text
//! onomancer keygen                      mint a signing key
//! onomancer record  --hostname … --doc-seed … --generation-seed …
//!                                       the DNS-publishable TXT record
//!                                       (+ optionally a signed ONC cert)
//! onomancer resolve --hostname …        live chain fetch → DNSSEC walk
//!                    [--cert …]         (+ full graded verdict for a cert)
//! ```
//!
//! Everything cryptographic happens in the libraries; this binary
//! only parses arguments, moves bytes, and prints.

// A CLI's job is printing; its errors surface through `run()`.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod keygen;
mod record;
mod resolve;
mod seed;

use std::process::ExitCode;

use clap::Parser;

/// The Onomancy agent.
#[derive(Debug, Parser)]
#[command(name = "onomancer", version, about)]
enum Command {
    /// Mint an ed25519 signing key (seed + verifying-key forms).
    Keygen(keygen::Keygen),

    /// Emit the DNS-publishable TXT record for a binding, and
    /// optionally a signed ONC certificate.
    Record(record::Record),

    /// Fetch and validate a hostname's chain from live DNS; with a
    /// certificate, produce the full graded verdict.
    Resolve(resolve::Resolve),
}

fn main() -> ExitCode {
    let outcome: Result<(), Box<dyn std::error::Error>> = match Command::parse() {
        Command::Keygen(command) => command.run().map_err(Into::into),
        Command::Record(command) => command.run().map_err(Into::into),
        Command::Resolve(command) => command.run().map_err(Into::into),
    };

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
