//! The Onomancy agent: publisher and verifier glue over the pure
//! crates.
//!
//! ```text
//! onomancer keygen                      mint a signing key
//! onomancer bind                        first-binding ceremony → Plan
//! onomancer rotate                      generation rotation → Plan
//! onomancer migrate                     document migration → Plan
//! onomancer refresh                     keyless chain re-attach → Plan
//! onomancer record                      low-level TXT/cert emission
//! onomancer resolve                     live fetch → walk → verdict
//! ```
//!
//! Everything cryptographic happens in the libraries; this binary
//! only parses arguments, moves bytes, and prints.

// A CLI's job is printing; its errors surface through `run()`.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod bind;
mod keygen;
mod migrate;
mod plan_io;
mod record;
mod refresh;
mod resolve;
mod rotate;
mod seed;

use std::{
    io::Write as _,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::Parser;

/// The Onomancy agent.
#[derive(Debug, Parser)]
#[command(name = "onomancer", version, about)]
enum Command {
    /// Plan a first binding (ceremony: TXT + certificate).
    Bind(bind::Bind),

    /// Mint an ed25519 signing key (seed + verifying-key forms).
    Keygen(keygen::Keygen),

    /// Plan a document migration (ceremony: dual-publish + proof).
    Migrate(migrate::Migrate),

    /// Emit the DNS-publishable TXT record for a binding, and
    /// optionally a signed ONC certificate (low-level; prefer bind).
    Record(record::Record),

    /// Refresh a certificate's chain from live DNS — keyless.
    Refresh(refresh::Refresh),

    /// Fetch and validate a hostname's chain from live DNS; with a
    /// certificate, produce the full graded verdict.
    Resolve(resolve::Resolve),

    /// Plan a generation rotation (ceremony: statement + TXT + cert).
    Rotate(rotate::Rotate),
}

fn main() -> ExitCode {
    let outcome: Result<(), Box<dyn std::error::Error>> = match Command::parse() {
        Command::Bind(command) => command.run().map_err(Into::into),
        Command::Keygen(command) => command.run().map_err(Into::into),
        Command::Migrate(command) => command.run().map_err(Into::into),
        Command::Record(command) => command.run().map_err(Into::into),
        Command::Refresh(command) => command.run().map_err(Into::into),
        Command::Resolve(command) => command.run().map_err(Into::into),
        Command::Rotate(command) => command.run().map_err(Into::into),
    };

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Milliseconds since the Unix epoch — the serial convention.
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Drive one future on a scratch current-thread runtime.
pub(crate) fn block_on<F: Future>(future: F) -> Result<F::Output, std::io::Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    Ok(runtime.block_on(future))
}

/// Print one line to stdout; exit quietly when the pipe is gone
/// (`onomancer keygen | head` must not panic).
pub(crate) fn say(line: &str) {
    if let Err(failure) = writeln!(std::io::stdout(), "{line}")
        && failure.kind() == std::io::ErrorKind::BrokenPipe
    {
        std::process::exit(0);
    }
}
