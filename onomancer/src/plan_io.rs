//! Plan presentation and the printing executor.

use std::path::Path;

use onomancy_publish::{
    plan::{DnsOp, Plan, Postcondition},
    zone_editor::ZoneEditor,
};

use crate::say;

/// The printing executor: "applying" an op means telling the human
/// what to put in their zone. The trivial [`ZoneEditor`]; provider
/// adapters slot in behind the same seam later.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PrintEditor;

impl ZoneEditor for PrintEditor {
    type Error = core::convert::Infallible;

    async fn apply(&mut self, op: &DnsOp) -> Result<(), Self::Error> {
        let (verb, hostname, record) = match op {
            DnsOp::PublishTxt { hostname, record } => ("publish", hostname, record),
            DnsOp::RetainTxt { hostname, record } => ("RETAIN (dual-publish)", hostname, record),
            DnsOp::RetireTxt { hostname, record } => {
                ("retire (after the migration window)", hostname, record)
            }
        };
        say(&format!("; {verb}:"));
        say(&format!("_onomancy.{hostname}. IN TXT \"{record}\""));
        Ok(())
    }
}

/// Print the whole plan and write its artifacts under `out_dir`.
pub(crate) async fn execute(plan: &Plan, out_dir: &Path) -> Result<(), std::io::Error> {
    say("; == zone operations (apply these, then re-sign the zone) ==");
    let mut editor = PrintEditor;
    for op in &plan.dns_ops {
        // Infallible: the printing executor cannot refuse an op.
        match editor.apply(op).await {
            Ok(()) => (),
        }
    }
    if plan.dns_ops.is_empty() {
        say("; (none — this ceremony never touches DNS)");
    }

    say("; == artifacts (serve at the designated endpoint / gossip) ==");
    for artifact in &plan.artifacts {
        let path = out_dir.join(&artifact.name);
        std::fs::write(&path, &artifact.bytes)?;
        say(&format!(
            "; wrote {:?} artifact: {}",
            artifact.kind,
            path.display()
        ));
    }

    say("; == postconditions (check with `onomancer resolve` / `watch`) ==");
    for postcondition in &plan.postconditions {
        match postcondition {
            Postcondition::VerifiesFresh(fresh) => say(&format!(
                "; {} verifies fresh ✓ → document {} generation g={}",
                fresh.hostname,
                fresh.document,
                base64_key(fresh.generation.verifying_key().as_bytes()),
            )),
            Postcondition::EffectiveSerialAtLeast { hostname, serial } => {
                say(&format!("; {hostname} effective serial ≥ {serial}"));
            }
        }
    }
    Ok(())
}

/// The TXT `g=` spelling of a key.
pub(crate) fn base64_key(bytes: &[u8; 32]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Parse the TXT `g=` spelling back into 32 key bytes.
pub(crate) fn parse_base64_key(text: &str) -> Option<[u8; 32]> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .ok()?;
    bytes.as_slice().try_into().ok()
}
