//! The TXT binding record: `v=ONO0;k=ed25519;n=<serial>;g=<key>;p=<key>`.
//!
//! The record at `_onomancy.<name>` is the one trust-bearing DNS record
//! in the protocol. Its grammar is deliberately strict *within* a known
//! format tag — fixed field order, no unknown fields, canonical
//! integers, canonical padded base64 — because the record is a trust
//! root and parser leniency is attack surface. Extension happens by
//! format-tag bump (`ONO1`), never by field tolerance.
//!
//! # Wire Format
//!
//! | Field       | Type    | Width | Notes                           |
//! |-------------|---------|-------|---------------------------------|
//! | `v=ONO0`    | literal | 6B    | format tag                      |
//! | `k=ed25519` | literal | 9B    | key algorithm                   |
//! | `n=<…>`     | digits  | 2–22B | serial, ≤ 20 digits             |
//! | `g=<…>`     | base64  | 46B   | generation key, 44 chars        |
//! | `p=<…>`     | base64  | 46B   | document key, 44 chars          |
//!
//! Fields joined by single `;` — at most 133 octets total.
//!
//! # `RRset` Dispositions
//!
//! Records in an `RRset` are not merely valid-or-invalid; the spec
//! mandates three distinct dispositions, which
//! [`TxtRecord::classify`](record::TxtRecord::classify) makes
//! unrepresentable to confuse:
//!
//! ```text
//! "v=ONO0;…"        ──►  Classified::Binding(TxtRecord)   (parse strictly)
//! "v=ONO7;…"        ──►  Classified::UnknownVersion       (skip; newer software's mail)
//! "v=spf1 …" etc.   ──►  Classified::UnknownRecord        (ignore entirely)
//! "v=ONO0;<junk>"   ──►  Err(ParseTxtRecordError::…)      (reject THIS record, surfaced)
//! ```
//!
//! # Module Organization
//!
//! - [`record`] — [`TxtRecord`](record::TxtRecord), its dispositions,
//!   and its parse errors
//! - [`serial`] — the anti-replay serial (`n=`)
//! - [`generation_key`] — the attested generation key (`g=`)

pub mod generation_key;
pub mod record;
pub mod serial;
