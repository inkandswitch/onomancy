//! The declared shapes of what this module returns.
//!
//! These exist because a returned `JsValue` publishes as `any`, and
//! `any` states nothing: it neither lists a union's members nor warns
//! that one is missing. A downstream consumer then has no readable
//! contract at all, and the only statement of the truth is the
//! implementation — which is exactly the position that lets a wrong
//! description circulate unchallenged.
//!
//! Rust doc comments do *not* close this: `///` on an exported
//! function reaches the `.d.ts`, but an intra-doc link like
//! ``[`verdict_object`]`` does not resolve there, so a shape
//! documented by reference arrives as a dangling name.
//!
//! [`typescript_custom_section`] emits declarations verbatim into the
//! published `.d.ts`, so the union members ship with the package and
//! a `switch` over them can be checked by the consumer's compiler.
//!
//! [`typescript_custom_section`]: https://rustwasm.github.io/wasm-bindgen/reference/attributes/on-rust-exports/typescript_custom_section.html

use wasm_bindgen::prelude::*;

/// The declarations, verbatim, from the sibling `shapes.d.ts`.
///
/// Kept in a real `.d.ts` rather than a Rust string literal so it is
/// edited as TypeScript, and so the emitted section and the drift
/// test read one source rather than two copies that agree by habit.
// Const-inlined into the linker section on wasm and read by the drift
// test on host, so it is used on both and named on neither.
#[allow(dead_code)]
pub(crate) const TYPES: &str = include_str!("shapes.d.ts");

#[wasm_bindgen(typescript_custom_section)]
const SECTION: &'static str = TYPES;

#[wasm_bindgen]
extern "C" {
    /// A [`Verdict`](https://docs.rs/onomancy_protocol) as published
    /// to TypeScript.
    #[wasm_bindgen(typescript_type = "Verdict")]
    pub type JsVerdict;

    /// A live DNSSEC walk's result, as published to TypeScript.
    #[wasm_bindgen(typescript_type = "Resolution")]
    pub type JsResolution;

    /// A resolution walk's outcome, as published to TypeScript.
    #[wasm_bindgen(typescript_type = "WalkOutcome")]
    pub type JsWalkOutcome;
}
