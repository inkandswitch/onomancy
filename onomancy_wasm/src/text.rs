//! A string argument that is `string` to TypeScript and unchecked to
//! Rust.
//!
//! `&str` parameters are not an option at this boundary: wasm-bindgen's
//! generated glue for `&str` faults *inside* the module on a non-string
//! argument, surfacing as `RuntimeError: memory access out of bounds`
//! rather than a catchable error. Taking `&JsValue` fixes the fault but
//! costs the declaration its type, widening the published signature to
//! `any` — which stops TypeScript from rejecting a number at compile
//! time, on exactly the arguments a caller is most likely to get wrong.
//!
//! Neither horn is necessary. [`typescript_type`] pins the declared
//! type while leaving the value unchecked, so the `.d.ts` says `string`
//! and the implementation still tests rather than trusts.
//!
//! [`typescript_type`]: https://rustwasm.github.io/wasm-bindgen/reference/attributes/on-rust-exports/typescript_type.html

use wasm_bindgen::{JsCast as _, prelude::*};

#[wasm_bindgen]
extern "C" {
    /// A string argument: `string` in the published declaration,
    /// unchecked on arrival.
    #[wasm_bindgen(typescript_type = "string")]
    pub type Text;
}

/// Read the argument as a `String`, or say what was wrong with it.
///
/// `noun` names what was expected, so the message can be specific
/// without each caller rewriting it: a caller who lands here passed
/// the wrong thing and needs to know what the right thing is.
///
/// # Errors
///
/// Returns a plain JS error when the argument is not a string.
pub fn read(value: &Text, noun: &str) -> Result<String, JsError> {
    value
        .unchecked_ref::<JsValue>()
        .as_string()
        .ok_or_else(|| JsError::new(&format!("{noun} must be a string")))
}
