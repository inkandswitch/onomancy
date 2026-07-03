//! Names as a validated domain type.
//!
//! Following "Parse, Don't Validate": construct a [`Name`] once at the
//! boundary and carry the proof of well-formedness in the type.

use alloc::string::String;
use core::fmt;

/// A non-empty, trimmed name.
///
/// # Examples
///
/// ```
/// use onomancer_core::name::Name;
///
/// let name = Name::parse("  Ada  ").expect("non-empty name");
/// assert_eq!(name.as_str(), "Ada");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Name(String);

impl Name {
    /// Parse a raw string into a [`Name`], trimming surrounding whitespace.
    ///
    /// # Errors
    ///
    /// Returns [`EmptyNameError`] if the trimmed input is empty.
    pub fn parse(raw: &str) -> Result<Self, EmptyNameError> {
        let trimmed = raw.trim();

        if trimmed.is_empty() {
            return Err(EmptyNameError);
        }

        Ok(Self(String::from(trimmed)))
    }

    /// View the name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The input was empty (or whitespace-only) after trimming.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("name must be non-empty after trimming whitespace")]
pub struct EmptyNameError;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_whitespace_only() {
        assert_eq!(Name::parse("   "), Err(EmptyNameError));
    }

    #[test]
    fn parse_is_idempotent_on_trimmed_input() {
        bolero::check!().with_type::<String>().for_each(|raw| {
            if let Ok(name) = Name::parse(raw) {
                let reparsed = Name::parse(name.as_str()).expect("already trimmed & non-empty");
                assert_eq!(name, reparsed);
            }
        });
    }
}
