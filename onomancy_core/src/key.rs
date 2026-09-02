//! Strict ed25519 verifying-key decoding.
//!
//! An ed25519 verifying key has exactly one canonical 32-byte
//! spelling: the compressed Edwards `y` coordinate with the sign of
//! `x` in the top bit. The raw byte space also contains alternate
//! spellings of valid points — a `y` at or above the field prime, and
//! the negative-zero encoding that RFC 8032 §5.1.3 assigns to no
//! point — which lenient decompression accepts. Accepting them lets
//! one key travel as two distinct byte strings, so every byte-keyed
//! guarantee (equality, dedup at a serial tie, digest stability)
//! reads one statement as two. Decoding is therefore strict: the
//! bytes must decompress to a point *and* be that point's own
//! re-compression.

use ed25519_dalek::VerifyingKey;

/// Decode a verifying key from its canonical compressed spelling.
///
/// # Errors
///
/// Returns [`NotCanonicalKey`] when the bytes decompress to no curve
/// point, or decompress to a point whose canonical compression is a
/// different byte string.
///
/// # Examples
///
/// ```
/// use ed25519_dalek::SigningKey;
/// use onomancy_core::key;
///
/// let verifying = SigningKey::from_bytes(&[7; 32]).verifying_key();
/// assert_eq!(key::decode(&verifying.to_bytes())?, verifying);
///
/// // The negative-zero spelling (y = 1, sign bit set) names no key.
/// let mut negative_zero = [0u8; 32];
/// negative_zero[0] = 1;
/// negative_zero[31] = 0x80;
/// assert!(key::decode(&negative_zero).is_err());
/// # Ok::<(), key::NotCanonicalKey>(())
/// ```
pub fn decode(bytes: &[u8; 32]) -> Result<VerifyingKey, NotCanonicalKey> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| NotCanonicalKey)?;

    // `VerifyingKey` retains the compressed bytes it was given; only a
    // fresh compression of the decompressed point exposes the
    // canonical spelling.
    if key.to_edwards().compress().to_bytes() != *bytes {
        return Err(NotCanonicalKey);
    }

    Ok(key)
}

/// The bytes are not the canonical encoding of an ed25519 curve point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not the canonical encoding of an ed25519 curve point")]
pub struct NotCanonicalKey;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    #[test]
    fn canonical_keys_decode_to_themselves() {
        let verifying = SigningKey::from_bytes(&[7; 32]).verifying_key();

        assert_eq!(decode(&verifying.to_bytes()).expect("canonical"), verifying);
    }

    /// RFC 8032 §5.1.3 step 4: x = 0 with the sign bit set encodes no
    /// point, though lenient decompression accepts it.
    #[test]
    fn the_negative_zero_spelling_is_rejected() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes[31] = 0x80;

        assert_eq!(decode(&bytes), Err(NotCanonicalKey));
    }

    /// A masked `y` at or above the field prime is an alternate
    /// spelling of the reduced point, not a key of its own.
    #[test]
    fn a_field_element_past_the_prime_is_rejected() {
        assert_eq!(decode(&[0xff; 32]), Err(NotCanonicalKey));
    }

    #[test]
    fn non_points_are_rejected() {
        let non_point = (0u8..=255)
            .map(|fill| [fill; 32])
            .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
            .expect("some constant fill fails decompression");

        assert_eq!(decode(&non_point), Err(NotCanonicalKey));
    }

    mod props {
        use super::*;

        /// Every generated key decodes, and every successful decode is
        /// a fixed point: the accepted bytes are the key's own
        /// canonical spelling.
        #[test]
        fn decoding_accepts_exactly_the_canonical_spellings() {
            bolero::check!().with_type::<[u8; 32]>().for_each(|bytes| {
                let generated = SigningKey::from_bytes(bytes).verifying_key();
                assert_eq!(
                    decode(&generated.to_bytes()).expect("generated keys are canonical"),
                    generated,
                );

                if let Ok(key) = decode(bytes) {
                    assert_eq!(key.to_bytes(), *bytes);
                }
            });
        }
    }
}
