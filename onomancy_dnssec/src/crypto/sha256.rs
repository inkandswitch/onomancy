//! The SHA-256 hash-algorithm marker.

use onomancy_core::digest::HashAlgorithm;

/// SHA-256: DNS's mandated DS digest hash (digest type 2), never
/// ours — onomancy's own addressing is BLAKE3.
pub struct Sha256;

impl HashAlgorithm for Sha256 {
    fn hash(input: &[u8]) -> [u8; 32] {
        use sha2::Digest as _;
        sha2::Sha256::digest(input).into()
    }
}
