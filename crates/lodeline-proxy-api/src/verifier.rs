//! Downstream bearer-token verifier (control-plane.md §5.1/§5.2).
//!
//! `verifier = lowercase-hex SHA-256` over the exact ASCII bearer token string
//! as sent on the wire (the value after `Bearer `, no prefix added). Proxy CLI
//! and server must both use this module so the rule cannot drift.

use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Lowercase-hex SHA-256 of the token string.
pub fn verifier_for(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

/// Constant-time check that `token` hashes to `verifier_hex`. A malformed
/// `verifier_hex` (wrong length or case) never matches.
pub fn verify(token: &str, verifier_hex: &str) -> bool {
    let computed = verifier_for(token);
    let a = computed.as_bytes();
    let b = verifier_hex.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTOR: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn fixed_vector() {
        assert_eq!(verifier_for("abc"), VECTOR);
    }

    #[test]
    fn verify_accepts_and_rejects() {
        assert!(verify("abc", VECTOR));
        assert!(!verify("abd", VECTOR));
        assert!(!verify("abc", &VECTOR.to_uppercase()));
        assert!(!verify("abc", &VECTOR[..63]));
        assert!(!verify("abc", ""));
    }
}
