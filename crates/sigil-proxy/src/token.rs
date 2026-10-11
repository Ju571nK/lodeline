//! Downstream bearer token generation (D-02 decision 4, control-plane.md §5.1/§5.2).
//!
//! The token is 256 bits from the OS RNG, shown once by the CLI. Only its
//! SHA-256 verifier is meant to leave the proxy host; nothing secret is stored.

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

/// 64 lowercase hex characters (256 bits from the OS RNG).
pub fn generate_token() -> Result<String, getrandom::Error> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw)?;
    let t = hex(&raw);
    raw.fill(0);
    Ok(t)
}

// OPEN: the contract says "SHA-256 of the 256-bit token" without fixing the
// input encoding. The verifier here is SHA-256 over the ASCII bearer string
// exactly as a client sends it (64 hex chars), so the proxy can verify without
// decoding. T-11/T-12 must use the same rule.
pub fn verifier(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_256_bit_hex_and_unique() {
        let a = generate_token().unwrap();
        let b = generate_token().unwrap();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));
        assert_ne!(a, b);
    }

    #[test]
    fn verifier_is_sha256_hex() {
        // SHA-256("abc") test vector
        assert_eq!(
            verifier("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
