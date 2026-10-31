//! Downstream bearer token generation (D-02 decision 4, control-plane.md §5.1/§5.2).
//!
//! The token is 256 bits from the OS RNG, shown once by the CLI. Only its
//! SHA-256 verifier (`lodeline_proxy_api::verifier_for`) is meant to leave the
//! proxy host; nothing secret is stored.

/// 64 lowercase hex characters (256 bits from the OS RNG).
pub fn generate_token() -> Result<String, getrandom::Error> {
    use std::fmt::Write;
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw)?;
    let t = raw.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    });
    raw.fill(0);
    Ok(t)
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
}
