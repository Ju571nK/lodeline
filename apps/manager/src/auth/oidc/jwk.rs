//! go-jose v4.1.4's `JSONWebKey.UnmarshalJSON` for one key set member, which decides whether
//! go-oidc keeps the key, skips it, or refuses the whole set. go-jose's JSON decoder matches
//! member names exactly and fails on a repeated one.

use std::collections::{HashMap, HashSet};

use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use x509_parser::oid_registry::{
    Oid, OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_SIG_ED25519,
};
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

use super::{string, strings};
use crate::auth::{go_base64, Members};
use crate::config;

/// The public key a member describes, to compare with its certificate's.
enum Public {
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    /// The curve's OID and the uncompressed point.
    Ec(Oid<'static>, Vec<u8>),
    Ed25519([u8; 32]),
}

/// `None` refuses the set, `Some(false)` skips the key (a type go-jose does not know, or an OKP
/// curve other than Ed25519), and `Some(true)` keeps it.
///
/// Stricter than go-jose, on members no published key set holds: private key members (`d`) of
/// RSA, EC and Ed25519 keys, and P-521 keys, whose point this port cannot check, fail the set.
pub(super) fn check(raw: &RawValue) -> Option<bool> {
    let members: Option<Members<Box<RawValue>>> = serde_json::from_str(raw.get()).ok()?;
    let members = members.map_or_else(Vec::new, |m| m.0);
    let mut seen = HashSet::new();
    let [mut kty, mut crv, mut x5u, mut x5t, mut x5t256, mut unused] = Default::default();
    let mut buffers: HashMap<&str, Vec<u8>> = HashMap::new();
    let mut x5c = Vec::new();
    for (key, value) in &members {
        if !seen.insert(key.as_str()) {
            return None;
        }
        match key.as_str() {
            "kty" => string(&mut kty, value)?,
            "crv" => string(&mut crv, value)?,
            "x5u" => string(&mut x5u, value)?,
            "x5t" => string(&mut x5t, value)?,
            "x5t#S256" => string(&mut x5t256, value)?,
            "use" | "kid" | "alg" => string(&mut unused, value)?,
            "x5c" => x5c = strings(value)?,
            name @ ("k" | "x" | "y" | "n" | "e" | "d" | "p" | "q" | "dp" | "dq" | "qi") => {
                // null leaves the member unset; "" sets it empty.
                if let Some(text) = serde_json::from_str::<Option<String>>(value.get()).ok()? {
                    buffers.insert(name, go_base64(&text, true)?);
                }
            }
            _ => {}
        }
    }
    let certs: Vec<Vec<u8>> = x5c
        .iter()
        .map(|c| go_base64(c, false))
        .collect::<Option<_>>()?;
    let mut leaf = None;
    for der in &certs {
        let (rest, cert) = X509Certificate::from_der(der).ok()?;
        if !rest.is_empty() {
            return None;
        }
        leaf.get_or_insert(cert);
    }

    let buffer = |name| buffers.get(name).cloned();
    let private = buffers.contains_key("d");
    let public = match (kty.as_str(), crv.as_str()) {
        ("RSA" | "EC" | "OKP", _) if private && (kty != "OKP" || crv == "Ed25519") => return None,
        ("RSA", _) => Some(Public::Rsa {
            n: buffer("n")?,
            e: buffer("e")?,
        }),
        ("EC", "P-256" | "P-384") => {
            let (size, oid) = if crv == "P-256" {
                (32, OID_EC_P256)
            } else {
                (48, OID_NIST_EC_P384)
            };
            let (x, y) = (buffer("x")?, buffer("y")?);
            if x.len() != size || y.len() != size {
                return None;
            }
            let point = [&[4][..], &x, &y].concat();
            let on_curve = if size == 32 {
                p256::PublicKey::from_sec1_bytes(&point).is_ok()
            } else {
                p384::PublicKey::from_sec1_bytes(&point).is_ok()
            };
            if !on_curve {
                return None;
            }
            Some(Public::Ec(oid, point))
        }
        ("EC", _) => return None,
        ("oct", _) if !certs.is_empty() || !buffers.contains_key("k") => return None,
        ("oct", _) => None,
        ("OKP", "Ed25519") => {
            // go-jose copies `x` into 32 bytes, padding or cutting it.
            let x = buffer("x")?;
            let mut key = [0; 32];
            let len = x.len().min(32);
            key[..len].copy_from_slice(&x[..len]);
            Some(Public::Ed25519(key))
        }
        ("", _) => return None,
        _ => return Some(false),
    };

    if let (Some(cert), Some(public)) = (&leaf, &public) {
        if !same_key(cert, public) {
            return None;
        }
    }
    if !x5u.is_empty() && config::go_url(&x5u).is_none() {
        return None;
    }
    let sha1 = thumbprint(&x5t, 20)?;
    let sha256 = thumbprint(&x5t256, 32)?;
    if let Some(der) = certs.first() {
        let sha1_ok = sha1.is_empty()
            || sha1 == ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, der).as_ref();
        if !sha1_ok || !(sha256.is_empty() || sha256[..] == Sha256::digest(der)[..]) {
            return None;
        }
    }
    Some(true)
}

/// Whether the certificate holds the member's key, as Go compares the parsed keys.
fn same_key(cert: &X509Certificate, public: &Public) -> bool {
    let spki = cert.public_key();
    let strip = |b: &[u8]| -> Vec<u8> { b.iter().copied().skip_while(|&b| b == 0).collect() };
    match public {
        Public::Rsa { n, e } => match spki.parsed() {
            // Go's parser wants a positive modulus and a positive exponent that fits an int.
            Ok(PublicKey::RSA(k)) => {
                let (modulus, exponent) = (strip(k.modulus), strip(k.exponent));
                let positive = |raw: &[u8], stripped: &[u8]| !stripped.is_empty() && raw[0] < 0x80;
                positive(k.modulus, &modulus)
                    && positive(k.exponent, &exponent)
                    && (exponent.len() < 8 || (exponent.len() == 8 && exponent[0] < 0x80))
                    && modulus == strip(n)
                    && exponent == strip(e)
            }
            _ => false,
        },
        Public::Ec(curve, point) => {
            let named = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .is_some_and(|oid| oid == *curve);
            spki.algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY
                && named
                && spki.subject_public_key.data.as_ref() == point.as_slice()
        }
        Public::Ed25519(key) => {
            spki.algorithm.algorithm == OID_SIG_ED25519
                && spki.subject_public_key.data.as_ref() == key.as_slice()
        }
    }
}

/// An `x5t` or `x5t#S256` value: base64url of the digest, or of its hex spelling. Empty or the
/// digest's size.
fn thumbprint(text: &str, size: usize) -> Option<Vec<u8>> {
    let mut bytes = go_base64(text, true)?;
    if bytes.len() == 2 * size {
        bytes = bytes
            .chunks(2)
            .map(|pair| {
                let digit = |b: u8| char::from(b).to_digit(16);
                Some((digit(pair[0])? * 16 + digit(pair[1])?) as u8)
            })
            .collect::<Option<_>>()?;
    }
    (bytes.is_empty() || bytes.len() == size).then_some(bytes)
}
