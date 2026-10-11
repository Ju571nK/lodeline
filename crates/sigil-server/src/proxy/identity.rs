//! Peer classification and proxy SAN handling (control-plane §1.2).

use crate::tls_accept::{hex_lower, PeerIdentity};
use anyhow::{bail, Context, Result};
use std::path::Path;

/// Reserved DNS suffix of a proxy SAN.
// OPEN: control-plane §10 q1 — exact proxy SAN form is not decided. Every use
// of the form goes through `proxy_san` / `proxy_id_from_san` below.
const PROXY_SAN_SUFFIX: &str = ".proxy.sigil.invalid";

/// The SAN a proxy leaf carries for `proxy_id`.
// OPEN: control-plane §10 q1
pub fn proxy_san(proxy_id: &str) -> String {
    format!("{proxy_id}{PROXY_SAN_SUFFIX}")
}

/// Extract the `proxy_id` from a leaf's DNS SANs. The signing profile allows
/// exactly one DNS SAN, so zero or several give `None`. The id must be a DNS
/// label (alnum + `-`, 1..=63). A bare host_id-shaped SAN is never a proxy
/// identity. CN, when present, must equal the id.
// OPEN: control-plane §10 q1
pub fn proxy_id_from_san(san_dns: &[String], cn: Option<&str>) -> Option<String> {
    let [san] = san_dns else {
        return None;
    };
    if san.len() <= PROXY_SAN_SUFFIX.len()
        || !san[san.len() - PROXY_SAN_SUFFIX.len()..].eq_ignore_ascii_case(PROXY_SAN_SUFFIX)
    {
        return None;
    }
    let id = &san[..san.len() - PROXY_SAN_SUFFIX.len()];
    if !is_dns_label(id) {
        return None;
    }
    if cn.is_some_and(|c| c != id) {
        return None;
    }
    Some(id.to_string())
}

fn is_dns_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Class of a verified TLS peer, from its leaf issuer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerClass {
    /// Issued by anything in the bundle other than the proxy CA.
    Host,
    /// Issued by the configured proxy CA.
    Proxy,
    /// Issuer DN equals the proxy CA but the AKI contradicts its key id.
    /// Rejected on every route class (fail closed).
    Ambiguous,
    /// Management-caller class (host CA + verifier fingerprint list).
    // OPEN: S2 — never produced by S1.
    Management,
}

/// What the server knows about the proxy CA.
#[derive(Clone, Debug)]
pub struct ProxyCaInfo {
    /// Subject DN (x509-parser display form), compared with the leaf issuer.
    pub subject_dn: String,
    /// Subject Key Identifier (hex), when the CA cert carries one.
    pub ski: Option<String>,
}

impl ProxyCaInfo {
    pub fn new(subject_dn: impl Into<String>, ski: Option<String>) -> Self {
        Self {
            subject_dn: subject_dn.into(),
            ski,
        }
    }

    /// Read the proxy CA PEM and cross-check it against the client-CA bundle.
    pub fn from_files(proxy_ca: &Path, client_bundle: &Path) -> Result<Self> {
        let proxy_ders = read_pem_certs(proxy_ca)?;
        if proxy_ders.len() != 1 {
            bail!("expected exactly one certificate in the proxy CA file");
        }
        let proxy_der = &proxy_ders[0];
        let info = Self::from_der(proxy_der)?;
        let bundle = read_pem_certs(client_bundle)?;
        if !bundle.iter().any(|d| d == proxy_der) {
            bail!("proxy CA is not in client_ca_path; proxy leaves would fail the TLS handshake");
        }
        for der in bundle.iter().filter(|d| *d != proxy_der) {
            let other = Self::from_der(der)?;
            if other.subject_dn == info.subject_dn {
                bail!(
                    "host CA and proxy CA share subject DN {:?}; the DNs must differ",
                    info.subject_dn
                );
            }
        }
        Ok(info)
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        use x509_parser::extensions::ParsedExtension;
        let (_, cert) = x509_parser::parse_x509_certificate(der)
            .map_err(|e| anyhow::anyhow!("parse CA certificate: {e}"))?;
        let ski = cert
            .iter_extensions()
            .find_map(|e| match e.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(k) => Some(hex_lower(k.0)),
                _ => None,
            });
        Ok(Self {
            subject_dn: cert.subject().to_string(),
            ski,
        })
    }

    /// Classify a verified peer. Host vs proxy is decided by the leaf issuer
    /// DN, tightened by the AKI when both sides carry a key id.
    pub fn classify(&self, peer: &PeerIdentity) -> PeerClass {
        if peer.issuer_dn.as_deref() != Some(self.subject_dn.as_str()) {
            return PeerClass::Host;
        }
        match (&peer.issuer_aki, &self.ski) {
            (Some(aki), Some(ski)) if aki != ski => PeerClass::Ambiguous,
            _ => PeerClass::Proxy,
        }
    }
}

fn read_pem_certs(path: &Path) -> Result<Vec<Vec<u8>>> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut rd = std::io::BufReader::new(&data[..]);
    let certs: Vec<Vec<u8>> = rustls_pemfile::certs(&mut rd)
        .map(|c| c.map(|d| d.as_ref().to_vec()))
        .collect::<Result<_, _>>()
        .with_context(|| format!("parse certs from {}", path.display()))?;
    if certs.is_empty() {
        bail!("no certs in {}", path.display());
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(issuer: &str, aki: Option<&str>) -> PeerIdentity {
        PeerIdentity {
            fingerprint: "ab".into(),
            issuer_dn: Some(issuer.into()),
            issuer_aki: aki.map(str::to_string),
            ..Default::default()
        }
    }

    fn ca() -> ProxyCaInfo {
        ProxyCaInfo::new("CN=proxy-ca", Some("0a0b".into()))
    }

    #[test]
    fn classify_by_issuer() {
        assert_eq!(ca().classify(&peer("CN=proxy-ca", None)), PeerClass::Proxy);
        assert_eq!(
            ca().classify(&peer("CN=proxy-ca", Some("0a0b"))),
            PeerClass::Proxy
        );
        assert_eq!(ca().classify(&peer("CN=host-ca", None)), PeerClass::Host);
        assert_eq!(
            ca().classify(&PeerIdentity::default()),
            PeerClass::Host,
            "unparsed issuer is never proxy"
        );
    }

    #[test]
    fn classify_aki_mismatch_is_ambiguous() {
        assert_eq!(
            ca().classify(&peer("CN=proxy-ca", Some("ffff"))),
            PeerClass::Ambiguous
        );
        // CA without SKI: AKI cannot contradict it.
        let no_ski = ProxyCaInfo::new("CN=proxy-ca", None);
        assert_eq!(
            no_ski.classify(&peer("CN=proxy-ca", Some("ffff"))),
            PeerClass::Proxy
        );
    }

    #[test]
    fn san_round_trip_and_rejections() {
        let one = |s: &str| vec![s.to_string()];
        assert_eq!(proxy_san("px-1"), "px-1.proxy.sigil.invalid");
        assert_eq!(
            proxy_id_from_san(&one(&proxy_san("px-1")), None).as_deref(),
            Some("px-1")
        );
        assert_eq!(
            proxy_id_from_san(&one(&proxy_san("px-1")), Some("px-1")).as_deref(),
            Some("px-1")
        );
        // CN present but different.
        assert_eq!(
            proxy_id_from_san(&one(&proxy_san("px-1")), Some("other")),
            None
        );
        // Bare host_id-shaped SAN, wrong suffix, empty id, dotted id, two SANs.
        let host = "018f9c1a-0000-7000-8000-0000000000aa";
        assert_eq!(proxy_id_from_san(&one(host), None), None);
        assert_eq!(proxy_id_from_san(&one(".proxy.sigil.invalid"), None), None);
        assert_eq!(
            proxy_id_from_san(&one("a.b.proxy.sigil.invalid"), None),
            None
        );
        assert_eq!(
            proxy_id_from_san(&one("px.proxy.sigil.example"), None),
            None
        );
        assert_eq!(
            proxy_id_from_san(&[proxy_san("a"), proxy_san("b")], None),
            None
        );
        assert_eq!(proxy_id_from_san(&[], None), None);
    }
}
