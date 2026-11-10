//! Check an issued client certificate before it is trusted with the host's identity.

use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use x509_parser::extensions::GeneralName;

/// How far ahead of this host's clock a certificate may start. The server stamps
/// `notBefore` with its own "now", so a host a few seconds behind sees it in the future.
pub const CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);

fn certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|_| "the certificate is not valid PEM".to_string())
}

/// Check the bundle (the leaf, then its intermediates) against this host.
///
/// The leaf's public key must be `key_public` (the raw point), its CN and a SAN DNS
/// name must be `host_id`, and it must chain to one of `roots_pem` for client
/// authentication at `now`. A `notBefore` up to [`CLOCK_SKEW`] ahead is accepted and
/// reported as the `Ok` warning.
pub fn check(
    bundle_pem: &str,
    key_public: &[u8],
    host_id: &str,
    roots_pem: &str,
    now: OffsetDateTime,
) -> Result<Option<String>, String> {
    let chain = certs(bundle_pem)?;
    let (leaf, intermediates) = chain.split_first().ok_or("there is no certificate in it")?;
    let (_, x) = x509_parser::parse_x509_certificate(leaf)
        .map_err(|_| "the leaf is not a valid X.509 certificate")?;
    if *x.public_key().subject_public_key.data != *key_public {
        return Err("it is for another key than this host's client.key".into());
    }
    let cn = x
        .subject()
        .iter_common_name()
        .next()
        .and_then(|c| c.as_str().ok());
    let san_ok = x
        .subject_alternative_name()
        .ok()
        .flatten()
        .is_some_and(|e| {
            e.value
                .general_names
                .iter()
                .any(|n| matches!(n, GeneralName::DNSName(d) if *d == host_id))
        });
    if cn != Some(host_id) || !san_ok {
        return Err(
            "it names another host than this one (CN and SAN DNS must be the host_id)".into(),
        );
    }

    let mut store = rustls::RootCertStore::empty();
    for root in certs(roots_pem)? {
        store
            .add(root)
            .map_err(|e| format!("bad CA certificate: {e}"))?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(store),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .map_err(|e| format!("cannot build the verifier: {e}"))?;

    let ahead = x.validity().not_before.timestamp() - now.unix_timestamp();
    let skewed = ahead > 0 && ahead as u64 <= CLOCK_SKEW.as_secs();
    let at = if skewed {
        now.unix_timestamp() + ahead
    } else {
        now.unix_timestamp()
    };
    let at = UnixTime::since_unix_epoch(Duration::from_secs(at.max(0) as u64));
    verifier
        .verify_client_cert(leaf, intermediates, at)
        .map_err(|e| describe(&e))?;
    Ok(skewed.then(|| {
        format!(
            "the certificate starts {ahead} s after this host's clock; this host's clock is \
             behind the server's. Fix it, or the sender's TLS fails until the certificate starts"
        )
    }))
}

fn describe(e: &rustls::Error) -> String {
    use rustls::CertificateError as C;
    match e {
        rustls::Error::InvalidCertificate(C::Expired | C::ExpiredContext { .. }) => {
            "it has expired".into()
        }
        rustls::Error::InvalidCertificate(C::NotValidYet | C::NotValidYetContext { .. }) => {
            "it is not valid yet by more than 5 minutes; check this host's clock".into()
        }
        rustls::Error::InvalidCertificate(C::UnknownIssuer | C::BadSignature) => {
            "it does not chain to a CA in the enrollment file's server_ca_pem".into()
        }
        rustls::Error::InvalidCertificate(C::InvalidPurpose | C::InvalidPurposeContext { .. }) => {
            "it is not valid for client authentication".into()
        }
        other => format!("it does not verify: {other}"),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair,
    };

    pub const HOST: &str = "3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6f";

    pub fn ca(name: &str) -> CertifiedIssuer<'static, KeyPair> {
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name.push(DnType::CommonName, name);
        CertifiedIssuer::self_signed(p, KeyPair::generate().unwrap()).unwrap()
    }

    pub fn intermediate(root: &CertifiedIssuer<'_, KeyPair>) -> CertifiedIssuer<'static, KeyPair> {
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name.push(DnType::CommonName, "int");
        CertifiedIssuer::signed_by(p, KeyPair::generate().unwrap(), root).unwrap()
    }

    pub fn leaf(
        issuer: &CertifiedIssuer<'_, KeyPair>,
        key: &KeyPair,
        cn: &str,
        eku: ExtendedKeyUsagePurpose,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> String {
        let mut p = CertificateParams::new(vec![cn.to_string()]).unwrap();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.extended_key_usages = vec![eku];
        p.not_before = not_before;
        p.not_after = not_after;
        p.signed_by(key, issuer).unwrap().pem()
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    fn day() -> time::Duration {
        time::Duration::days(1)
    }

    /// Run `check` on a leaf for `HOST` made with `mutate` over the defaults.
    fn run(
        eku: ExtendedKeyUsagePurpose,
        nb: time::Duration,
        na: time::Duration,
        cn: &str,
        wrong_key: bool,
        other_root: bool,
    ) -> Result<Option<String>, String> {
        let root = ca("root");
        let int = intermediate(&root);
        let key = KeyPair::generate().unwrap();
        let bundle = format!(
            "{}{}",
            leaf(&int, &key, cn, eku, now() + nb, now() + na),
            int.pem()
        );
        let roots = if other_root {
            ca("other").pem()
        } else {
            root.pem()
        };
        let pk = if wrong_key {
            KeyPair::generate().unwrap().public_key_raw().to_vec()
        } else {
            key.public_key_raw().to_vec()
        };
        check(&bundle, &pk, HOST, &roots, now())
    }

    use ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};

    #[test]
    fn a_good_certificate_passes_without_a_warning() {
        assert_eq!(run(ClientAuth, -day(), day(), HOST, false, false), Ok(None));
    }

    #[test]
    fn another_key_host_root_purpose_or_expiry_is_refused() {
        let e = |r: Result<Option<String>, String>| r.unwrap_err();
        assert!(e(run(ClientAuth, -day(), day(), HOST, true, false)).contains("another key"));
        assert!(
            e(run(ClientAuth, -day(), day(), "someone-else", false, false))
                .contains("another host")
        );
        assert!(e(run(ClientAuth, -day(), day(), HOST, false, true)).contains("server_ca_pem"));
        assert!(
            e(run(ServerAuth, -day(), day(), HOST, false, false)).contains("client authentication")
        );
        assert!(e(run(ClientAuth, -day() * 3, -day(), HOST, false, false)).contains("expired"));
    }

    #[test]
    fn a_start_within_five_minutes_ahead_warns_and_more_is_refused() {
        let ok = run(
            ClientAuth,
            time::Duration::seconds(120),
            day(),
            HOST,
            false,
            false,
        );
        assert!(ok.unwrap().unwrap().contains("clock"));
        let e = run(
            ClientAuth,
            time::Duration::minutes(6),
            day(),
            HOST,
            false,
            false,
        )
        .unwrap_err();
        assert!(e.contains("not valid yet"), "{e}");
    }
}
