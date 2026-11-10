//! `lodeline-sender csr`: the host's enrollment key and CSR, made on the host.

/// A new ECDSA P-256 private key as PKCS#8 PEM, and a PEM CSR signed by it whose
/// subject is only `CN=<host_id>`. `host_id` must be a UUID, the rule
/// `POST /v1/enroll` applies; the CN is the string as given because the server
/// compares it with the request's `host_id` byte for byte.
pub fn host_key_and_csr(host_id: &str) -> anyhow::Result<(String, String)> {
    if uuid::Uuid::parse_str(host_id).is_err() {
        anyhow::bail!("--host-id must be a UUID (the agent's host_id), got {host_id:?}");
    }
    let key = new_key()?;
    let csr = csr_for(&key, host_id)?;
    Ok((key.serialize_pem(), csr))
}

/// A new ECDSA P-256 host key.
pub fn new_key() -> anyhow::Result<rcgen::KeyPair> {
    Ok(rcgen::KeyPair::generate_for(
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )?)
}

/// The PEM CSR for `key`, with subject `CN=<host_id>` and nothing else.
pub fn csr_for(key: &rcgen::KeyPair, host_id: &str) -> anyhow::Result<String> {
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host_id);
    Ok(params.serialize_request(key)?.pem()?)
}

#[cfg(test)]
mod tests {
    use super::host_key_and_csr;
    use x509_parser::certification_request::X509CertificationRequest;
    use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY};
    use x509_parser::prelude::FromDer;

    const HOST_ID: &str = "3f2c6a1e-8b4d-4c2a-9e7f-1a2b3c4d5e6f";

    #[test]
    fn csr_is_signed_by_a_p256_key_and_names_only_the_host() {
        let (key_pem, csr_pem) = host_key_and_csr(HOST_ID).unwrap();

        let (_, pem) = x509_parser::pem::parse_x509_pem(csr_pem.as_bytes()).unwrap();
        assert_eq!(pem.label, "CERTIFICATE REQUEST");
        let (rest, csr) = X509CertificationRequest::from_der(&pem.contents).unwrap();
        assert!(rest.is_empty());
        csr.verify_signature().expect("CSR self-signature verifies");

        let info = &csr.certification_request_info;
        let cns: Vec<_> = info
            .subject
            .iter_common_name()
            .map(|cn| cn.as_str().unwrap())
            .collect();
        assert_eq!(cns, [HOST_ID]);
        assert_eq!(
            info.subject.iter_attributes().count(),
            1,
            "subject is CN only"
        );
        assert!(csr.requested_extensions().is_none(), "no extension request");

        let spki = &info.subject_pki;
        assert_eq!(spki.algorithm.algorithm, OID_KEY_TYPE_EC_PUBLIC_KEY);
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .unwrap()
            .as_oid()
            .unwrap();
        assert_eq!(curve, OID_EC_P256);

        let key = rcgen::KeyPair::from_pem(&key_pem).unwrap();
        assert!(
            key_pem.starts_with("-----BEGIN PRIVATE KEY-----"),
            "PKCS#8 PEM"
        );
        assert_eq!(key.algorithm(), &rcgen::PKCS_ECDSA_P256_SHA256);
        assert_eq!(key.public_key_raw(), &*spki.subject_public_key.data);
    }

    #[test]
    fn rejects_a_host_id_that_is_not_a_uuid() {
        for bad in ["", "hostA", "3f2c6a1e-8b4d-4c2a-9e7f", "CN=x"] {
            // map(drop): an unexpected Ok must not print the key.
            let err = host_key_and_csr(bad).map(drop).unwrap_err().to_string();
            assert!(err.contains("must be a UUID"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn each_call_makes_a_new_key() {
        let (a, _) = host_key_and_csr(HOST_ID).unwrap();
        let (b, _) = host_key_and_csr(HOST_ID).unwrap();
        assert!(a != b, "two calls returned the same key");
    }
}
