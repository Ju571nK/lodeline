//! TLS for the downstream listener (required for non-loopback binds) and for
//! `https` upstreams. Unix only: `ring` needs a C toolchain and the Windows
//! proxy service is unsupported until verified. On other platforms the types
//! are uninhabited and loading fails with a clear error (fail closed).

#[cfg(unix)]
pub use unix::*;

#[cfg(unix)]
mod unix {
    use std::io::BufReader;
    use std::path::Path;
    use std::sync::Arc;

    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    pub use tokio_rustls::{TlsAcceptor as Acceptor, TlsConnector as Connector};

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    /// Listener TLS. The certificate is public material; the key is read
    /// through the owner-only reader.
    pub fn load_acceptor(cert_file: &Path, key_file: &Path) -> anyhow::Result<Acceptor> {
        let cert_f = crate::fsutil::open_public_file(cert_file)?;
        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut BufReader::new(cert_f)).collect::<Result<_, _>>()?;
        if certs.is_empty() {
            anyhow::bail!("tls_cert_file holds no certificate");
        }
        let key_bytes = crate::fsutil::read_private_file(key_file)?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(&key_bytes[..]))?
            .ok_or_else(|| anyhow::anyhow!("tls_key_file holds no private key"))?;
        let mut cfg = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Acceptor::from(Arc::new(cfg)))
    }

    /// Upstream TLS: the webpki root set, HTTP/1.1 only.
    // OPEN: upstream trust roots. Public WebPKI only; a private CA for an
    // upstream is not configurable in slice A.
    pub fn upstream_connector() -> Connector {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut cfg = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Connector::from(Arc::new(cfg))
    }

    pub fn server_name(host: &str) -> Option<ServerName<'static>> {
        ServerName::try_from(host.to_string()).ok()
    }
}

#[cfg(not(unix))]
pub enum Acceptor {}
#[cfg(not(unix))]
pub enum Connector {}

#[cfg(not(unix))]
pub fn load_acceptor(_: &std::path::Path, _: &std::path::Path) -> anyhow::Result<Acceptor> {
    anyhow::bail!("TLS listeners are not supported on this platform")
}
