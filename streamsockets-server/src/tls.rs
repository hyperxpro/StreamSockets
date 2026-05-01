//! TLS termination via rustls for native `wss://` support.
//!
//! Supports optional mTLS (`TLS_REQUIRE_CLIENT_CERT=true`) gated by a
//! `TLS_CLIENT_CA_FILE` (PEM bundle of trusted client-cert issuers).

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;

pub type TlsAcceptor = tokio_rustls::TlsAcceptor;

pub fn load_tls(
    cert_path: &Path,
    key_path: &Path,
    require_client_cert: bool,
    client_ca_path: Option<&Path>,
) -> anyhow::Result<TlsAcceptor> {
    let cert_bytes = std::fs::read(cert_path)
        .with_context(|| format!("reading TLS cert {}", cert_path.display()))?;
    let key_bytes = std::fs::read(key_path)
        .with_context(|| format!("reading TLS key {}", key_path.display()))?;

    let mut cursor = std::io::Cursor::new(&cert_bytes);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .context("parsing TLS certs")?;
    if certs.is_empty() {
        anyhow::bail!("no certs found in {}", cert_path.display());
    }

    let mut cursor = std::io::Cursor::new(&key_bytes);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut cursor)
        .context("parsing TLS key")?
        .ok_or_else(|| anyhow::anyhow!("no private key in {}", key_path.display()))?;

    let builder = rustls::ServerConfig::builder();

    let mut config = if require_client_cert {
        let ca_path = client_ca_path.ok_or_else(|| {
            anyhow::anyhow!("TLS_REQUIRE_CLIENT_CERT=true requires TLS_CLIENT_CA_FILE to be set")
        })?;
        let ca_bytes = std::fs::read(ca_path)
            .with_context(|| format!("reading client CA bundle {}", ca_path.display()))?;
        let mut cursor = std::io::Cursor::new(&ca_bytes);
        let mut root = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut cursor) {
            let cert = cert.context("parsing client CA cert")?;
            root.add(cert)
                .context("adding client CA cert to root store")?;
        }
        if root.is_empty() {
            anyhow::bail!("no client CA certs found in {}", ca_path.display());
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(root))
            .build()
            .context("building client cert verifier")?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .context("building rustls server config (mTLS)")?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("building rustls server config")?
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config).into())
}
