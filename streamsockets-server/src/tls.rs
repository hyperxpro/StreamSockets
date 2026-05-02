//! TLS termination via rustls for native `wss://` support.
//!
//! Pinned to TLS 1.2 + 1.3 explicitly so a future rustls dep bump cannot
//! silently relax the protocol floor. Optional mTLS is gated by
//! `TLS_REQUIRE_CLIENT_CERT=true` plus `TLS_CLIENT_CA_FILE` (PEM bundle of
//! trusted client-cert issuers).
//!
//! Certificates are reloaded on demand via [`HotReloadResolver`]: the file
//! contents are re-read on `reload()`, and every new TLS handshake selects
//! the latest version. SIGHUP triggers reload from `lib.rs`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use arc_swap::ArcSwap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;

pub type TlsAcceptor = tokio_rustls::TlsAcceptor;

/// Holds the latest cert+key pair, swapped atomically on reload. Implements
/// [`ResolvesServerCert`] so a single rustls config covers both the initial
/// handshake and every post-rotation handshake.
#[derive(Debug)]
pub struct HotReloadResolver {
    cert_path: PathBuf,
    key_path: PathBuf,
    current: ArcSwap<CertifiedKey>,
}

impl HotReloadResolver {
    pub fn new(cert_path: PathBuf, key_path: PathBuf) -> anyhow::Result<Arc<Self>> {
        let ck = load_certified_key(&cert_path, &key_path)?;
        Ok(Arc::new(Self {
            cert_path,
            key_path,
            current: ArcSwap::from_pointee(ck),
        }))
    }

    /// Re-read the cert + key from disk and atomically swap the active version.
    /// Errors leave the previous version installed.
    pub fn reload(&self) -> anyhow::Result<()> {
        let ck = load_certified_key(&self.cert_path, &self.key_path)?;
        self.current.store(Arc::new(ck));
        Ok(())
    }

    /// Async variant: `std::fs::read` blocks the runtime worker for the duration
    /// of disk I/O. Off-load to the blocking pool so SIGHUP-triggered reload
    /// does not stall every other task on this thread.
    pub async fn reload_async(self: Arc<Self>) -> anyhow::Result<()> {
        let cert_path = self.cert_path.clone();
        let key_path = self.key_path.clone();
        let ck = tokio::task::spawn_blocking(move || load_certified_key(&cert_path, &key_path))
            .await
            .map_err(|e| anyhow::anyhow!("tls reload join failure: {e}"))??;
        self.current.store(Arc::new(ck));
        Ok(())
    }
}

impl ResolvesServerCert for HotReloadResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.load_full())
    }
}

fn load_certified_key(cert_path: &Path, key_path: &Path) -> anyhow::Result<CertifiedKey> {
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

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .context("building signing key from PEM")?;
    let ck = CertifiedKey::new(certs, signing_key);
    // Verify the private key actually corresponds to the leaf certificate.
    // Without this, a misconfigured cert/key pair only surfaces at first
    // handshake — the server starts, /readyz flips green, and every TLS
    // accept fails. `keys_match` (rustls 0.23 §`CertifiedKey::keys_match`)
    // compares SubjectPublicKeyInfo bytes, which is the strongest validator
    // rustls exposes.
    ck.keys_match().context("TLS cert/key SPKI mismatch")?;
    Ok(ck)
}

pub fn load_tls(
    cert_path: &Path,
    key_path: &Path,
    require_client_cert: bool,
    client_ca_path: Option<&Path>,
) -> anyhow::Result<(TlsAcceptor, Arc<HotReloadResolver>)> {
    let resolver = HotReloadResolver::new(cert_path.to_path_buf(), key_path.to_path_buf())?;

    // Pin the protocol floor explicitly. A future rustls dep that adds (e.g.)
    // TLS 1.1 to `default_versions()` cannot regress us silently.
    let builder = rustls::ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ]);

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
            .with_cert_resolver(resolver.clone() as Arc<dyn ResolvesServerCert>)
    } else {
        builder
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone() as Arc<dyn ResolvesServerCert>)
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    // Bound the session cache. `ServerSessionMemoryCache` is unbounded by
    // default, so a long-running process accumulates session tickets without
    // upper bound. 4096 is comfortably above the steady-state TLS-resumption
    // working set for a single host while capping the worst case at a few MiB.
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(4096);
    Ok((Arc::new(config).into(), resolver))
}
