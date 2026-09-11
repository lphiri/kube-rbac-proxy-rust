use rustls::crypto::ring::sign::any_supported_type;
use rustls::{
    crypto::{self, CryptoProvider},
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_pemfile::{certs, private_key};
use std::{fmt, fs::File, io::BufReader, path::PathBuf, sync::Arc};

/// Build the rustls provider used by Pingora's listener.
///
/// Pingora 0.9 selects TLS 1.2 and TLS 1.3 at the listener builder level. A
/// provider filtered to TLS 1.3 suites therefore enforces a TLS 1.3 minimum,
/// while filtering by suite name implements the CLI cipher restriction.
pub fn provider_for(min_version: &str, cipher_names: &[String]) -> anyhow::Result<CryptoProvider> {
    let mut provider = crypto::ring::default_provider();
    provider.cipher_suites.retain(|suite| {
        let tls13 = suite.version().version == rustls::ProtocolVersion::TLSv1_3;
        let version_allowed = min_version != "VersionTLS13" || tls13;
        let name_allowed = cipher_names.is_empty()
            || cipher_names
                .iter()
                .any(|name| name == &format!("{:?}", suite.suite()));
        version_allowed && name_allowed
    });
    if provider.cipher_suites.is_empty() {
        anyhow::bail!("TLS settings select no supported cipher suites")
    }
    Ok(provider)
}

pub fn install_provider(min_version: &str, cipher_names: &[String]) -> anyhow::Result<()> {
    if min_version == "VersionTLS12" && cipher_names.is_empty() {
        return Ok(());
    }
    provider_for(min_version, cipher_names)?
        .install_default()
        .map_err(|_| anyhow::anyhow!("TLS crypto provider was already installed"))
}

/// Loads the configured certificate and key for each new TLS handshake.
/// This makes replacing the files effective without restarting the process.
pub struct ReloadingCertificateResolver {
    certificate: PathBuf,
    private_key: PathBuf,
}

impl ReloadingCertificateResolver {
    pub fn new(certificate: impl Into<PathBuf>, private_key: impl Into<PathBuf>) -> Self {
        Self {
            certificate: certificate.into(),
            private_key: private_key.into(),
        }
    }

    fn load(&self) -> Option<Arc<CertifiedKey>> {
        let certificates = certs(&mut BufReader::new(File::open(&self.certificate).ok()?))
            .collect::<std::result::Result<Vec<CertificateDer<'static>>, _>>()
            .ok()?;
        let key: PrivateKeyDer<'static> =
            private_key(&mut BufReader::new(File::open(&self.private_key).ok()?)).ok()??;
        let signer = any_supported_type(&key).ok()?;
        Some(Arc::new(CertifiedKey::new(certificates, signer)))
    }
}

impl fmt::Debug for ReloadingCertificateResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReloadingCertificateResolver")
            .field("certificate", &self.certificate)
            .field("private_key", &self.private_key)
            .finish()
    }
}

impl ResolvesServerCert for ReloadingCertificateResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.load()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_filters_tls13_and_named_suites() {
        let provider = provider_for("VersionTLS13", &["TLS13_AES_128_GCM_SHA256".into()]).unwrap();
        assert_eq!(provider.cipher_suites.len(), 1);
        assert_eq!(
            format!("{:?}", provider.cipher_suites[0].suite()),
            "TLS13_AES_128_GCM_SHA256"
        );
    }

    #[test]
    fn provider_rejects_empty_selection() {
        assert!(provider_for(
            "VersionTLS13",
            &["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into()]
        )
        .is_err());
    }

    #[test]
    fn missing_files_fail_closed() {
        let resolver = ReloadingCertificateResolver::new("missing-cert.pem", "missing-key.pem");
        assert!(resolver.load().is_none());
    }

    #[test]
    fn valid_pem_files_load_a_certified_key() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let resolver = ReloadingCertificateResolver::new(
            root.join("tests/fixtures/reload-cert.pem"),
            root.join("tests/fixtures/reload-key.pem"),
        );
        let key = resolver.load().expect("fixture certificate should load");
        assert_eq!(key.cert.len(), 1);
    }
}
