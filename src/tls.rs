use rustls::crypto::ring::sign::any_supported_type;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_pemfile::{certs, private_key};
use std::{fmt, fs::File, io::BufReader, path::PathBuf, sync::Arc};

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
    fn missing_files_fail_closed() {
        let resolver = ReloadingCertificateResolver::new("missing-cert.pem", "missing-key.pem");
        assert!(resolver.load().is_none());
    }
}
