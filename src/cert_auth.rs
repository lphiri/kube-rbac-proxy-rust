use crate::{authn::Authenticator, authorization::Identity};
use anyhow::Result;
use async_trait::async_trait;
use http::Request;
use pingora::{listeners::TlsAccept, protocols::tls::TlsRef};
use std::{any::Any, sync::Arc};

pub struct ClientCertificateCallback;

#[async_trait]
impl TlsAccept for ClientCertificateCallback {
    async fn handshake_complete_callback(
        &self,
        tls: &TlsRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        let der = tls.peer_certificate_der()?;
        let (_, certificate) = x509_parser::parse_x509_certificate(der).ok()?;
        let common_name = certificate
            .subject()
            .iter_common_name()
            .next()?
            .as_str()
            .ok()?
            .to_string();
        Some(Arc::new(common_name))
    }
}

/// Authenticates the certificate identity recorded by the trusted Pingora TLS layer.
/// The internal header is inserted only from Pingora's TLS connection digest.
#[derive(Clone, Default)]
pub struct ClientCertificateAuthenticator {
    pub username_prefix: String,
}

#[async_trait]
impl Authenticator for ClientCertificateAuthenticator {
    async fn authenticate(&self, request: &Request<()>) -> Result<Option<Identity>> {
        let Some(name) = request
            .headers()
            .get("x-pingora-client-cert-identity")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        Ok(Some(Identity {
            name: format!("{}{}", self.username_prefix, name),
            groups: Vec::new(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn certificate_identity_is_mapped_to_common_name() {
        let request = Request::builder()
            .header("x-pingora-client-cert-identity", "alice")
            .body(())
            .unwrap();
        let identity = ClientCertificateAuthenticator {
            username_prefix: "cert:".into(),
        }
        .authenticate(&request)
        .await
        .unwrap()
        .unwrap();
        assert_eq!(identity.name, "cert:alice");
    }
}
