use crate::{
    authn::AuthenticatorChain, authorization, config::AuthorizationConfig, kube::KubernetesClient,
};
use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, Uri};
use pingora::prelude::*;
use pingora::protocols::tls::CaType;
use pingora::utils::tls::{parse_x509, CertKey, WrappedX509};
use rustls_pemfile::{certs, private_key};
use std::{
    fs::File,
    io::BufReader,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

#[derive(Clone)]
pub struct Proxy {
    pub upstream: Uri,
    pub authz: AuthorizationConfig,
    pub allow: Vec<String>,
    pub ignore: Vec<String>,
    pub auth_headers: bool,
    pub user_header: String,
    pub groups_header: String,
    pub group_separator: String,
    pub authenticators: AuthenticatorChain,
    pub kube_client: Option<KubernetesClient>,
    pub upstream_timeout: Duration,
    pub upstream_force_h2c: bool,
    pub upstream_client_cert_key: Option<Arc<CertKey>>,
    pub upstream_ca: Option<Arc<CaType>>,
    pub requests_total: Arc<AtomicU64>,
    pub operational_endpoints: bool,
    pub http2_max_concurrent_streams: u32,
    pub http2_max_size: u32,
}
pub struct RequestContext {
    pub identity: Option<crate::authorization::Identity>,
}

fn matches(pattern: &str, path: &str) -> bool {
    if pattern == path || pattern == "*" {
        return true;
    }
    let p: Vec<_> = pattern.split('*').collect();
    p.len() == 2 && path.starts_with(p[0]) && path.ends_with(p[1])
}
fn request_from_session(session: &Session) -> Request<()> {
    let mut request = Request::from_parts(session.req_header().as_owned_parts(), ());
    if let Some(identity) = session
        .digest()
        .and_then(|digest| digest.ssl_digest.as_ref())
        .and_then(|ssl| ssl.extension.get::<String>().map(String::as_str))
    {
        request.headers_mut().insert(
            "x-pingora-client-cert-identity",
            identity
                .parse()
                .expect("certificate identity is valid ASCII"),
        );
    }
    request
}

#[async_trait]
impl ProxyHttp for Proxy {
    type CTX = RequestContext;
    fn new_ctx(&self) -> Self::CTX {
        RequestContext { identity: None }
    }
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let path = session.req_header().uri.path().to_string();
        if self.operational_endpoints && path == "/healthz" {
            session
                .respond_error_with_body(200, Bytes::from_static(b"ok\n"))
                .await?;
            return Ok(true);
        }
        if self.operational_endpoints && path == "/metrics" {
            let count = self.requests_total.load(Ordering::Relaxed);
            session
                .respond_error_with_body(
                    200,
                    Bytes::from(format!("# HELP kube_rbac_proxy_requests_total Proxy requests\n# TYPE kube_rbac_proxy_requests_total counter\nkube_rbac_proxy_requests_total {count}\n")),
                )
                .await?;
            return Ok(true);
        }
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if !self.allow.is_empty() && !self.allow.iter().any(|p| matches(p, &path)) {
            session.respond_error(404).await?;
            return Ok(true);
        }
        if self.ignore.iter().any(|p| matches(p, &path)) {
            return Ok(false);
        }
        let request = request_from_session(session);
        let Some(user) = self
            .authenticators
            .authenticate(&request)
            .await
            .map_err(|e| pingora::Error::explain(ErrorType::InternalError, e.to_string()))?
        else {
            session.respond_error(401).await?;
            return Ok(true);
        };
        let attrs = authorization::attributes(&self.authz, &request, user.clone())
            .map_err(|e| pingora::Error::explain(ErrorType::InternalError, e.to_string()))?;
        if attrs.is_empty() {
            session.respond_error(403).await?;
            return Ok(true);
        }
        for attr in &attrs {
            if authorization::static_allows(&self.authz.static_rules, attr) {
                continue;
            }
            let allowed = match &self.kube_client {
                Some(client) => client.authorize(attr).await.map_err(|e| {
                    pingora::Error::explain(ErrorType::InternalError, e.to_string())
                })?,
                None => false,
            };
            if !allowed {
                session.respond_error(403).await?;
                return Ok(true);
            }
        }
        ctx.identity = Some(user);
        Ok(false)
    }
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let host = self.upstream.host().ok_or_else(|| {
            pingora::Error::explain(ErrorType::InternalError, "upstream has no host")
        })?;
        let h2c = self.upstream.scheme_str() == Some("h2c") || self.upstream_force_h2c;
        let tls = self.upstream.scheme_str() == Some("https");
        let port = self
            .upstream
            .port_u16()
            .unwrap_or(if tls { 443 } else { 80 });
        let mut peer = HttpPeer::new(format!("{host}:{port}"), tls, host.to_string());
        peer.options.connection_timeout = Some(self.upstream_timeout);
        peer.options.read_timeout = Some(self.upstream_timeout);
        peer.options.write_timeout = Some(self.upstream_timeout);
        if h2c {
            peer.options.set_http_version(2, 2);
        }
        peer.options.max_h2_streams = self.http2_max_concurrent_streams as usize;
        peer.options.h2_stream_window_size = Some(self.http2_max_size);
        peer.options.h2_connection_window_size = Some(self.http2_max_size);
        peer.client_cert_key = self.upstream_client_cert_key.clone();
        peer.options.ca = self.upstream_ca.clone();
        Ok(Box::new(peer))
    }
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if self.auth_headers {
            if let Some(user) = &ctx.identity {
                request.insert_header(self.user_header.clone(), &user.name)?;
                request.insert_header(
                    self.groups_header.clone(),
                    user.groups.join(&self.group_separator),
                )?;
            }
        }
        Ok(())
    }
}
#[allow(clippy::too_many_arguments)]
pub fn build_proxy(
    upstream: Uri,
    authz: AuthorizationConfig,
    allow: Vec<String>,
    ignore: Vec<String>,
    auth_headers: bool,
    user_header: String,
    groups_header: String,
    group_separator: String,
    authenticators: AuthenticatorChain,
    kube_client: Option<KubernetesClient>,
    upstream_timeout: Duration,
    upstream_force_h2c: bool,
    upstream_client_cert_file: Option<std::path::PathBuf>,
    upstream_client_key_file: Option<std::path::PathBuf>,
    upstream_ca_file: Option<std::path::PathBuf>,
    requests_total: Arc<AtomicU64>,
    http2_max_concurrent_streams: u32,
    http2_max_size: u32,
    operational_endpoints: bool,
) -> Proxy {
    let upstream_client_cert_key = match (upstream_client_cert_file, upstream_client_key_file) {
        (Some(cert), Some(key)) => {
            let certs = certs(&mut BufReader::new(
                File::open(cert).expect("upstream certificate"),
            ))
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("upstream certificate PEM");
            let key = private_key(&mut BufReader::new(File::open(key).expect("upstream key")))
                .expect("upstream key PEM")
                .expect("upstream private key");
            Some(Arc::new(CertKey::new(
                certs.into_iter().map(|x| x.to_vec()).collect(),
                key.secret_der().to_vec(),
            )))
        }
        _ => None,
    };
    let upstream_ca: Option<Arc<CaType>> = upstream_ca_file.map(|path| {
        let certs = certs(&mut BufReader::new(File::open(path).expect("upstream CA")))
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("upstream CA PEM");
        Arc::from(
            certs
                .into_iter()
                .map(|cert| WrappedX509::new(cert.to_vec(), parse_x509))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        )
    });
    Proxy {
        upstream,
        authz,
        allow,
        ignore,
        auth_headers,
        user_header,
        groups_header,
        group_separator,
        authenticators,
        kube_client,
        upstream_timeout,
        upstream_force_h2c,
        upstream_client_cert_key,
        upstream_ca,
        requests_total,
        http2_max_concurrent_streams,
        http2_max_size,
        operational_endpoints,
    }
}
