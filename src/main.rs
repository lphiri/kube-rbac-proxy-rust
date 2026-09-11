use anyhow::Result;
use clap::Parser;
use kube_rbac_proxy::{
    authn::AuthenticatorChain,
    cert_auth::{ClientCertificateAuthenticator, ClientCertificateCallback},
    config,
    kube::{KubernetesAuthenticator, KubernetesClient},
    oidc::OidcAuthenticator,
    pingora_proxy,
    tls::{self, ReloadingCertificateResolver},
};
use pingora::prelude::*;
use rustls::{
    server::{ResolvesServerCert, WebPkiClientVerifier},
    RootCertStore,
};
use rustls_pemfile::certs;
use std::sync::{atomic::AtomicU64, Arc};
use std::{path::PathBuf, time::Duration};

#[derive(Parser, Debug)]
#[command(
    name = "kube-rbac-proxy",
    version,
    about = "A small HTTP proxy with Kubernetes-style RBAC authorization"
)]
struct Args {
    #[arg(long)]
    upstream: String,
    #[arg(long)]
    secure_listen_address: Option<String>,
    #[arg(long, hide = true)]
    insecure_listen_address: Option<String>,
    #[arg(long, default_value_t = 0)]
    proxy_endpoints_port: u16,
    #[arg(long)]
    config_file: Option<String>,
    #[arg(long, default_value = "30s", value_parser = parse_duration)]
    upstream_timeout: Duration,
    #[arg(long)]
    upstream_force_h2c: bool,
    #[arg(long)]
    upstream_ca_file: Option<PathBuf>,
    #[arg(long)]
    upstream_client_cert_file: Option<PathBuf>,
    #[arg(long)]
    upstream_client_key_file: Option<PathBuf>,
    #[arg(long, value_delimiter = ',')]
    allow_paths: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    ignore_paths: Vec<String>,
    #[arg(long)]
    auth_header_fields_enabled: bool,
    #[arg(long, default_value = "x-remote-user")]
    auth_header_user_field_name: String,
    #[arg(long, default_value = "x-remote-groups")]
    auth_header_groups_field_name: String,
    #[arg(long, default_value = "|")]
    auth_header_groups_field_separator: String,
    #[arg(long, value_delimiter = ',')]
    auth_token_audiences: Vec<String>,
    #[arg(long)]
    client_ca_file: Option<PathBuf>,
    #[arg(long)]
    tls_cert_file: Option<PathBuf>,
    #[arg(long)]
    tls_private_key_file: Option<PathBuf>,
    #[arg(long, default_value = "VersionTLS12")]
    tls_min_version: String,
    #[arg(long, value_delimiter = ',')]
    tls_cipher_suites: Vec<String>,
    #[arg(long, default_value = "60s", value_parser = parse_duration)]
    tls_reload_interval: Duration,
    #[arg(long)]
    oidc_issuer: Option<String>,
    #[arg(long = "oidc-clientID")]
    oidc_client_id: Option<String>,
    #[arg(long, default_value = "email")]
    oidc_username_claim: String,
    #[arg(long, default_value = "")]
    oidc_username_prefix: String,
    #[arg(long, default_value = "groups")]
    oidc_groups_claim: String,
    #[arg(long, default_value = "")]
    oidc_groups_prefix: String,
    #[arg(long, value_delimiter = ',', default_values = ["RS256"])]
    oidc_sign_alg: Vec<String>,
    #[arg(long)]
    oidc_ca_file: Option<PathBuf>,
    #[arg(long)]
    kubeconfig: Option<PathBuf>,
    #[arg(long, default_value_t = 0.0)]
    kube_api_qps: f32,
    #[arg(long, default_value_t = 0)]
    kube_api_burst: u32,
    #[arg(long, default_value_t = 100)]
    http2_max_concurrent_streams: u32,
    #[arg(long, default_value_t = 256 * 1024)]
    http2_max_size: u32,
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    humantime::parse_duration(value).map_err(|e| e.to_string())
}

fn supported_tls_cipher_suite(value: &str) -> bool {
    matches!(
        value,
        "TLS13_AES_128_GCM_SHA256"
            | "TLS13_AES_256_GCM_SHA384"
            | "TLS13_CHACHA20_POLY1305_SHA256"
            | "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            | "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            | "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
            | "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
            | "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
            | "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
    )
}

impl Args {
    fn validate(&self) -> Result<()> {
        if !self.allow_paths.is_empty() && !self.ignore_paths.is_empty() {
            anyhow::bail!("cannot use --allow-paths and --ignore-paths together");
        }
        let upstream = url::Url::parse(&self.upstream)
            .map_err(|e| anyhow::anyhow!("invalid --upstream: {e}"))?;
        if !matches!(upstream.scheme(), "http" | "https" | "h2c") || upstream.host_str().is_none() {
            anyhow::bail!("--upstream must be an HTTP, HTTPS, or h2c URL with a host");
        }
        if self.upstream_force_h2c && !matches!(upstream.scheme(), "http" | "h2c") {
            anyhow::bail!("--upstream-force-h2c requires an HTTP upstream");
        }
        if self.upstream_client_cert_file.is_some() != self.upstream_client_key_file.is_some() {
            anyhow::bail!("--upstream-client-cert-file and --upstream-client-key-file must be provided together");
        }
        if self.tls_cert_file.is_some() != self.tls_private_key_file.is_some() {
            anyhow::bail!("--tls-cert-file and --tls-private-key-file must be provided together");
        }
        if self.client_ca_file.is_some() && self.tls_cert_file.is_none() {
            anyhow::bail!("--client-ca-file requires --tls-cert-file and --tls-private-key-file");
        }
        if tls::normalize_min_version(&self.tls_min_version).is_none() {
            anyhow::bail!(
                "--tls-min-version must be VersionTLS12, VersionTLS13, TLS1.2, or TLS1.3"
            );
        }
        if self
            .tls_cipher_suites
            .iter()
            .any(|cipher| cipher.trim().is_empty())
        {
            anyhow::bail!("--tls-cipher-suites cannot contain empty values");
        }
        if let Some(cipher) = self
            .tls_cipher_suites
            .iter()
            .find(|cipher| !supported_tls_cipher_suite(cipher))
        {
            anyhow::bail!("unsupported TLS cipher suite: {cipher}");
        }
        if self.oidc_issuer.is_some() && self.oidc_client_id.is_none() {
            anyhow::bail!("--oidc-clientID is required when --oidc-issuer is set");
        }
        if let Some(issuer) = &self.oidc_issuer {
            let parsed = url::Url::parse(issuer)
                .map_err(|e| anyhow::anyhow!("invalid --oidc-issuer: {e}"))?;
            if parsed.scheme() != "https" {
                anyhow::bail!("--oidc-issuer must use HTTPS");
            }
        }
        if self.auth_header_fields_enabled
            && (self.auth_header_user_field_name.is_empty()
                || self.auth_header_groups_field_name.is_empty())
        {
            anyhow::bail!("auth header field names cannot be empty when enabled");
        }
        if self.kube_api_qps < 0.0 || (self.kube_api_qps > 0.0 && self.kube_api_burst == 0) {
            anyhow::bail!("--kube-api-burst must be positive when --kube-api-qps is set");
        }
        if self.http2_max_concurrent_streams == 0 || self.http2_max_size == 0 {
            anyhow::bail!("HTTP/2 limits must be positive");
        }
        if self.secure_listen_address.is_none() && self.insecure_listen_address.is_none() {
            anyhow::bail!(
                "at least one of --secure-listen-address or --insecure-listen-address is required"
            );
        }
        if self.proxy_endpoints_port != 0 && self.secure_listen_address.is_none() {
            anyhow::bail!("--proxy-endpoints-port requires --secure-listen-address");
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    let _ = env_logger::try_init();
    let a = Args::parse();
    a.validate()?;
    let tls_min_version = tls::normalize_min_version(&a.tls_min_version)
        .expect("TLS minimum version was validated above");
    tls::install_provider(tls_min_version, &a.tls_cipher_suites)?;
    let cfg = a
        .config_file
        .map(|p| config::load(&p))
        .transpose()?
        .unwrap_or_default();
    let kube_client = KubernetesClient::from_configuration(
        a.kubeconfig.as_deref(),
        a.kube_api_qps,
        a.kube_api_burst,
    )?;
    let mut authn = Vec::new();
    if a.client_ca_file.is_some() {
        authn.push(Arc::new(ClientCertificateAuthenticator::default())
            as Arc<dyn kube_rbac_proxy::authn::Authenticator>);
    }
    if let Some(issuer) = &a.oidc_issuer {
        authn.push(Arc::new(OidcAuthenticator::new(
            issuer.clone(),
            a.oidc_client_id.clone().unwrap_or_default(),
            a.oidc_username_claim.clone(),
            a.oidc_username_prefix.clone(),
            a.oidc_groups_claim.clone(),
            a.oidc_groups_prefix.clone(),
            &a.oidc_sign_alg,
            a.oidc_ca_file.as_deref(),
        )?)
            as Arc<dyn kube_rbac_proxy::authn::Authenticator>);
    }
    if let Some(client) = &kube_client {
        authn.push(Arc::new(KubernetesAuthenticator {
            client: client.clone(),
            audiences: a.auth_token_audiences.clone(),
        }) as Arc<dyn kube_rbac_proxy::authn::Authenticator>);
    }
    let authenticators = AuthenticatorChain::new(authn);
    let mut server = Server::new(None)?;
    if let Some(configuration) = Arc::get_mut(&mut server.configuration) {
        configuration.grace_period_seconds = Some(30);
        configuration.graceful_shutdown_timeout_seconds = Some(30);
    }
    server.bootstrap();
    let proxy = pingora_proxy::build_proxy(
        a.upstream.parse()?,
        cfg.authorization,
        a.allow_paths,
        a.ignore_paths,
        a.auth_header_fields_enabled,
        a.auth_header_user_field_name,
        a.auth_header_groups_field_name,
        a.auth_header_groups_field_separator,
        authenticators,
        kube_client,
        a.upstream_timeout,
        a.upstream_force_h2c,
        a.upstream_client_cert_file,
        a.upstream_client_key_file,
        a.upstream_ca_file,
        Arc::new(AtomicU64::new(0)),
        a.http2_max_concurrent_streams,
        a.http2_max_size,
        false,
    );
    let mut service = http_proxy_service(&server.configuration, proxy.clone());
    let tls_resolver: Option<Arc<dyn ResolvesServerCert>> = if a.secure_listen_address.is_some() {
        Some(
            if let (Some(cert), Some(key)) = (&a.tls_cert_file, &a.tls_private_key_file) {
                Arc::new(ReloadingCertificateResolver::new(cert, key))
            } else {
                Arc::new(tls::self_signed_resolver()?)
            },
        )
    } else {
        None
    };
    let client_verifier = if let Some(ca_path) = &a.client_ca_file {
        let mut roots = RootCertStore::empty();
        for certificate in certs(&mut std::io::BufReader::new(std::fs::File::open(ca_path)?)) {
            roots.add(certificate?)?;
        }
        Some(WebPkiClientVerifier::builder(Arc::new(roots)).build()?)
    } else {
        None
    };
    let make_tls = || -> anyhow::Result<pingora::listeners::tls::TlsSettings> {
        let mut tls = pingora::listeners::tls::TlsSettings::with_callbacks(Box::new(
            ClientCertificateCallback,
        ))?;
        tls.set_cert_resolver(Arc::clone(
            tls_resolver
                .as_ref()
                .expect("TLS resolver exists for TLS service"),
        ));
        tls.enable_h2();
        if let Some(verifier) = &client_verifier {
            tls.set_client_cert_verifier(Arc::clone(verifier));
        }
        Ok(tls)
    };
    if let Some(address) = &a.secure_listen_address {
        service.add_tls_with_settings(address, None, make_tls()?);
    }
    if let Some(address) = &a.insecure_listen_address {
        service.add_tcp(address);
    }
    server.add_service(service);
    if a.proxy_endpoints_port != 0 {
        let mut operational_proxy = proxy;
        operational_proxy.operational_endpoints = true;
        let mut operational = http_proxy_service(&server.configuration, operational_proxy);
        if let Some(address) = &a.secure_listen_address {
            let host = address
                .rsplit_once(':')
                .map(|(host, _)| host)
                .unwrap_or(address);
            operational.add_tls_with_settings(
                &format!("{host}:{}", a.proxy_endpoints_port),
                None,
                make_tls()?,
            );
        }
        server.add_service(operational);
    }
    server.run_forever();
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Args {
        let mut values = vec!["kube-rbac-proxy", "--upstream", "http://127.0.0.1:8080"];
        values.extend_from_slice(args);
        Args::try_parse_from(values).unwrap()
    }

    #[test]
    fn minimal_configuration_is_valid() {
        assert!(parse(&[]).validate().is_err());
        assert!(parse(&["--secure-listen-address", "127.0.0.1:8443"])
            .validate()
            .is_ok());
        assert!(parse(&[
            "--insecure-listen-address",
            "127.0.0.1:8080",
            "--proxy-endpoints-port",
            "8081",
        ])
        .validate()
        .is_err());
    }

    #[test]
    fn allow_and_ignore_paths_are_mutually_exclusive() {
        let args = parse(&["--allow-paths", "/metrics", "--ignore-paths", "/healthz"]);
        assert!(args
            .validate()
            .unwrap_err()
            .to_string()
            .contains("allow-paths"));
    }

    #[test]
    fn certificate_pairs_are_required() {
        let args = parse(&["--tls-cert-file", "server.crt"]);
        assert!(args
            .validate()
            .unwrap_err()
            .to_string()
            .contains("tls-private-key-file"));
        let args = parse(&["--upstream-client-key-file", "client.key"]);
        assert!(args
            .validate()
            .unwrap_err()
            .to_string()
            .contains("upstream-client-cert-file"));
    }

    #[test]
    fn oidc_requires_https_issuer_and_client_id() {
        let args = parse(&["--oidc-issuer", "http://issuer.example"]);
        assert!(args
            .validate()
            .unwrap_err()
            .to_string()
            .contains("oidc-clientID"));
        let args = parse(&[
            "--oidc-issuer",
            "http://issuer.example",
            "--oidc-clientID",
            "client",
        ]);
        assert!(args.validate().unwrap_err().to_string().contains("HTTPS"));
    }

    #[test]
    fn h2c_and_api_rate_limits_are_validated() {
        let args = Args::try_parse_from([
            "kube-rbac-proxy",
            "--upstream",
            "h2c://127.0.0.1:9000",
            "--upstream-force-h2c",
            "--secure-listen-address",
            "127.0.0.1:8443",
        ])
        .unwrap();
        assert!(args.validate().is_ok());
        let args = parse(&["--kube-api-qps", "5"]);
        assert!(args
            .validate()
            .unwrap_err()
            .to_string()
            .contains("kube-api-burst"));
        assert!(Args::try_parse_from([
            "kube-rbac-proxy",
            "--upstream",
            "http://localhost",
            "--upstream-timeout",
            "not-a-duration"
        ])
        .is_err());
    }

    #[test]
    fn help_and_version_flags_are_registered() {
        assert!(Args::try_parse_from(["kube-rbac-proxy", "--help"]).is_err());
        assert!(Args::try_parse_from(["kube-rbac-proxy", "--version"]).is_err());
    }

    #[test]
    fn tls_client_ca_and_version_are_validated() {
        let mut args =
            Args::try_parse_from(["proxy", "--upstream", "http://localhost:8080"]).unwrap();
        args.client_ca_file = Some("ca.pem".into());
        assert!(args.validate().is_err());
        args.client_ca_file = None;
        args.tls_min_version = "VersionTLS11".into();
        assert!(args.validate().is_err());
        args.tls_min_version = "VersionTLS12".into();
        args.tls_cipher_suites = vec!["not-a-cipher".into()];
        assert!(args.validate().is_err());
    }
}
