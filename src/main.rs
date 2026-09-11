use anyhow::Result;
use clap::Parser;
use kube_rbac_proxy::{
    authn::AuthenticatorChain,
    config,
    kube::{KubernetesAuthenticator, KubernetesClient},
    oidc::OidcAuthenticator,
    pingora_proxy,
};
use pingora::prelude::*;
use std::sync::Arc;
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
    #[arg(long, default_value = "0.0.0.0:8443")]
    secure_listen_address: String,
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
        if self.proxy_endpoints_port == 0 && self.insecure_listen_address.is_some() {
            anyhow::bail!("--insecure-listen-address is deprecated and cannot be used without --proxy-endpoints-port");
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    let a = Args::parse();
    a.validate()?;
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
    );
    let mut service = http_proxy_service(&server.configuration, proxy);
    service.add_tcp(&a.secure_listen_address);
    server.add_service(service);
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
        assert!(parse(&[]).validate().is_ok());
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
}
