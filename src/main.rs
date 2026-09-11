use anyhow::Result;
use clap::Parser;
use kube_rbac_proxy::{config, pingora_proxy};
use pingora::prelude::*;

#[derive(Parser, Debug)]
#[command(
    name = "kube-rbac-proxy",
    about = "A small HTTP proxy with Kubernetes-style RBAC authorization"
)]
struct Args {
    #[arg(long)]
    upstream: String,
    #[arg(long, default_value = "0.0.0.0:8443")]
    secure_listen_address: String,
    #[arg(long)]
    config_file: Option<String>,
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
}
fn main() -> Result<()> {
    let a = Args::parse();
    if !a.allow_paths.is_empty() && !a.ignore_paths.is_empty() {
        anyhow::bail!("--allow-paths cannot be used with --ignore-paths");
    }
    let cfg = a
        .config_file
        .map(|p| config::load(&p))
        .transpose()?
        .unwrap_or_default();
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
    );
    let mut service = http_proxy_service(&server.configuration, proxy);
    service.add_tcp(&a.secure_listen_address);
    server.add_service(service);
    server.run_forever();
}
