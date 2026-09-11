# kube-rbac-proxy (Rust)

Rust rebuild of `kube-rbac-proxy` using Cloudflare's Pingora proxy runtime, with YAML-compatible `resourceAttributes`, `rewrites`, `static`, and endpoint-scoped authorization rules, named endpoint captures, and allow/ignore path filters.

Run it with:

```sh
cargo run -- --upstream http://127.0.0.1:8080 --secure-listen-address 127.0.0.1:8443 --config-file ./authorization.yaml
```

The current listener is plain TCP/HTTP despite retaining the upstream flag name for CLI compatibility. Pingora is configured with rustls and supports TLS upstream connections. Identity is supplied through `X-Remote-User` and `X-Remote-Groups`; static authorization is implemented. Kubernetes TokenReview/SubjectAccessReview, OIDC, client certificates, TLS serving configuration, kubeconfig loading, and HTTP/2 tuning remain parity work.

Verify with `cargo test`.

## Development checks

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build
cargo test
```
