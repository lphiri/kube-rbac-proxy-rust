# kube-rbac-proxy (Rust)

Rust rebuild of `kube-rbac-proxy` using Cloudflare's Pingora proxy runtime, with YAML-compatible `resourceAttributes`, `rewrites`, `static`, and endpoint-scoped authorization rules, named endpoint captures, and allow/ignore path filters.

Run it with:

```sh
cargo run -- --upstream http://127.0.0.1:8080 --secure-listen-address 127.0.0.1:8443 --config-file ./authorization.yaml
```

The runtime uses Pingora with rustls. It supports Kubernetes TokenReview/SubjectAccessReview, OIDC discovery/JWKS authentication, client-CA TLS authentication, TLS serving, kubeconfig loading, upstream timeouts, h2c, and upstream mTLS. Static and Kubernetes authorization are evaluated before upstream forwarding; identity headers are injected only after successful authentication and authorization.

Verify with `cargo test`.

## Development checks

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build
cargo test
```

Build the non-root container image with `docker build -t kube-rbac-proxy-rust .`.

Run the disposable in-cluster authorization smoke test with `tests/e2e/kind.sh`.
It creates and removes only the `kube-rbac-proxy-rust-e2e` Kind cluster.

The completion audit is tracked in `PARITY_MATRIX.md`; `PLAN.md` records the
original staged requirements. Protocol harnesses cover HTTPS, h2c, upstream and
downstream HTTP/2, mTLS, and streaming responses. OIDC behavior is covered with
a deterministic local issuer/JWKS fixture so the Kind smoke test does not depend
on an external identity provider.
