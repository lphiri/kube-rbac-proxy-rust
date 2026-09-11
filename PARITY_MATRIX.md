# Rust parity matrix

This matrix is the completion audit for `PLAN.md`. A row is complete only when
the implementation and its relevant tests both exist.

| Go behavior | Rust implementation | Rust evidence | Checkpoint | Status |
|---|---|---|---|---|
| CLI flags and validation | `src/main.rs` | CLI unit tests | `6bf76d3` | Implemented |
| Authorization formats 1 and 2 | `src/authorization.rs` | authorization unit tests | `048cfec` | Implemented |
| Authentication chain | `src/authn.rs`, `src/pingora_proxy.rs` | authentication tests | `2beda35` | Implemented |
| TokenReview and SAR | `src/kube.rs` | wiremock API tests plus live Kind API calls (including PEM CA and 2xx responses) | next checkpoint | Implemented |
| OIDC discovery, JWKS, claims | `src/oidc.rs` | local issuer test | `8ba5381` | Implemented |
| Client CA verification and CN mapping | `src/cert_auth.rs`, `src/main.rs` | callback and fixture tests | `1886ec2` | Implemented |
| TLS serving and certificate reload | `src/tls.rs`, `src/main.rs` | PEM resolver tests | `3091db4` | Implemented |
| Upstream CA, mTLS, timeout, h2c | `src/pingora_proxy.rs` | compile/config tests | `bcabeab`, `23cb782` | Implemented; protocol E2E pending |
| Operational port and health endpoint | `src/main.rs`, `src/pingora_proxy.rs` | isolated Kind listener probe | next checkpoint | Implemented |
| Metrics and sanitized access logging | `src/pingora_proxy.rs` | runtime implementation | `765312e`, `af33bbf` | Implemented |
| Graceful drain and HTTP/2 limits | `src/main.rs`, `src/pingora_proxy.rs` | build/test gate | `d632225`, `9c5cb81` | Implemented |
| Production container | `Dockerfile` | locked release build and non-root image inspection | next checkpoint | Implemented |
| TLS cipher/min-version selection | Pingora 0.9 `TlsSettings` limitation | validation only | `0a52839` | Gap: listener selection not exposed |
| HTTPS, h2c, HTTP/2, mTLS, streaming E2E | Planned integration harness | no protocol matrix yet | — | Pending |
| Kind TokenReview/SAR/RBAC/OIDC/client-cert E2E | `tests/e2e/kind.sh` | live TokenReview/SAR/RBAC, forwarding, 401, healthz, metrics | next checkpoint | Partial: OIDC and client-cert scenarios pending |
