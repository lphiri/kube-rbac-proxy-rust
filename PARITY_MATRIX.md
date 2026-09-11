# Rust parity matrix

This matrix is the completion audit for `PLAN.md`. A row is complete only when
the implementation and its relevant tests both exist.

| Go behavior | Rust implementation | Rust evidence | Checkpoint | Status |
|---|---|---|---|---|
| CLI flags and validation | `src/main.rs` | CLI unit tests | `6bf76d3` | Implemented |
| Authorization formats 1 and 2 | `src/authorization.rs` | authorization unit tests | `048cfec` | Implemented |
| Authentication chain | `src/authn.rs`, `src/pingora_proxy.rs` | authentication tests | `2beda35` | Implemented |
| TokenReview and SAR | `src/kube.rs` | wiremock API tests plus live Kind API calls (including PEM CA and 2xx responses) | `0bd4eb5` | Implemented |
| OIDC discovery, JWKS, claims | `src/oidc.rs` | local issuer test | `8ba5381` | Implemented |
| Client CA verification and CN mapping | `src/cert_auth.rs`, `src/main.rs` | callback and fixture tests | `1886ec2` | Implemented |
| TLS serving and certificate reload | `src/tls.rs`, `src/main.rs` | PEM resolver tests | `3091db4` | Implemented |
| Upstream CA, mTLS, timeout, h2c | `src/pingora_proxy.rs` | `tests/e2e/https-upstream.sh`, `tests/e2e/h2c.sh`, `tests/e2e/upstream-http2.sh` | `2440019`, `458ba90`, `c526395`, `43da592`, `8cc3d76` | Implemented |
| Operational port and health endpoint | `src/main.rs`, `src/pingora_proxy.rs` | isolated Kind and local TLS listener probes | `09f59e8` | Implemented |
| Metrics and sanitized access logging | `src/pingora_proxy.rs` | runtime implementation | `765312e`, `af33bbf` | Implemented |
| Graceful drain and HTTP/2 limits | `src/main.rs`, `src/pingora_proxy.rs` | build/test gate | `d632225`, `9c5cb81` | Implemented |
| Production container | `Dockerfile` | locked release build, pinned base images, labels, and non-root image inspection | `b685350` | Implemented |
| TLS cipher/min-version selection | `src/tls.rs` rustls provider filtering before Pingora listener construction | provider unit tests and live generated self-signed listener handshake | `7eaf555` | Implemented for TLS 1.3 minimum and supported cipher suites |
| HTTPS, h2c, HTTP/2, mTLS, streaming E2E | `tests/e2e/*.sh` | HTTPS/custom CA, upstream mTLS, streaming, downstream HTTP/2, upstream HTTP/2, and h2c harnesses | `2440019`, `458ba90`, `c526395`, `43da592`, `338bcb4`, `8cc3d76` | Implemented |
| Kind TokenReview/SAR/RBAC/OIDC/client-cert E2E | `tests/e2e/kind.sh`, `tests/e2e/client-cert.sh`, `src/oidc.rs` | live TokenReview/SAR/RBAC plus local client-cert and deterministic OIDC issuer/JWKS coverage | `0bd4eb5`, `5f4bacc`, `8ba5381` | Implemented; external OIDC provider is intentionally not required for the disposable Kind test |
