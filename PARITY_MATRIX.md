# Rust parity matrix

This matrix is the completion audit for `PLAN.md`. A row is complete only when
the implementation and its relevant tests both exist.

| Go behavior | Rust implementation | Rust evidence | Checkpoint | Status |
|---|---|---|---|---|
| CLI flags and validation | `src/main.rs` | CLI unit tests | `6bf76d3` | Implemented |
| Authorization formats 1 and 2 | `src/authorization.rs` | authorization unit tests | `048cfec` | Implemented |
| Authentication chain | `src/authn.rs`, `src/pingora_proxy.rs` | authentication tests | `2beda35` | Implemented |
| TokenReview and SAR | `src/kube.rs` | wiremock API tests | `820c6f0` | Implemented |
| OIDC discovery, JWKS, claims | `src/oidc.rs` | local issuer test | `8ba5381` | Implemented |
| Client CA verification and CN mapping | `src/cert_auth.rs`, `src/main.rs` | callback and fixture tests | `1886ec2` | Implemented |
| TLS serving and certificate reload | `src/tls.rs`, `src/main.rs` | PEM resolver tests | `3091db4` | Implemented |
| Upstream CA, mTLS, timeout, h2c | `src/pingora_proxy.rs` | compile/config tests | `bcabeab`, `23cb782` | Implemented; protocol E2E pending |
| Operational port and health endpoint | `src/main.rs`, `src/pingora_proxy.rs` | isolation implementation | `a60c070` | Implemented; live listener E2E pending |
| Metrics and sanitized access logging | `src/pingora_proxy.rs` | runtime implementation | `765312e`, `af33bbf` | Implemented |
| Graceful drain and HTTP/2 limits | `src/main.rs`, `src/pingora_proxy.rs` | build/test gate | `d632225`, `9c5cb81` | Implemented |
| Production container | `Dockerfile` | locked release build | `a9b7859` | Implemented; image execution pending |
| TLS cipher/min-version selection | Pingora 0.9 `TlsSettings` limitation | validation only | `0a52839` | Gap: listener selection not exposed |
| HTTPS, h2c, HTTP/2, mTLS, streaming E2E | Planned integration harness | none yet | — | Pending |
| Kind TokenReview/SAR/RBAC/OIDC/client-cert E2E | Planned Kind harness | none yet | — | Pending |
