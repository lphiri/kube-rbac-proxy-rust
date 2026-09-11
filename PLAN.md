# kube-rbac-proxy Rust parity plan

## Goal

Bring the Rust implementation in `../kube-rbac-proxy-rust` to behavioral parity with the Go implementation in `../kube-rbac-proxy`, while using Pingora for the proxy runtime.

Parity means matching the Go project’s externally visible behavior: CLI flags and validation, configuration format, authentication, authorization, TLS, proxying, operational endpoints, error handling, and test coverage. Rust-specific implementation details may differ.

## Working rules

Each stage below is complete only when its acceptance criteria pass. At that point:

```sh
git add -A
git commit -m "parity: <stage name>"
```

The commit is the checkpoint for that stage. Do not create a checkpoint for a partially implemented or failing stage. Every stage should also preserve all earlier tests.

Because the project currently has no git history, initialize it before implementation:

```sh
git init
git add -A
git commit -m "chore: establish Rust parity baseline"
```

## Baseline inventory

Already present:

- Cargo project and Pingora 0.9 transport integration.
- YAML parsing for the main authorization configuration.
- Format 1 resource/non-resource attributes and rewrites.
- Format 2 endpoint mappings, named captures, and templates.
- Static authorization matching.
- Allow/ignore path filtering in the proxy path.
- 9 authorization unit tests.

Known baseline limitations:

- Listener is plain HTTP/TCP, despite the compatibility flag name.
- Identity is read from `X-Remote-User` and `X-Remote-Groups`.
- No Kubernetes TokenReview or SubjectAccessReview client.
- No OIDC, client-certificate authentication, or production TLS configuration.
- No upstream CA/client-certificate configuration, timeout, or h2c support.
- No health endpoint, metrics, generated CLI help, or end-to-end test harness.

## Stage 0 — Repository and reproducible baseline

Tasks:

- Initialize git and create the baseline checkpoint.
- Pin the Rust toolchain if needed with `rust-toolchain.toml`.
- Keep `Cargo.lock` committed.
- Add formatting, lint, build, and test commands to the README.
- Add a CI workflow that runs `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo build`, and `cargo test`.

Acceptance:

- A clean checkout builds and tests without undocumented local setup.
- CI executes the same checks locally expected by contributors.

Checkpoint: `chore: establish reproducible Rust baseline`

## Stage 1 — Configuration model and CLI parity

Tasks:

- Port every supported Go flag and default from `cmd/kube-rbac-proxy/app/options`.
- Preserve flag names, aliases, defaults, and deprecated compatibility flags where practical.
- Add typed configuration validation with actionable errors.
- Validate required combinations: upstream/listener, certificate/key pairs, client certificate/key pairs, mutually exclusive allow/ignore paths, OIDC issuer/client ID, and TLS settings.
- Support the complete authorization YAML schema, including static rules, rewrites, endpoint mappings, and resource attributes.
- Add version output and generated help verification.
- Add table-driven CLI/config tests corresponding to Go option validation tests.

Acceptance:

- `--help` contains the supported parity flags.
- Valid Go example configurations deserialize successfully.
- Invalid combinations fail before starting the server.
- Configuration tests cover defaults, missing values, malformed YAML, and compatibility behavior.

Checkpoint: `parity: configuration and CLI`

## Stage 2 — Authorization engine parity

Tasks:

- Complete Format 1 behavior, including all HTTP verbs, explicit verb override, query/header rewrite ordering, repeated values, and template errors.
- Complete Format 2 behavior, including exact path cleaning, wildcard semantics, named capture validation, duplicate captures, method matching, and required rewrite values.
- Add authorization config validation equivalent to `ValidateAuthorizationConfig`.
- Preserve resource versus non-resource request distinctions.
- Match Go error classes/status mapping for malformed requests, missing rewrite values, and matched-path method denial.
- Add tests ported from `pkg/authz/endpoints_test.go`, `pkg/authz/auth_test.go`, and `pkg/proxy/proxy_test.go`.

Acceptance:

- Rust unit tests cover every Go authorization test case that does not depend on Kubernetes.
- Attribute records produced by equivalent Go/Rust fixtures are identical.
- Bad configuration and bad requests produce equivalent categories of errors.

Checkpoint: `parity: authorization engine`

## Stage 3 — Authentication abstraction and request pipeline

Tasks:

- Define a Rust authentication trait returning a normalized identity and authentication status.
- Compose multiple authenticators with the same precedence as Go: client certificate, OIDC when configured, and Kubernetes token authentication.
- Remove reliance on untrusted identity headers for authentication; retain those headers only as upstream output fields.
- Implement request pipeline ordering: path bypass, authentication, attribute generation, authorization, upstream header injection, proxying.
- Match 401/403/400/500 behavior and response bodies where externally observable.
- Add unit tests for successful authentication, missing credentials, invalid credentials, auth errors, bypass paths, and header propagation.

Acceptance:

- No request can become authenticated solely by sending `X-Remote-User`.
- Pipeline tests verify ordering and status codes.
- Identity headers are injected only after successful authentication and authorization.

Checkpoint: `parity: authentication pipeline`

## Stage 4 — Kubernetes client, TokenReview, and SubjectAccessReview

Tasks:

- Load in-cluster configuration and kubeconfig files.
- Implement Kubernetes API TLS/auth configuration and QPS/burst settings.
- Implement TokenReview bearer-token authentication with configured audiences.
- Implement SubjectAccessReview authorization for every generated attribute.
- Port Go authorizer caching behavior: allow cache, deny cache, retries, and webhook failure handling.
- Preserve static authorization as a fast local allow path before SAR.
- Add fake Kubernetes API tests for accepted/rejected tokens, audiences, SAR allow/deny, API failures, retries, and multiple attributes.

Acceptance:

- A real Kubernetes service-account token can authenticate through TokenReview.
- SAR decisions control access correctly.
- Multiple generated attributes require all checks to allow.
- Kubernetes client failures map to the expected server errors.

Checkpoint: `parity: Kubernetes authentication and authorization`

## Stage 5 — OIDC authentication

Tasks:

- Discover issuer metadata and signing keys.
- Validate issuer, audience/client ID, expiry, signing algorithm, and signature.
- Support configurable username/groups claims and prefixes.
- Support a custom OIDC CA bundle.
- Refresh discovery/JWKS data and handle key rotation.
- Port the Go OIDC tests with deterministic local issuer/JWKS fixtures.

Acceptance:

- Valid OIDC tokens produce the expected identity.
- Invalid issuer, audience, signature, algorithm, expiry, and claims are rejected.
- Key rotation and issuer/network failures behave predictably.

Checkpoint: `parity: OIDC authentication`

## Stage 6 — Client certificate authentication

Tasks:

- Add TLS listener client-certificate request/verification support.
- Load and validate the configured client CA bundle.
- Map the certificate Common Name to the authenticated username.
- Match Go behavior when certificates are absent, invalid, or signed by an unknown CA.
- Add generated-certificate integration tests for valid and invalid chains.

Acceptance:

- Valid client certificates authenticate with the expected identity.
- Invalid certificates cannot reach the upstream.
- Certificate-authenticated requests can be authorized by static rules and SAR.

Checkpoint: `parity: client certificate authentication`

## Stage 7 — TLS listener and certificate lifecycle

Tasks:

- Configure Pingora’s TLS listener with certificate/key files.
- Support minimum TLS version and cipher configuration.
- Support HTTP/1.1 and HTTP/2 negotiation.
- Implement certificate reload behavior equivalent to the Go reloader.
- Support the secure proxy endpoint listener and cloned TLS configuration.
- Add TLS handshake, protocol, invalid configuration, and reload tests.

Acceptance:

- The default listener is securely served when certificate flags are supplied.
- TLS 1.2/1.3 and configured cipher restrictions are enforced.
- Replacing certificate files takes effect without process restart.
- HTTP/2 clients can connect when enabled.

Checkpoint: `parity: TLS listener and reload`

## Stage 8 — Upstream transport parity

Tasks:

- Parse upstream URL schemes and ports exactly.
- Configure upstream CA bundles and system trust behavior.
- Support upstream client certificate/key authentication.
- Apply upstream response/request timeouts.
- Support forced h2c for cleartext HTTP/2 upstreams.
- Preserve request paths, query strings, methods, bodies, and relevant headers.
- Match hop-by-hop header sanitization and upstream error handling.
- Add HTTP/1, HTTPS, mTLS, timeout, h2c, and streaming-body integration tests.

Acceptance:

- HTTP and HTTPS upstreams work with configured trust and client credentials.
- Timeout and connection failures return the expected gateway errors.
- h2c and HTTP/2 upstreams work with representative clients.
- Request/response behavior matches Go transport tests.

Checkpoint: `parity: upstream transport`

## Stage 9 — Pingora runtime and operational endpoints

Tasks:

- Configure Pingora worker count, graceful shutdown, connection reuse, and request limits.
- Add `/healthz` on the configured proxy endpoint port.
- Add metrics and access logging consistent with the Go implementation’s operational expectations.
- Add sanitized logging for credentials and Kubernetes review objects.
- Implement request size, stream, and HTTP/2 settings.
- Verify signal handling and graceful drain behavior.

Acceptance:

- Health checks do not require application authorization.
- Shutdown drains active requests and stops accepting new ones.
- Sensitive bearer tokens, client data, and review payloads are not logged.
- Operational endpoints and metrics are isolated from the protected upstream.

Checkpoint: `parity: runtime operations`

## Stage 10 — Integration and end-to-end parity

Tasks:

- Build a local fake Kubernetes API server for deterministic integration tests.
- Add upstream test servers for HTTP, HTTPS, h2c, HTTP/2, mTLS, slow responses, and streaming.
- Port the Go filter/auth/transport integration tests.
- Add a kind-based end-to-end suite for TokenReview, SAR, RBAC, OIDC, and client certificates.
- Port representative examples from `examples/` and verify their deployment manifests/configuration.

Acceptance:

- Unit, integration, and kind-based end-to-end suites pass.
- Example scenarios have equivalent allow/deny behavior in Go and Rust.
- Failure behavior is documented and intentional.

Checkpoint: `parity: integration and end-to-end tests`

## Stage 11 — Packaging, compatibility, and release readiness

Tasks:

- Add production Dockerfiles and non-root runtime packaging.
- Add cross-compilation targets and reproducible release builds.
- Port version/build metadata and container labels.
- Update README, examples, changelog, and migration notes.
- Add security review for header trust, TLS defaults, token handling, SSRF/upstream parsing, and log redaction.
- Run dependency audits and clippy with warnings denied.

Acceptance:

- Release image starts with a non-root user and has no unnecessary tools.
- Supported architectures build successfully.
- Security checks and all test tiers pass in CI.
- The Rust binary can replace the Go binary for documented supported scenarios.

Checkpoint: `release: Rust feature parity`

## Final parity matrix

Before declaring parity complete, maintain a matrix mapping every Go feature, flag, test, example, and operational behavior to:

1. Rust implementation location.
2. Rust test location.
3. Any intentional difference.
4. The checkpoint commit that introduced it.

The final release checkpoint should not be created until every unimplemented item is either completed or explicitly documented as an intentional incompatibility.
