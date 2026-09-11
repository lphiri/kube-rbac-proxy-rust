# Examples

These snippets are intentionally small and can be mounted as the
`--config-file` passed to the Rust binary.

`authorization.yaml` is the same top-level configuration shape used by the
Go implementation. Authentication is performed by Kubernetes TokenReview,
OIDC, or a client certificate; static rules authorize an already authenticated
identity and do not make `X-Remote-User` a trusted credential.

The Rust listener is TLS when `--secure-listen-address` is used. For local
development without certificate files it generates a self-signed certificate;
production deployments should provide `--tls-cert-file` and
`--tls-private-key-file` (and normally a client CA when using mTLS).
