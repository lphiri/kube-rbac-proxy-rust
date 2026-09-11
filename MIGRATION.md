# Migration from Go kube-rbac-proxy

The Rust binary keeps the authorization YAML schema and compatible flag names
for the supported proxy behavior. Replace the Go image with the Rust image and
mount the same authorization file, then review these operational differences:

- At least one of `--secure-listen-address` or the deprecated
  `--insecure-listen-address` is required. The secure listener is TLS and uses
  a generated self-signed certificate only when certificate files are omitted;
  production deployments should configure a certificate and key explicitly.
- `--proxy-endpoints-port` serves HTTPS when the secure listener is selected,
  including `/healthz` and `/metrics`. Probe it with the appropriate CA or
  `curl --insecure` only for a disposable self-signed deployment.
- Client certificate authentication maps the verified certificate Common Name
  to the username. A supplied `X-Remote-User` header is never an authentication
  credential and is overwritten only after successful authorization.
- Upstream URLs support `http`, `https`, and forced `h2c`. Upstream custom CA,
  client certificate, timeout, and HTTP/2 settings are configured with the
  corresponding Rust flags shown by `--help`.

The Rust implementation uses Pingora for connection handling and rustls for
TLS. Access logs redact authorization credentials and do not include review
request bodies.
