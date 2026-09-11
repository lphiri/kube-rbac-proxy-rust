# Security notes

- Authentication comes from Kubernetes TokenReview, configured OIDC, or a
  verified client certificate. Identity headers supplied by callers are not
  trusted.
- TLS certificate and minimum-version/cipher settings are applied before the
  listener is created. Use configured certificates and a client CA for
  production mTLS deployments.
- Bearer tokens, client credentials, and Kubernetes review payloads are not
  written to access logs. Avoid enabling verbose application logging in a
  shared environment without reviewing its output.
- The proxy deliberately permits administrator-selected upstream URLs. This
  is an SSRF-capable feature by design; restrict configuration writers and use
  network policy to limit reachable destinations.
- OIDC issuer and custom CA configuration should be treated as trusted
  administrative input. Keep issuer endpoints and signing-key refresh traffic
  on the intended network.

Report suspected vulnerabilities privately to the repository maintainers
before opening a public issue.

The release audit (`cargo audit`) reports no known vulnerabilities. It reports
two unmaintained transitive crates: `derivative` from Pingora and
`rustls-pemfile` from the TLS dependency graph. They are not direct
application dependencies; upgrading them is tracked with the corresponding
upstream projects.
