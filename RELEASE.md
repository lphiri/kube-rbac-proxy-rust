# Release checklist

The release image is reproducible from the committed toolchain, lockfile, and
pinned Docker base-image digests:

```sh
docker build --build-arg VERSION=0.1.0 -t kube-rbac-proxy-rust:0.1.0 .
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo build --locked
cargo test --locked
cargo audit
```

The verified container target is Linux `amd64`; the image is distroless and
runs as `nonroot:nonroot`. The Rust checks are architecture-independent, while
additional container architectures should be built with the matching pinned
Rust builder target and separately validated before publication.

Before publishing, run all scripts in `tests/e2e/` and inspect the final image
labels for the release version.
