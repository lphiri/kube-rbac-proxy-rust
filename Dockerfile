ARG VERSION=0.1.0

FROM rust:1.88-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS build
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake g++ pkg-config \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
ARG VERSION
COPY --from=build /src/target/release/kube-rbac-proxy /usr/local/bin/kube-rbac-proxy
USER nonroot:nonroot
LABEL org.opencontainers.image.title="kube-rbac-proxy-rust" \
      org.opencontainers.image.description="Kubernetes RBAC authorization proxy implemented with Rust and Pingora" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.licenses="Apache-2.0"
ENTRYPOINT ["/usr/local/bin/kube-rbac-proxy"]
