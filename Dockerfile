FROM rust:1.88-bookworm AS build
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake g++ pkg-config \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/kube-rbac-proxy /usr/local/bin/kube-rbac-proxy
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/kube-rbac-proxy"]
