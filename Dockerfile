FROM rust:1.85-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/kube-rbac-proxy /usr/local/bin/kube-rbac-proxy
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/kube-rbac-proxy"]
