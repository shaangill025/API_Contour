FROM rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY collectors/nodered/live-integration/manifest.json collectors/nodered/live-integration/manifest.json
COPY collectors/nodered/receiver-integration/manifest-504.json collectors/nodered/receiver-integration/manifest-504.json
COPY collectors/nodered/receiver-integration/artifact-504.json collectors/nodered/receiver-integration/artifact-504.json
RUN cargo build --release --locked -p contour-ingress --example causal_factory_collector
RUN mkdir /runtime-libs && cp /usr/lib/*-linux-gnu/libssl.so.3 /usr/lib/*-linux-gnu/libcrypto.so.3 /runtime-libs/
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
COPY --from=build /runtime-libs/ /usr/local/lib/
COPY --from=build /src/target/release/examples/causal_factory_collector /usr/local/bin/causal_factory_collector
ENV LD_LIBRARY_PATH=/usr/local/lib
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/causal_factory_collector", "/fixture/collector.json"]
