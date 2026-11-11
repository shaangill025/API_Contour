FROM rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY collectors/nodered/live-integration/manifest.json collectors/nodered/live-integration/manifest.json
RUN cargo build --release --locked -p contour-ingress --example origin_https_probe --example origin_sensor_probe
RUN cargo build --release --locked -p contour-postgres --example catalog_probe
RUN mkdir /runtime-libs && cp /usr/lib/*-linux-gnu/libssl.so.3 /usr/lib/*-linux-gnu/libcrypto.so.3 /runtime-libs/
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
ARG SOURCE_HEAD
LABEL org.apicontour.fixture.source=$SOURCE_HEAD
COPY --from=build /runtime-libs/ /usr/local/lib/
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/target/release/examples/catalog_probe /usr/local/bin/catalog_probe
COPY --from=build /src/target/release/examples/origin_https_probe /usr/local/bin/origin_https_probe
COPY --from=build /src/target/release/examples/origin_sensor_probe /usr/local/bin/origin_sensor_probe
ENV LD_LIBRARY_PATH=/usr/local/lib
USER 65534:65534
