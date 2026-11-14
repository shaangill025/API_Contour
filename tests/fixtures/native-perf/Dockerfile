# Fixture-only image; build under a unique owned tag.
# Image digests pin the multi-platform manifests used by this local build.
FROM node:22.23.5-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run build

FROM rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY collectors/nodered/live-integration/manifest.json collectors/nodered/live-integration/manifest.json
COPY collectors/nodered/receiver-integration/manifest-504.json collectors/nodered/receiver-integration/manifest-504.json
COPY collectors/nodered/receiver-integration/artifact-504.json collectors/nodered/receiver-integration/artifact-504.json
RUN cargo build --release --locked -p contour-platform
RUN cargo build --release --locked -p contour-ingress --bin local_capture
RUN cargo build --release --locked -p contour-ingress --bin local_gateway
RUN cargo build --release --locked -p contour-ingress --example native_perf_paused --example native_perf_online
# native-tls uses OpenSSL on Linux. Keep its shared libraries from the same
# Bookworm builder; the runtime base provides glibc and libgcc.
RUN mkdir /runtime-libs && cp /usr/lib/*-linux-gnu/libssl.so.3 /usr/lib/*-linux-gnu/libcrypto.so.3 /runtime-libs/

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
COPY --from=build /runtime-libs/ /usr/local/lib/
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/target/release/contour-platform /usr/local/bin/contour-platform
COPY --from=build /src/target/release/local_capture /usr/local/bin/local_capture
COPY --from=build /src/target/release/local_gateway /usr/local/bin/local_gateway
COPY --from=build /src/target/release/examples/native_perf_paused /usr/local/bin/native_perf_paused
COPY --from=build /src/target/release/examples/native_perf_online /usr/local/bin/native_perf_online
COPY --from=web /src/web/dist/ /opt/contour/web/
ENV LD_LIBRARY_PATH=/usr/local/lib
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/contour-platform", "/run/config/platform.json", "/run/config/business.json", "/opt/contour/web"]
