# Image digests pin the multi-platform manifests used by this local build.
FROM node:22.23.1-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run build

FROM rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN cargo build --release --locked -p contour-platform
# native-tls uses OpenSSL on Linux. Keep its shared libraries from the same
# Bookworm builder; the runtime base provides glibc and libgcc.
RUN mkdir /runtime-libs && cp /usr/lib/*-linux-gnu/libssl.so.3 /usr/lib/*-linux-gnu/libcrypto.so.3 /runtime-libs/

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
COPY --from=build /runtime-libs/ /usr/local/lib/
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/target/release/contour-platform /usr/local/bin/contour-platform
COPY --from=web /src/web/dist/ /opt/contour/web/
ENV LD_LIBRARY_PATH=/usr/local/lib
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/contour-platform", "/run/config/platform.json", "/run/config/business.json", "/opt/contour/web"]
