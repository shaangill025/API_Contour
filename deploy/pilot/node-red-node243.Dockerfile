# REVIEW PROPOSAL ONLY: not referenced by a profile or an active build.
FROM docker.io/library/node:24.22.3-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5 AS patched_node
FROM docker.io/nodered/node-red:5.0.9@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963
COPY --from=patched_node /usr/local/bin/node /usr/local/bin/node
ENV NODE_VERSION=24.22.3
