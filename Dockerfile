# syntax=docker/dockerfile:1.9
#
# Multi-stage build for the `nosfry` Nostr relay.
#
# * Stage 1 (`chef`)    -- pin cargo-chef, the dependency-graph caching tool.
# * Stage 2 (`planner`) -- emit recipe.json describing the dep graph only.
# * Stage 3 (`builder`) -- cook deps from the recipe, then compile the bin.
# * Stage 4 (`runtime`) -- distroless runtime image, non-root.
#
# Multi-arch: the base images are multi-arch out of the box.

# The Rust tag must track rust-toolchain.toml: that file is excluded via
# .dockerignore, so the image's Rust base pins the compiler instead of
# rustup downloading a toolchain during the build. Dependabot's docker
# ecosystem bumps the tag and digest together.
FROM rust:1.99-slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be AS chef
ENV CARGO_TERM_COLOR=always
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      pkg-config build-essential ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked --version 0.1.78
WORKDIR /src

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /src/recipe.json recipe.json
# Cook deps once; rebuilds reuse this layer until the dep graph changes.
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN mkdir /data \
 && cargo build --release --locked -p nosfry

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime
LABEL org.opencontainers.image.title="nosfry" \
      org.opencontainers.image.description="High-performance Nostr relay" \
      org.opencontainers.image.source="https://github.com/qntx/nosfry" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

COPY --from=builder /src/target/release/nosfry /nosfry
COPY docker/nosfry.toml /etc/nosfry/nosfry.toml
COPY --from=builder --chown=nonroot:nonroot /data /data

ENV NOSFRY_CONFIG=/etc/nosfry/nosfry.toml \
    RUST_LOG=info

# LMDB data must never live in the container's writable layer.
VOLUME ["/data"]
WORKDIR /data

EXPOSE 7777
USER nonroot:nonroot

ENTRYPOINT ["/nosfry"]
CMD ["relay"]
