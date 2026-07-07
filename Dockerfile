# syntax=docker/dockerfile:1
#
# Container image for the stelyph PDS server. Multi-stage: a Rust builder that
# compiles the `stelyph` binary, then a slim Debian runtime that carries just the
# binary + CA roots. Build for the host arch (arm64 on an Apple-Silicon Mac
# Studio / OrbStack Linux VM).
#
# The build stage needs cmake + perl + a C toolchain because the server's TLS
# stack pulls `aws-lc-sys` (and `ring`), and `rusqlite` compiles a bundled SQLite.

# ---- builder ---------------------------------------------------------------
FROM rust:1-bookworm AS builder

# aws-lc-sys → cmake; ring/aws-lc → C compiler (in buildpack-deps already);
# perl is present via the rust image but pin it explicitly to be safe.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# Release build of just the server binary (and its path-dep stelyph-core).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release -p stelyph --bin stelyph \
    && cp target/release/stelyph /usr/local/bin/stelyph

# ---- runtime ---------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# ca-certificates: TLS roots for outbound HTTPS to plc.directory / relay / appview.
# (reqwest is built with rustls + webpki-roots so this is belt-and-suspenders.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /data stelyph

COPY --from=builder /usr/local/bin/stelyph /usr/local/bin/stelyph

# Persistent state lives on a mounted volume; never bake the DB into the image.
ENV PDS_DB_PATH=/data/pds.db \
    PDS_PORT=3000 \
    PDS_MODE=proxy
# proxy mode = serve plain HTTP on PDS_PORT; TLS is terminated upstream by
# Coolify's Traefik (or a Cloudflare/Tailscale tunnel), not by the app.

RUN mkdir -p /data && chown stelyph:stelyph /data
VOLUME ["/data"]
USER stelyph
EXPOSE 3000

ENTRYPOINT ["stelyph"]
CMD ["serve"]
