# Stelyph

[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![CI](https://github.com/spirallex/stelyph/actions/workflows/ci.yml/badge.svg)](https://github.com/spirallex/stelyph/actions/workflows/ci.yml)

> A single static binary AT Protocol PDS — self-hosted Bluesky federation.
> No Docker. No Node. No bundled proxy. One binary, two commands.

## Install

```sh
# Pre-built static musl binary (Linux x86_64 / aarch64, no toolchain needed):
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/spirallex/stelyph/releases/latest/download/stelyph-installer.sh | sh

# Or build from source (Rust toolchain required):
git clone https://github.com/spirallex/stelyph && cd stelyph
cargo install --path rust-pds
```

The musl binaries are fully static — no glibc, no system SQLite, no runtime dependencies.

Every release artifact carries a [Sigstore build-provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
proving it was built by this repository's CI:

```sh
gh attestation verify stelyph-x86_64-unknown-linux-musl.tar.gz --repo spirallex/stelyph
```

## Quickstart

```sh
stelyph init
```

The wizard walks through:

1. DNS check for your domain
2. did:plc registration
3. First account creation (prompts for an admin password and a key passphrase)
4. `requestCrawl` to connect your PDS to the live relay

It detects your network (public `:443` vs. behind a proxy/tunnel) and writes the
recommended mode to `rust-pds.toml`. It also generates a `PDS_JWT_SECRET` and
prints it **once** — save it now; secrets are deliberately never written to the
config file.

Then run the server with the two secrets from `init`:

```sh
export PDS_JWT_SECRET=...        # printed once by `stelyph init`
export PDS_KEY_PASSPHRASE=...    # the passphrase you chose during `init`
stelyph serve
```

Your first signed commit appears on the Bluesky firehose moments later.

`serve` runs in **proxy mode** by default (plain HTTP behind your reverse proxy or
tunnel). On a host with a bindable public `:443`, pass `--mode standalone` for
built-in TLS via rustls + ACME (Let's Encrypt; `--acme staging` to rehearse).

## Behind a tunnel (no public IP)

On a home network, mobile connection, or behind CGNAT you usually have no bindable public
`:443`, so standalone ACME can't work. Run Stelyph in **proxy mode** and put a tunnel in front —
the tunnel terminates TLS and forwards to Stelyph on localhost. WebSocket upgrade (the firehose)
and `Host` passthrough both work over the tunnel.

Pick any local port with `--port` (default `3000`); the tunnel must forward to that **same**
port. The examples below use `8080`.

**Cloudflare Tunnel** (`cloudflared`) — or use the interactive helper
[`scripts/setup-cloudflare-tunnel.sh`](scripts/setup-cloudflare-tunnel.sh):

```sh
stelyph serve --mode proxy --port 8080     # Stelyph listens on :8080; Cloudflare terminates TLS
cloudflared tunnel login
cloudflared tunnel create stelyph
cloudflared tunnel route dns stelyph pds.example.com
```

Then point the tunnel at Stelyph (`~/.cloudflared/config.yml`):

```yaml
tunnel: <TUNNEL_ID>
credentials-file: /root/.cloudflared/<TUNNEL_ID>.json
ingress:
  - hostname: pds.example.com
    service: http://localhost:8080         # must match --port; ws upgrade + Host passthrough handled by cloudflared
  - service: http_status:404
```

```sh
cloudflared tunnel run stelyph
```

**Tailscale Funnel** (expose to the public internet over your tailnet):

```sh
stelyph serve --mode proxy --port 8080
tailscale funnel 8080                       # serves https://<machine>.<tailnet>.ts.net → :8080
```

In both cases set your handle/DID to the tunnel hostname (e.g. `pds.example.com` or the
`*.ts.net` name) when you run `stelyph init`.

## Configuration

`stelyph init` persists non-secret settings to `rust-pds.toml` (override the path with
`--config` / `PDS_CONFIG`). Everything is also settable per-run; precedence is
flag > env > config file > default.

| Env | Default | Purpose |
|---|---|---|
| `PDS_HOSTNAME` | — (required) | Public hostname; also the account-handle suffix |
| `PDS_JWT_SECRET` | — (required, ≥32 bytes) | Session token signing secret — never stored in config |
| `PDS_KEY_PASSPHRASE` | — (required) | Decrypts the signing keys at rest — never stored in config |
| `PDS_MODE` | `proxy` | `proxy` (plain HTTP) or `standalone` (rustls + ACME on `:443`) |
| `PDS_PORT` | `3000` | Listen port in proxy mode |
| `PDS_DB_PATH` | `./pds.db` | SQLite database (the whole PDS state is this one file) |
| `PDS_ACME_ENV` | `production` | `staging` to rehearse against Let's Encrypt staging |
| `PDS_RELAY_URL` | `https://bsky.network` | Relay to `requestCrawl` |
| `PDS_PLC_URL` | `https://plc.directory` | PLC directory |
| `PDS_APPVIEW_URL` | `https://api.bsky.app` | AppView for proxied `app.bsky.*` reads |
| `PDS_APPVIEW_DID` | `did:web:api.bsky.app` | AppView service DID |

## Running a multi-user PDS

Registration is **invite-gated by default**. Local admin commands operate directly on
the database file — there is no privileged network surface:

```sh
stelyph admin create-invite            # mint an invite code (--uses N for multi-use)
stelyph admin list-accounts            # every account with status
stelyph admin reset-password <handle>  # prompts non-echoing
stelyph admin takedown <did>           # hide an account (untakedown to restore)
```

Pass `--open-registration` to `serve` to allow signups without invites.

Signing keys are portable: `stelyph export-keys` / `stelyph import-keys` move the
encrypted key material between hosts (passphrase-verified, written `0600`).

## What It Is

A single-binary Personal Data Server for the [AT Protocol](https://atproto.com/) — the open
protocol behind [Bluesky](https://bsky.app). Self-host your identity and posts on your own
domain in minutes, with full federation to the real Bluesky network.

- **Single binary:** download it, run it. No orchestration.
- **Federated from day one:** relay + AppView integration via `requestCrawl`.
- **Static SQLite storage:** WAL-mode, encrypted key storage (Argon2id + AES-256-GCM), backup-safe.
- **Adaptive front door:** the `init` wizard probes your network and recommends
  standalone TLS (rustls + ACME) or proxy mode behind a tunnel/reverse proxy.

## License

Copyright © 2026 [Spirallex](https://github.com/spirallex).

This program is free software: you can redistribute it and/or modify it under the terms of the
GNU General Public License as published by the Free Software Foundation, either version 3 of
the License, or (at your option) any later version. See [LICENSE](LICENSE).
