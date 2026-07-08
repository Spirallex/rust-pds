#!/usr/bin/env bash
#
# Cloudflare Tunnel setup for stelyph (bring-your-own Cloudflare account via SSO).
#
# Stands up a named Cloudflare Tunnel in front of a locally-running stelyph so the
# PDS is reachable at a public hostname over HTTPS with no bindable :443 — Cloudflare
# terminates TLS and forwards to stelyph on localhost. WebSocket upgrade (the firehose)
# and Host passthrough both survive the tunnel.
#
# Account-agnostic: whoever runs this logs into THEIR OWN Cloudflare account and picks
# a zone they control — nothing here is tied to any one account. It uses the INSTALLED
# `cloudflared` service, NOT the Cloudflare SDK, because the auth step is interactive
# SSO: `cloudflared tunnel login` opens the browser and the operator authenticates their
# own account. The SDK is API-token-only and has no SSO, so it can't offer this flow.
#
# Because stelyph derives the account-handle suffix from PDS_HOSTNAME
# (availableUserDomains = .<hostname> → e.g. joey.<hostname>), this also routes the
# `*.<hostname>` wildcard so per-user handle resolution
# (https://<handle>/.well-known/atproto-did) reaches the PDS.
#
# Usage:
#   ./scripts/setup-cloudflare-tunnel.sh <hostname> [--run]
#   ./scripts/setup-cloudflare-tunnel.sh stelyph.spirallex.com --run
#
# Env overrides:
#   PDS_PORT       local port stelyph listens on (default: from stelyph.toml, else 3000)
#   TUNNEL_NAME    cloudflared tunnel name        (default: stelyph)
#   NO_WILDCARD=1  skip the *.<hostname> wildcard route
#
# Flags:
#   --run      start the tunnel in the foreground after provisioning (otherwise just
#              prints the run command so you can wire it into a service/launchd later).
#   --relogin  force a fresh SSO login even if a cached cert.pem exists — use this when
#              a DIFFERENT person/account is bringing their own Cloudflare on this host.

set -euo pipefail

err()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; }
ok()   { printf '\033[32m✓ %s\033[0m\n' "$*"; }
info() { printf '\033[36m→ %s\033[0m\n' "$*"; }

# ---- args -------------------------------------------------------------------
HOSTNAME="${1:-}"
RUN=0
RELOGIN=0
for a in "$@"; do
  case "$a" in
    --run)     RUN=1 ;;
    --relogin) RELOGIN=1 ;;
  esac
done

if [[ -z "$HOSTNAME" || "$HOSTNAME" == --* ]]; then
  read -r -p "DNS hostname for the PDS (e.g. stelyph.spirallex.com): " HOSTNAME
fi
[[ -n "$HOSTNAME" ]] || { err "no hostname given"; exit 2; }

command -v cloudflared >/dev/null || { err "cloudflared not installed (brew install cloudflared)"; exit 2; }

TUNNEL_NAME="${TUNNEL_NAME:-stelyph}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CF_DIR="${HOME}/.cloudflared"

# Resolve the local port: PDS_PORT env > stelyph.toml `port = N` > 3000.
if [[ -n "${PDS_PORT:-}" ]]; then
  PORT="$PDS_PORT"
elif PORT_LINE=$(grep -E '^[[:space:]]*port[[:space:]]*=' "${REPO_ROOT}/stelyph.toml" 2>/dev/null); then
  PORT="$(sed -E 's/[^0-9]//g' <<<"$PORT_LINE")"
fi
PORT="${PORT:-3000}"

info "hostname : $HOSTNAME"
info "tunnel   : $TUNNEL_NAME"
info "forward  : http://localhost:${PORT}  (stelyph must run with --mode proxy --port ${PORT})"
echo

# ---- 1. SSO auth (bring your own account) -----------------------------------
# cert.pem is the origin cert minted by the browser SSO login; it authorizes
# tunnel + DNS management for zones in WHICHEVER account logged in. A cached cert
# belongs to a previous operator's account — `--relogin` forces a fresh SSO so a
# different person can bring their own Cloudflare on this same host.
if [[ "$RELOGIN" == "1" && -f "${CF_DIR}/cert.pem" ]]; then
  info "--relogin: clearing cached credentials so you can sign into your own account"
  rm -f "${CF_DIR}/cert.pem"
fi

if [[ -f "${CF_DIR}/cert.pem" ]]; then
  ok "using cached login (${CF_DIR}/cert.pem) — pass --relogin to use a different account"
else
  info "Cloudflare SSO — sign into YOUR account and pick the zone for ${HOSTNAME}"
  cloudflared tunnel login
  [[ -f "${CF_DIR}/cert.pem" ]] || { err "login did not produce cert.pem"; exit 1; }
  ok "authenticated"
fi

# ---- 2. create tunnel (idempotent) -----------------------------------------
if cloudflared tunnel list -o json 2>/dev/null | grep -q "\"name\":\"${TUNNEL_NAME}\""; then
  ok "tunnel '${TUNNEL_NAME}' already exists — reusing"
else
  info "creating tunnel '${TUNNEL_NAME}'"
  cloudflared tunnel create "${TUNNEL_NAME}"
  ok "tunnel created"
fi

TUNNEL_ID="$(cloudflared tunnel list -o json | sed -n "s/.*\"id\":\"\([^\"]*\)\",\"name\":\"${TUNNEL_NAME}\".*/\1/p" | head -1)"
[[ -n "$TUNNEL_ID" ]] || { err "could not resolve tunnel id for ${TUNNEL_NAME}"; exit 1; }
CREDS_FILE="${CF_DIR}/${TUNNEL_ID}.json"
ok "tunnel id: ${TUNNEL_ID}"

# ---- 3. ingress config ------------------------------------------------------
# Locally-managed config: apex host + wildcard both forward to stelyph; everything
# else 404s. `service` ports MUST match the stelyph --port.
CONFIG_FILE="${CF_DIR}/config-${TUNNEL_NAME}.yml"
{
  echo "tunnel: ${TUNNEL_ID}"
  echo "credentials-file: ${CREDS_FILE}"
  echo "ingress:"
  echo "  - hostname: ${HOSTNAME}"
  echo "    service: http://localhost:${PORT}"
  if [[ "${NO_WILDCARD:-0}" != "1" ]]; then
    echo "  - hostname: \"*.${HOSTNAME}\""
    echo "    service: http://localhost:${PORT}"
  fi
  echo "  - service: http_status:404"
} >"${CONFIG_FILE}"
ok "wrote ${CONFIG_FILE}"

# ---- 4. DNS routes ----------------------------------------------------------
info "routing DNS ${HOSTNAME} → ${TUNNEL_NAME}"
cloudflared tunnel route dns "${TUNNEL_NAME}" "${HOSTNAME}" || \
  err "route for ${HOSTNAME} failed (already routed elsewhere? check the dashboard)"

if [[ "${NO_WILDCARD:-0}" != "1" ]]; then
  info "routing wildcard *.${HOSTNAME} (per-user handle resolution)"
  if ! cloudflared tunnel route dns "${TUNNEL_NAME}" "*.${HOSTNAME}"; then
    err "wildcard route failed via CLI — add a proxied CNAME '*.${HOSTNAME}' → ${TUNNEL_ID}.cfargotunnel.com in the dashboard"
  fi
fi

echo
ok "provisioned. did:web:${HOSTNAME} will resolve once stelyph is up behind the tunnel."
echo
RUN_CMD="cloudflared tunnel --config ${CONFIG_FILE} run ${TUNNEL_NAME}"
if [[ "$RUN" == "1" ]]; then
  info "starting tunnel (foreground) — Ctrl-C to stop"
  exec ${RUN_CMD}
else
  echo "Next: start stelyph, then run the tunnel:"
  echo "  stelyph serve --mode proxy --port ${PORT}"
  echo "  ${RUN_CMD}"
fi
