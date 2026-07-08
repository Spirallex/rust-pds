#!/usr/bin/env bash
#
# Cloudflare Tunnel setup for stelyph, via a scoped API token instead of SSO.
#
# `scripts/setup-cloudflare-tunnel.sh` is the primary path (interactive
# `cloudflared tunnel login` browser SSO, bring-your-own-account, no token to manage).
# Use THIS script only when that SSO flow doesn't work for you — some networks/browsers
# fail the local OAuth callback that `cloudflared tunnel login` depends on. This script
# does the same job (tunnel + DNS + ingress → your local stelyph) through the Cloudflare
# REST API instead, using a short-lived, narrowly-scoped API token you create yourself.
#
# Still fully interactive and bring-your-own-account: you create the token in YOUR
# Cloudflare dashboard, paste it here, and confirm the one destructive step (repointing
# an existing DNS record). Nothing runs unattended and nothing is stored beyond this
# shell's lifetime.
#
# Produces a "remotely-managed" tunnel (ingress config lives on Cloudflare's side, not
# in a local config.yml) — a different tunnel type than the SSO script's locally-managed
# one, but functionally equivalent for stelyph's purposes.
#
# Usage:
#   export CF_API_TOKEN=...          # or leave unset and it will prompt (hidden input)
#   ./scripts/setup-cloudflare-tunnel-token.sh <hostname> [--zone example.com]
#   ./scripts/setup-cloudflare-tunnel-token.sh joey.stelyph.spirallex.com
#
# Required token permissions (dash.cloudflare.com/profile/api-tokens → Create Token →
# Custom token — scope Zone Resources to just your zone, Account Resources to just
# your account):
#   Account > Cloudflare Tunnel > Edit
#   Zone    > DNS               > Edit
#   Zone    > Workers Routes    > Edit
#
# Env overrides:
#   PDS_PORT      local port stelyph listens on (default: from stelyph.toml, else 3000)
#   TUNNEL_NAME   tunnel name (default: the hostname itself)
#   CF_ZONE       zone name, skips auto-detection (e.g. spirallex.com)
#   CF_API_TOKEN  API token (prompted, hidden, if unset)
#
# What it does NOT do: run `sudo` for you, or overwrite an existing DNS record or add a
# Worker Route bypass without asking first — both print exactly what's about to change
# and require a typed "y".

set -euo pipefail

err()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; }
ok()   { printf '\033[32m✓ %s\033[0m\n' "$*"; }
info() { printf '\033[36m→ %s\033[0m\n' "$*"; }
warn() { printf '\033[33m! %s\033[0m\n' "$*"; }

confirm() {
  local prompt="$1"
  read -r -p "${prompt} [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

# ---- args / deps -------------------------------------------------------------
HOSTNAME="${1:-}"
ZONE_OVERRIDE="${CF_ZONE:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --zone) ZONE_OVERRIDE="$2"; shift 2 ;;
    *) shift ;;
  esac
done

if [[ -z "$HOSTNAME" || "$HOSTNAME" == --* ]]; then
  read -r -p "Public hostname for the PDS (e.g. joey.stelyph.example.com): " HOSTNAME
fi
[[ -n "$HOSTNAME" ]] || { err "no hostname given"; exit 2; }

command -v curl >/dev/null || { err "curl not installed"; exit 2; }
command -v jq   >/dev/null || { err "jq not installed (brew install jq)"; exit 2; }
command -v cloudflared >/dev/null || warn "cloudflared not found locally — you'll need it to run the tunnel connector"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Resolve the local port the same way the SSO script does: PDS_PORT env > stelyph.toml
# `port = N` > 3000.
if [[ -n "${PDS_PORT:-}" ]]; then
  PORT="$PDS_PORT"
elif PORT_LINE=$(grep -E '^[[:space:]]*port[[:space:]]*=' "${REPO_ROOT}/stelyph.toml" 2>/dev/null); then
  PORT="$(sed -E 's/[^0-9]//g' <<<"$PORT_LINE")"
fi
PORT="${PORT:-3000}"

TUNNEL_NAME="${TUNNEL_NAME:-$HOSTNAME}"

info "hostname : $HOSTNAME"
info "forward  : http://localhost:${PORT}  (stelyph must run with --mode proxy --port ${PORT})"
info "tunnel   : $TUNNEL_NAME (remotely-managed)"
echo

# ---- 0. token -----------------------------------------------------------------
if [[ -z "${CF_API_TOKEN:-}" ]]; then
  read -r -s -p "Cloudflare API token (Tunnel:Edit + DNS:Edit + Workers Routes:Edit): " CF_API_TOKEN
  echo
fi
[[ -n "$CF_API_TOKEN" ]] || { err "no API token given"; exit 2; }

CF_API="https://api.cloudflare.com/client/v4"

cf() {
  # cf <METHOD> <path> [json-body]
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -sS -X "$method" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" \
      --data "$body" "${CF_API}${path}"
  else
    curl -sS -X "$method" -H "Authorization: Bearer $CF_API_TOKEN" "${CF_API}${path}"
  fi
}

cf_die_on_error() {
  # cf_die_on_error <json> <context>
  local resp="$1" ctx="$2"
  if [[ "$(echo "$resp" | jq -r '.success')" != "true" ]]; then
    err "Cloudflare API call failed: ${ctx}"
    echo "$resp" | jq '.errors' >&2
    exit 1
  fi
}

# ---- 1. verify token ------------------------------------------------------------
info "verifying API token"
VERIFY=$(cf GET "/user/tokens/verify")
cf_die_on_error "$VERIFY" "token verify"
ok "token active"

# ---- 2. resolve zone + account -------------------------------------------------
info "resolving zone for ${HOSTNAME}"
ZONE_ID=""
if [[ -n "$ZONE_OVERRIDE" ]]; then
  RESP=$(cf GET "/zones?name=${ZONE_OVERRIDE}")
  ZONE_ID=$(echo "$RESP" | jq -r '.result[0].id // empty')
  ZONE_NAME="$ZONE_OVERRIDE"
else
  candidate="$HOSTNAME"
  while [[ "$candidate" == *.* ]]; do
    RESP=$(cf GET "/zones?name=${candidate}")
    ZONE_ID=$(echo "$RESP" | jq -r '.result[0].id // empty')
    if [[ -n "$ZONE_ID" ]]; then
      ZONE_NAME="$candidate"
      break
    fi
    candidate="${candidate#*.}"
  done
fi
[[ -n "$ZONE_ID" ]] || { err "could not find a Cloudflare zone matching ${HOSTNAME} (pass --zone explicitly)"; exit 1; }
ok "zone: ${ZONE_NAME} (${ZONE_ID})"

ACCOUNT_JSON=$(cf GET "/zones/${ZONE_ID}")
cf_die_on_error "$ACCOUNT_JSON" "zone details"
ACCOUNT_ID=$(echo "$ACCOUNT_JSON" | jq -r '.result.account.id')
ok "account: $(echo "$ACCOUNT_JSON" | jq -r '.result.account.name') (${ACCOUNT_ID})"

# ---- 3. tunnel (idempotent) -----------------------------------------------------
info "checking for an existing tunnel named '${TUNNEL_NAME}'"
EXISTING=$(cf GET "/accounts/${ACCOUNT_ID}/cfd_tunnel?name=${TUNNEL_NAME}&is_deleted=false")
cf_die_on_error "$EXISTING" "list tunnels"
TUNNEL_ID=$(echo "$EXISTING" | jq -r '.result[0].id // empty')

if [[ -n "$TUNNEL_ID" ]]; then
  ok "reusing existing tunnel ${TUNNEL_ID}"
else
  info "creating tunnel '${TUNNEL_NAME}'"
  CREATED=$(cf POST "/accounts/${ACCOUNT_ID}/cfd_tunnel" \
    "$(jq -n --arg name "$TUNNEL_NAME" '{name: $name, config_src: "cloudflare"}')")
  cf_die_on_error "$CREATED" "create tunnel"
  TUNNEL_ID=$(echo "$CREATED" | jq -r '.result.id')
  ok "tunnel created: ${TUNNEL_ID}"
fi

# ---- 4. ingress config ----------------------------------------------------------
info "setting ingress: ${HOSTNAME} -> http://localhost:${PORT}"
INGRESS=$(cf PUT "/accounts/${ACCOUNT_ID}/cfd_tunnel/${TUNNEL_ID}/configurations" \
  "$(jq -n --arg host "$HOSTNAME" --arg svc "http://localhost:${PORT}" \
    '{config: {ingress: [{hostname: $host, service: $svc}, {service: "http_status:404"}]}}')")
cf_die_on_error "$INGRESS" "set tunnel ingress"
ok "ingress configured"

# ---- 5. connector token -----------------------------------------------------------
info "fetching connector token"
TOKEN_RESP=$(cf GET "/accounts/${ACCOUNT_ID}/cfd_tunnel/${TUNNEL_ID}/token")
cf_die_on_error "$TOKEN_RESP" "fetch tunnel token"
CONNECTOR_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.result')
ok "connector token retrieved"

# ---- 6. DNS record (confirm before overwriting anything) --------------------------
info "checking DNS for ${HOSTNAME}"
DNS_RESP=$(cf GET "/zones/${ZONE_ID}/dns_records?name=${HOSTNAME}&type=CNAME")
cf_die_on_error "$DNS_RESP" "list DNS records"
DNS_ID=$(echo "$DNS_RESP" | jq -r '.result[0].id // empty')
DNS_CONTENT=$(echo "$DNS_RESP" | jq -r '.result[0].content // empty')
WANT_CONTENT="${TUNNEL_ID}.cfargotunnel.com"

if [[ -z "$DNS_ID" ]]; then
  info "creating CNAME ${HOSTNAME} -> ${WANT_CONTENT}"
  CREATE_DNS=$(cf POST "/zones/${ZONE_ID}/dns_records" \
    "$(jq -n --arg name "$HOSTNAME" --arg content "$WANT_CONTENT" \
      '{type: "CNAME", name: $name, content: $content, proxied: true}')")
  cf_die_on_error "$CREATE_DNS" "create DNS record"
  ok "DNS record created"
elif [[ "$DNS_CONTENT" == "$WANT_CONTENT" ]]; then
  ok "DNS already points at this tunnel"
else
  warn "DNS record for ${HOSTNAME} currently points at '${DNS_CONTENT}', not this tunnel"
  warn "(this is exactly the kind of stale-DNS-from-an-old-attempt bug that costs debugging time later)"
  if confirm "Repoint it to ${WANT_CONTENT}?"; then
    UPDATE_DNS=$(cf PUT "/zones/${ZONE_ID}/dns_records/${DNS_ID}" \
      "$(jq -n --arg name "$HOSTNAME" --arg content "$WANT_CONTENT" \
        '{type: "CNAME", name: $name, content: $content, proxied: true}')")
    cf_die_on_error "$UPDATE_DNS" "update DNS record"
    ok "DNS repointed"
  else
    warn "left DNS untouched — ${HOSTNAME} will NOT reach this tunnel until you fix that record"
  fi
fi

# ---- 7. Worker Route shadowing check (heuristic, advisory) -------------------------
info "checking for Worker Routes that might shadow ${HOSTNAME}"
ROUTES=$(cf GET "/zones/${ZONE_ID}/workers/routes")
cf_die_on_error "$ROUTES" "list worker routes"

SHADOWING=$(echo "$ROUTES" | jq -r --arg host "$HOSTNAME" '
  .result[]
  | select(.pattern != ($host + "/*"))
  | select(
      (.pattern | startswith("*.")) and
      ($host | endswith(.pattern | sub("^\\*"; "") | sub("/\\*$"; "")))
    )
  | "\(.pattern) -> \(.script // "null")"
')

if [[ -n "$SHADOWING" ]]; then
  warn "found Worker Route(s) that would intercept ${HOSTNAME} before it reaches this tunnel:"
  echo "$SHADOWING" | sed 's/^/    /' >&2
  warn "any response through those routes is the Worker answering, NOT your tunnel/origin"
  if confirm "Add an exact-match bypass route (${HOSTNAME}/* -> no Worker) so this hostname reaches the tunnel?"; then
    BYPASS=$(cf POST "/zones/${ZONE_ID}/workers/routes" \
      "$(jq -n --arg pattern "${HOSTNAME}/*" '{pattern: $pattern, script: null}')")
    cf_die_on_error "$BYPASS" "create worker route bypass"
    ok "bypass route added"
  else
    warn "left it as-is — requests to ${HOSTNAME} may be intercepted by the Worker above"
  fi
else
  ok "no shadowing Worker Routes found"
fi

# ---- 8. summary -----------------------------------------------------------------
echo
ok "Cloudflare-side setup done for ${HOSTNAME} (tunnel ${TUNNEL_ID})"
echo
echo "Next steps:"
echo "  1. Run the connector (needs sudo — run this yourself, not via automation):"
echo "       sudo cloudflared service install ${CONNECTOR_TOKEN}"
echo "     (or, to run in the foreground first without installing a service:"
echo "       cloudflared tunnel run --token ${CONNECTOR_TOKEN}   )"
echo "  2. Start stelyph on the matching port:"
echo "       stelyph serve --mode proxy --port ${PORT}"
echo "  3. Verify (see docs/deploy-cloudflare-tunnel-token.md for the full checklist):"
echo "       curl https://${HOSTNAME}/xrpc/com.atproto.server.describeServer"
echo
warn "Revoke this API token now if you won't need it again — it's not required for ongoing operation."
