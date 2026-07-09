#!/usr/bin/env bash
#
# local-verify.sh — clean-slate, fully-offline end-to-end check of stelyph.
#
# Proves the whole flow works after any code change, WITHOUT touching your real
# PDS, minting a real did:plc, or hitting the network:
#   build → init (throwaway account via a fake local PLC) → serve → login →
#   signed record write → read back.
#
# Everything runs in a fresh temp dir with a throwaway hostname and a passphrase
# this script controls, then tears itself down. Safe to run repeatedly.
#
# Usage:
#   ./scripts/local-verify.sh            # builds debug binary and verifies
#   STELYPH_BIN=/path/to/stelyph ./scripts/local-verify.sh   # verify a specific binary
#
# Exit 0 = PASS, non-zero = FAIL.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
PLC_PORT=4790
SRV_PORT=4791
HOST="local-verify.example.com"
HANDLE="alice.${HOST}"
PW="verifypassword123"
PP="verify-passphrase"
JWT="local-verify-jwt-secret-32-bytes-minimum-xx"
PLC_PID=""; SRV_PID=""

cleanup() {
  [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true
  [ -n "$PLC_PID" ] && kill "$PLC_PID" 2>/dev/null || true
  # init auto-saves the throwaway secrets to the macOS Keychain — remove them so the
  # verify never pollutes your real login Keychain (no-op if unsupported/absent).
  [ -n "${BIN:-}" ] && "$BIN" keychain clear --hostname "$HOST" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

say() { printf '\033[36m▶ %s\033[0m\n' "$*"; }
ok()  { printf '\033[32m✓ %s\033[0m\n' "$*"; }
die() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# ---- binary ----------------------------------------------------------------
if [ -n "${STELYPH_BIN:-}" ]; then
  BIN="$STELYPH_BIN"
else
  say "building debug binary"
  ( cd "$REPO" && cargo build -p stelyph --quiet )
  BIN="$REPO/target/debug/stelyph"
fi
[ -x "$BIN" ] || die "binary not found/executable: $BIN"

# ---- fake PLC directory (returns 200 for any request; init only needs 2xx) -
say "starting fake PLC on :$PLC_PORT"
python3 - "$PLC_PORT" <<'PY' >/dev/null 2>&1 &
import sys, http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def _ok(self): self.send_response(200); self.end_headers(); self.wfile.write(b"{}")
    do_POST = do_GET = lambda s: s._ok()
    def log_message(self, *a): pass
class S(socketserver.TCPServer): allow_reuse_address = True
S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
PLC_PID=$!
# wait until the stub actually accepts a connection (max ~5s)
for _ in $(seq 1 25); do
  if python3 -c "import socket,sys; s=socket.socket(); s.settimeout(0.3); sys.exit(0 if s.connect_ex(('127.0.0.1',$PLC_PORT))==0 else 1)" 2>/dev/null; then break; fi
  sleep 0.2
done

# ---- init (offline: fake PLC, dead relay, all values via flags) ------------
say "init throwaway account ($HANDLE)"
"$BIN" init \
  --db-path "$WORK/pds.db" --config "$WORK/stelyph.toml" \
  --hostname "$HOST" --handle "$HANDLE" --mode proxy --port "$SRV_PORT" \
  --password "$PW" --key-passphrase "$PP" --jwt-secret "$JWT" \
  --plc-url "http://127.0.0.1:$PLC_PORT" --relay-url "http://127.0.0.1:9" \
  </dev/null >"$WORK/init.log" 2>&1 || { cat "$WORK/init.log"; die "init failed"; }
grep -q "account created" "$WORK/init.log" || { cat "$WORK/init.log"; die "init did not create an account"; }
ok "account created"

# ---- serve (background, secrets via env, no prompt) ------------------------
say "starting serve on :$SRV_PORT"
PDS_JWT_SECRET="$JWT" PDS_KEY_PASSPHRASE="$PP" \
  "$BIN" serve --hostname "$HOST" --port "$SRV_PORT" --db-path "$WORK/pds.db" \
  --mode proxy --relay-url "http://127.0.0.1:9" --non-interactive >"$WORK/serve.log" 2>&1 &
SRV_PID=$!
for _ in $(seq 1 40); do
  grep -q "listening on" "$WORK/serve.log" && break
  sleep 0.25
done
grep -q "listening on" "$WORK/serve.log" || { cat "$WORK/serve.log"; die "serve never came up"; }
ok "serving"

# ---- exercise the real request chain (login → signed write → read) ---------
BASE="http://127.0.0.1:$SRV_PORT/xrpc"
say "describeServer / createSession / createRecord / getRecord"
python3 - "$BASE" "$HANDLE" "$PW" <<'PY' || die "request chain failed"
import sys, json, urllib.request as U
base, handle, pw = sys.argv[1], sys.argv[2], sys.argv[3]
def post(p, b, tok=None):
    h = {"Content-Type": "application/json"}
    if tok: h["Authorization"] = "Bearer " + tok
    return json.load(U.urlopen(U.Request(base+"/"+p, json.dumps(b).encode(), h, method="POST"), timeout=8))
def get(p): return json.load(U.urlopen(base+"/"+p, timeout=8))
assert get("com.atproto.server.describeServer").get("did"), "describeServer had no did"
ses = post("com.atproto.server.createSession", {"identifier": handle, "password": pw})
tok, did = ses["accessJwt"], ses["did"]
rec = post("com.atproto.repo.createRecord", {"repo": did, "collection": "app.bsky.feed.post",
      "record": {"$type": "app.bsky.feed.post", "text": "local-verify", "createdAt": "2026-01-01T00:00:00Z"}}, tok)
assert rec.get("uri") and rec.get("cid"), "createRecord returned no uri/cid"
rkey = rec["uri"].split("/")[-1]
got = get(f"com.atproto.repo.getRecord?repo={did}&collection=app.bsky.feed.post&rkey={rkey}")
assert got.get("value", {}).get("text") == "local-verify", "getRecord text mismatch"
print("   did=%s  record=%s" % (did, rec["uri"]))
PY

echo
ok "LOCAL VERIFY PASS — init → serve → login → signed write → read all worked"
