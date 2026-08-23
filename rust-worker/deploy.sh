#!/usr/bin/env bash
# In-place deploy of this PDS worker to Cloudflare, straight from the monorepo.
# Uses the local wrangler.toml (already configured) and the ../rust-core PATH
# dependency — no git dep, no source copy, no drift.
#
#   ./deploy.sh            # build (release) + wrangler deploy
#   ./deploy.sh --dry-run  # build only (verify the wasm compiles)
#
# For a STANDALONE, one-click deploy repo (git-dep on stelyph-core, setup.sh,
# "Use this template" button) see: github.com/Spirallex/rust-pds-cloudflare
set -euo pipefail
cd "$(dirname "$0")"

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

echo "==> checking toolchain"
rustup target list --installed | grep -q wasm32-unknown-unknown \
  || { echo "installing wasm32 target"; rustup target add wasm32-unknown-unknown; }
command -v worker-build >/dev/null 2>&1 \
  || { echo "installing worker-build"; cargo install -q worker-build --version '^0.8'; }

if [[ "$DRY_RUN" == "1" ]]; then
  echo "==> building (dry run, no deploy)"; worker-build --release
  echo "==> OK: wasm built at build/worker/. Skipping deploy (--dry-run)."; exit 0
fi

command -v wrangler >/dev/null 2>&1 \
  || { echo "ERROR: wrangler not found. 'npm i -g wrangler' or use 'npx wrangler'." >&2; exit 1; }
echo "==> deploying (wrangler runs the [build] command from wrangler.toml)"
wrangler deploy
echo "==> done. Secrets are not deployed by this script — set once with:"
echo "      wrangler secret put PDS_JWT_SECRET"
echo "      wrangler secret put PDS_KEY_PASSPHRASE"
