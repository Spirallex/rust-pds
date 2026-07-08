#!/usr/bin/env bash
#
# Lexicon version drift check.
#
# stelyph's AT Protocol record/lexicon types come from the `atrium-api` crate,
# which is a generated snapshot of Bluesky's lexicons. bsky.app validates records
# against the *current* lexicons, so when Bluesky adds a required field or changes
# a format, a stale pin silently drifts and records can render wrong with no alarm.
#
# This compares the version of `atrium-api` resolved in Cargo.lock against the
# newest version published on crates.io. Exit codes:
#   0  in sync (pinned == newest)
#   1  drift detected (a newer atrium-api is published) — review the changelog
#   2  could not determine a version (lookup/parse failure)
#
# Run locally: ./scripts/check-lexicon-drift.sh
# In CI: see .github/workflows/lexicon-drift.yml (weekly + on-demand).

set -euo pipefail

CRATE="atrium-api"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCKFILE="$REPO_ROOT/Cargo.lock"

if [[ ! -f "$LOCKFILE" ]]; then
  echo "::error::Cargo.lock not found at $LOCKFILE" >&2
  exit 2
fi

# Pinned version: the [[package]] block in Cargo.lock whose name == $CRATE.
pinned="$(
  awk -v crate="$CRATE" '
    /^\[\[package\]\]/ { name=""; version="" }
    /^name = / { gsub(/[",]/, ""); name=$3 }
    /^version = / { gsub(/[",]/, ""); version=$3 }
    (name == crate && version != "") { print version; exit }
  ' "$LOCKFILE"
)"

if [[ -z "${pinned:-}" ]]; then
  echo "::error::could not find '$CRATE' in Cargo.lock" >&2
  exit 2
fi

# Newest published version from crates.io.
newest="$(
  curl -fsSL "https://crates.io/api/v1/crates/$CRATE" \
    -H "User-Agent: stelyph-lexicon-drift-check (https://github.com/Spirallex/rust-pds)" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['crate']['newest_version'])"
)"

if [[ -z "${newest:-}" ]]; then
  echo "::error::could not fetch newest '$CRATE' version from crates.io" >&2
  exit 2
fi

echo "$CRATE pinned (Cargo.lock): $pinned"
echo "$CRATE newest (crates.io):  $newest"

if [[ "$pinned" == "$newest" ]]; then
  echo "✓ lexicon dependency is up to date"
  exit 0
fi

echo "::warning::lexicon drift — $CRATE $pinned is pinned but $newest is published."
echo "Review the atrium-api changelog for new/changed Bluesky lexicons before bumping:"
echo "  https://crates.io/crates/$CRATE/versions"
exit 1
