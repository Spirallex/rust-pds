# TODOS

_No open todos._

---

## Done

- **Lexicon version drift monitoring** (2026-06-23) — `scripts/check-lexicon-drift.sh` compares the `atrium-api` version resolved in `Cargo.lock` (our snapshot of Bluesky's lexicons; `rsky-lexicon` was never actually a dependency) against the newest published on crates.io, exiting non-zero on drift. Wired into CI as `.github/workflows/lexicon-drift.yml` (weekly cron + manual dispatch).
- **XRPC server CORS** (2026-06-22) — `tower-http` permissive `CorsLayer` on the router in `xrpc/mod.rs`; browser preflight `OPTIONS` now returns 200. Unblocked bsky.app web login.
- **`init` listen-port prompt** (2026-06-23) — `init` prompts for the local port (default 3000), persists it to `rust-pds.toml`, and the proxy/tunnel snippet references that same value. `--port`/`PDS_PORT` on `InitArgs`; test `chosen_port_is_written_to_config`.
- **`init` hostname prompt + handle pre-validation** (2026-06-23) — the wizard now shows/confirms the hostname/DNS target (default from `--hostname`/`PDS_HOSTNAME`/config) and rejects an admin handle that isn't the hostname or a subdomain of it, before any did:plc registration.
