# Next session — plan & handoff

State as of the firehose/session/AppView work (branch `wr-09-worker-crate`,
deployed live to `stelyph-pds` at `pds.spirallex.com`).

## What's live on the Worker now

Multi-tenant PDS on Cloudflare Workers. One shared host `pds.spirallex.com`,
each account in its own Durable Object, shared `serviceEndpoint`.

- **Registration**: `GET /` page, `register/check`, `createAccount` (open, no
  invite), admin `delete-account` / `invite` / `firehose-inject`.
- **Identity/discovery**: `describeServer`, `did.json`, `atproto-did`,
  `oauth/jwks`, oauth AS/PR metadata.
- **Auth / session**: `createSession`, `getSession`, CORS (OPTIONS preflight +
  headers). Bluesky login works.
- **Preferences**: `app.bsky.actor.get/putPreferences` (birth-date screen).
- **Sign in with Stelyph**: device enrol + challenge-signed approve/deny,
  `signin/{start,poll,pending}`. iOS Face-ID UI on branch
  `feat/cloud-serve-option` (PR #1). P-256 interop verified.
- **Data-plane routing**: repo-scoped reads route by `repo`/`did` to the account
  DO; `describeRepo` is the one implemented read.
- **AppView proxy**: `app.bsky.*` / `chat.bsky.*` forwarded to
  `https://api.bsky.app` with an account-signed ES256K service-auth JWT.
- **Firehose sequencer**: central DO, global monotonic `seq`, `subscribeRepos`
  WebSocket with backfill + live fan-out. Verified with synthetic injects.

## THE main task: the write path — LANDED (not yet deployed/verified live)

The write path is implemented on branch `wr-09-worker-crate`. Builds clean for
`wasm32-unknown-unknown`; core + pds native tests green (227 + 23); clippy clean
on both targets. **Not yet deployed, and not yet verified against a real client.**

### 1. `createRecord` / `putRecord` / `deleteRecord` — DONE
- Reuses `stelyph-core`'s `RepoWriter` against `DoStore` (an `Arc<DoStore>`
  coerced to `Arc<dyn StorageBackend>` — `DoStore`'s `SendWrapper` fields satisfy
  the `Send + Sync` trait bounds).
- **wasm clock fix (core):** `writer.rs` now splits `apply_one` into
  `apply_one_at(op, now_rfc3339)` + a wall-clock wrapper. The single
  `chrono::Utc::now()` (line 286) was the only wasm panic; the Worker passes
  `crate::store::now_iso()`. `WriteOutcome` gained `since` + `blocks_car` so the
  Worker can feed the sequencer without re-decoding.
- Handlers in `handlers.rs` (`repo_write` + `commit_op`): bearer → DID (must
  equal body `repo`), validates via `repo::util`, loads `{did}#signing` like the
  AppView proxy, applies one signed commit. `putRecord` picks Create/Update by an
  MST existence check; `deleteRecord` is idempotent (NoOp when absent).
- Routed in `durable.rs::apply_write`; front Worker routes writes by bearer
  `sub` (added to the `is_auth` set in `lib.rs`).
- **Follow-ups:** `applyWrites` not implemented (loop `apply_one` per write, as
  the server does — each is its own commit). Per-DID write serialisation: each
  write builds a fresh `RepoWriter` with its own lock; if a single DO ever
  processes two writes concurrently they could fork history. Fine for a personal
  PDS; add a DO-held lock if it matters.

### 2. On commit, POST to the sequencer `/enqueue` — DONE
- `durable.rs::enqueue_to_sequencer` POSTs the `EnqueueReq`-shaped payload
  (`enqueue_payload` in `handlers.rs`) to the sequencer DO. Best-effort: a failed
  enqueue is logged, not surfaced — the commit already stands and this DO's
  `repo_seq` retains the event.

### 3. Heavy repo reads — `getRecord` DONE; `listRecords` / `sync.getRepo` TODO
- `getRecord` implemented (`handlers.rs::get_record` + `lookup_record_cid`,
  routed in `durable.rs`; already in the front Worker's `REPO_SCOPED` list).
  MST lookup → read block → dag-cbor → JSON.
- **Still TODO:** `listRecords` (MST prefix walk), `sync.getRepo` (CAR export),
  `sync.getLatestCommit`, `sync.getBlob` / `listBlobs`. Routing already exists.

### Next: deploy + verify + federate
- `wrangler deploy`, then post from a real Bluesky client against
  `pds.spirallex.com` and read it back via `getRecord`.
- Watch the firehose: a subscriber on `subscribeRepos` should see the real
  `#commit` with actual CAR blocks (not the empty-blocks admin inject).
- Then `requestCrawl` to `bsky.network` so the account federates.

## Secondary / cleanup

- **Test accounts to delete** (real did:plc on the ledger; data deletable, DID
  orphaned): `qa3.pds.spirallex.com`, `qa4.pds.spirallex.com`. Delete via admin
  `delete-account` when done. `c91` is the user's Bluesky account — keep.
- **c91 password**: current is `Spirallex-c91-2026` on DID
  `did:plc:36m62s3jqi5tce3cz4ppexrf`. The ORIGINAL c91 (made from the iOS app,
  DID `did:plc:ha6nci…`) was deleted by mistake and is unrecoverable. The user
  may want to recreate from the app instead (app still holds the old DID) — ask.
- **firehose-inject / _test-inject**: remove once real commits feed the
  sequencer (or keep admin-gated for testing).
- **Relay crawl**: once writes land, `requestCrawl` to a relay
  (`bsky.network`) so the account federates.
- **firehose `#commit` fields**: current inject sends empty blocks; the real
  path must send the actual CAR blocks + ops so relays can verify.

## Open PRs / branches

- rust-pds `wr-09-worker-crate` → **PR #19** (all Worker work; not merged).
- Infra-Cf-Spirallex `feat/stelyph-pds` → **PR #4** (routes/DNS/cert/apex;
  applied to production via `pulumi up`).
- stelyph `feat/cloud-serve-option` → **PR #1** (iOS cloud + Face-ID sign-in).

## Gotchas carried forward

- **`SystemTime::now()` panics on wasm32** — always inject the clock
  (`worker::Date::now().as_millis()/1000`). Bit both JWT and service-auth.
- **DO forwarding drops headers** — the front Worker's opaque forward only sets
  what it explicitly copies (X-Stelyph-Host, Authorization). Add any new header
  a DO handler needs.
- **Keychain fails in unsigned sim builds** (no application-identifier) — iOS
  DeviceKey has an in-process cache to survive it; real persistence needs a
  signed build.
- **createAccount can time out** on the slow PLC write while still succeeding —
  verify via `atproto-did` rather than trusting the HTTP response.
- **Edge-cached 404s / deploy propagation** — after deploy, poll for the new
  behaviour before concluding a change failed.
