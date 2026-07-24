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

## THE main task: the write path

Everything above lets an account log in and browse. It cannot **post** yet,
because repo writes are not on the Worker. This is the highest-value next work
and it lights up three things at once: posting, the heavy repo reads, and the
firehose's real event source.

### 1. `com.atproto.repo.createRecord` / `putRecord` / `deleteRecord` / `applyWrites`
- Reuse `stelyph-core`'s `RepoWriter` (`repo/writer.rs::apply_one`) against
  `DoStore`. The seam is already right: `load_repo_root` → build MST → **sign
  with the account signing key** → `commit_blocks` (atomic append + seq + root).
- The account DO holds the signing key (`{did}#signing`, encrypted) — load it
  the same way the AppView proxy does.
- `apply_one` uses `SystemTime` via nowhere critical? CHECK: the writer/firehose
  path for any `SystemTime::now()` and thread an injected clock (pattern already
  used in `encode_access_jwt_at`, `mint_service_auth_jwt_at`). This is the most
  likely wasm panic.
- Authenticated: bearer token → DID → must match the DO's account.

### 2. On commit, POST to the sequencer `/enqueue`
- After `commit_blocks` returns the local seq, hand the commit fields (repo,
  commit CID, rev, since, blocks CAR, ops) to the sequencer DO `/enqueue`. The
  sequencer already assigns the global seq, encodes the `#commit` frame, logs,
  and broadcasts — this replaces the admin `firehose-inject` stand-in.

### 3. Heavy repo reads: `getRecord`, `listRecords`, `sync.getRepo` (CAR)
- Routing already exists (data-plane). Implement the handlers in the DO reusing
  `stelyph-core` MST walk + `Repository::open` over `DoStore` (a `BlockStore`).
- `getRecord`: MST lookup of `{collection}/{rkey}` → read block → dag-cbor →
  JSON. `getRepo`: CAR export.

After 1–3, a Bluesky account on this PDS can post, and the firehose carries real
commits that a relay can crawl → the account becomes fully visible network-wide.

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
