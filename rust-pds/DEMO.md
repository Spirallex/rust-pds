# rust-pds live firehose demo

This runbook proves the federation spine end-to-end: create a post with this PDS and watch
your own signed commit appear in a second terminal, signature-verified (✓) within moments.

The ✓ indicator means the commit's secp256k1 signature cryptographically verified against the
account's signing did:key — the event is network-valid, independent of bsky.app's indexing clock.

---

## Prerequisites

```
cargo build -p rust-pds --bins
```

You need two environment variables for the server:

```
export PDS_HOSTNAME=localhost
export PDS_JWT_SECRET=some-random-string-at-least-32-chars-long
export PDS_KEY_PASSPHRASE=another-secret-passphrase
```

---

## Step 1 — Terminal 1: start the PDS

```bash
cargo run -p rust-pds
```

Expected output:

```
rust-pds listening on 0.0.0.0:3000 (hostname=localhost, open_registration=false)
```

---

## Step 2 — Terminal 1: create an account

```bash
curl -s -X POST http://localhost:3000/xrpc/com.atproto.server.createAccount \
  -H "Content-Type: application/json" \
  -d '{
    "handle": "alice.localhost",
    "email": "alice@localhost",
    "password": "hunter2"
  }' | tee /tmp/account.json
```

Note the `did` and `accessJwt` from the response:

```bash
DID=$(jq -r .did /tmp/account.json)
TOKEN=$(jq -r .accessJwt /tmp/account.json)
echo "DID: $DID"
```

Get the signing did:key (needed for the --did-key flag):

```bash
curl -s "http://localhost:3000/xrpc/com.atproto.identity.resolveHandle?handle=alice.localhost"
# or read it from the DID document served by the PDS:
curl -s "http://localhost:3000/.well-known/did.json" | jq '.verificationMethod[0].publicKeyMultibase'
# The did:key is: did:key:<publicKeyMultibase value>
```

---

## Step 3 — Terminal 2: start firehose-tail

Open a **new terminal window** and run the consumer binary:

```bash
cargo run -p rust-pds --bin firehose-tail -- \
  --url ws://localhost:3000/xrpc/com.atproto.sync.subscribeRepos \
  --demo-did "$DID"
```

Or, if you know the account's signing did:key (skip live DID resolution):

```bash
cargo run -p rust-pds --bin firehose-tail -- \
  --url ws://localhost:3000/xrpc/com.atproto.sync.subscribeRepos \
  --did-key "did:key:z..." \
  --demo-did "$DID"
```

Expected output:

```
Connected to ws://localhost:3000/xrpc/com.atproto.sync.subscribeRepos. Waiting for commits...
```

---

## Step 4 — Terminal 1: post a record

```bash
curl -s -X POST http://localhost:3000/xrpc/com.atproto.repo.createRecord \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "repo": "'"$DID"'",
    "collection": "app.bsky.feed.post",
    "record": {
      "$type": "app.bsky.feed.post",
      "text": "Hello from rust-pds!",
      "createdAt": "'"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"'"
    }
  }'
```

---

## Step 5 — Watch Terminal 2

Within seconds you should see a line like:

```
[seq=1] did:plc:abc123... rev=... ops=1 ✓ <-- MY COMMIT
```

**✓** — the commit's secp256k1 signature verified against the signing did:key.
**<-- MY COMMIT** — this commit was published by your account (`--demo-did`).

If the DID document is not publicly resolvable (localhost), supply `--did-key` directly
to bypass live resolution.

---

## Optional: replay with cursor

To replay all commits from the beginning:

```bash
cargo run -p rust-pds --bin firehose-tail -- \
  --url ws://localhost:3000/xrpc/com.atproto.sync.subscribeRepos \
  --cursor 0
```

---

## JSON output

For machine-readable output:

```bash
cargo run -p rust-pds --bin firehose-tail -- \
  --url ws://localhost:3000/xrpc/com.atproto.sync.subscribeRepos \
  --json
```

Each line is: `{"seq":1,"repo":"did:plc:...","rev":"...","ops":1,"sig_ok":true}`

---

## What the ✓ proves

The `verify_commit_sig` function in `stelyph::firehose::tail`:

1. Extracts the commit block from the CARv1 in `body.blocks` by matching `body.commit` CID.
2. Deserializes the `SignedCommit` struct (did, version, data, rev, prev, sig).
3. Re-serializes the non-sig fields as DAG-CBOR to reconstruct the bytes that were signed.
4. Calls `atrium_crypto::verify::verify_signature(signer_did_key, unsigned_bytes, sig)`.

A ✓ means step 4 returned Ok — the low-S secp256k1 signature over the canonical commit bytes
verifies against the account's signing key. This is exactly what the bsky.network relay checks
when it accepts a commit for distribution.

The automated proof is `test_fed04_e2e_signature_verifies` in `tests/firehose_ws.rs`.
