# Cloudflare Tunnel via API token (fallback for when SSO login fails)

The primary way to put stelyph behind a Cloudflare Tunnel is
[`scripts/setup-cloudflare-tunnel.sh`](../scripts/setup-cloudflare-tunnel.sh) — it
uses `cloudflared tunnel login`, an interactive browser SSO flow, and needs no token
to manage. **Use that one first.**

This doc covers the fallback: [`scripts/setup-cloudflare-tunnel-token.sh`](../scripts/setup-cloudflare-tunnel-token.sh),
which does the same job through the Cloudflare REST API using a short-lived, scoped
API token. Reach for it only if `cloudflared tunnel login` fails — some networks or
browser configurations break the local OAuth callback it depends on (it prints
`Failed to write the certificate... Failed to fetch resource` and never completes).

Both scripts are interactive and bring-your-own-account: you always create the
credential yourself in your own Cloudflare dashboard. The token script produces a
**remotely-managed** tunnel (ingress config lives on Cloudflare's side) rather than
the SSO script's locally-managed one (ingress in a local `config.yml`) — functionally
equivalent for stelyph, just configured differently on Cloudflare's end.

## 1. Create a scoped API token

**dash.cloudflare.com/profile/api-tokens → Create Token → Custom token:**

| Permission | Level |
|---|---|
| `Account` → `Cloudflare Tunnel` | `Edit` |
| `Zone` → `DNS` | `Edit` |
| `Zone` → `Workers Routes` | `Edit` |

Scope **Zone Resources** to just the zone you're using, and **Account Resources** to
just your account. Set a short TTL if the option is offered — it's only needed for
this one setup and should be revoked afterward (the script reminds you at the end).

## 2. Run the script

```sh
./scripts/setup-cloudflare-tunnel-token.sh joey.stelyph.example.com
```

It prompts for the token (hidden input) if `CF_API_TOKEN` isn't already exported, then:

1. Verifies the token
2. Resolves the Cloudflare zone and account from the hostname
3. Creates the tunnel (or reuses one already named after the hostname)
4. Sets the tunnel's ingress: `<hostname> → http://localhost:<port>`
5. Creates or repoints the DNS `CNAME` to that tunnel
6. Checks for Worker Routes that could shadow the hostname (see [Gotcha 1](#gotcha-1-a-worker-route-can-silently-swallow-your-hostname) below) and offers to add a bypass
7. Fetches the tunnel's connector token and prints the next commands

It asks for confirmation before doing anything that could affect something else
already using that zone — repointing an existing DNS record, or adding a Worker
Route. It never runs `sudo` for you.

`PDS_PORT` / `TUNNEL_NAME` / `CF_ZONE` env vars override the defaults; see the
script's header comment for details.

## 3. Bring up the connector and stelyph

```sh
sudo cloudflared service install <connector-token-the-script-printed>
stelyph serve --mode proxy --port <port>
```

(Or run `cloudflared tunnel run --token <token>` in the foreground first, if you want
to watch it connect before installing it as a persistent service.)

## 4. Verify

A clean `200` alone does **not** prove the tunnel reached your PDS — see
[Gotcha 1](#gotcha-1-a-worker-route-can-silently-swallow-your-hostname). Check the
actual response shape and the pieces that matter for federation:

```sh
# Real stelyph shape: {"did":..., "availableUserDomains":[...], "inviteCodeRequired":...}
curl https://<hostname>/xrpc/com.atproto.server.describeServer

# Should return the account's bare DID
curl https://<hostname>/.well-known/atproto-did

# Firehose WebSocket upgrade — must return "101 Switching Protocols".
# Force HTTP/1.1: curl's automatic HTTP/2 negotiation strips the Connection:
# Upgrade header and produces a misleading 400 that looks like a real failure.
curl -i --http1.1 \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  https://<hostname>/xrpc/com.atproto.sync.subscribeRepos

# If `stelyph init`'s requestCrawl failed (it does, if nothing was listening yet),
# resubmit it now that stelyph is actually serving:
curl -X POST -H "Content-Type: application/json" \
  --data '{"hostname":"<hostname>"}' \
  https://bsky.network/xrpc/com.atproto.sync.requestCrawl
```

## Troubleshooting

### Gotcha 1: a Worker Route can silently swallow your hostname

If your Cloudflare account has any Worker bound to a wildcard route on the zone
(`*.example.com/*` or similar — common on accounts that host several services
behind one zone), that Worker intercepts requests to your new hostname **before**
Cloudflare even looks at DNS or the tunnel. A curl to your new hostname can return a
clean `200` that looks exactly like a healthy PDS, while nothing has actually reached
your tunnel or `stelyph`.

**Tell** by comparing the response body to the real shape above — a Worker mock/proxy
built for a different purpose typically won't match it field-for-field, or will
suspiciously echo back whatever hostname you requested. **Confirm** by querying a
hostname you know was never configured; if it returns a similarly well-formed
response, something's intercepting the whole zone. The script checks for this
automatically (step 6 above) and offers to add an exact-match bypass route
(`<hostname>/* → no Worker`), which is what fixes it.

### Gotcha 2: stale DNS pointing at a dead tunnel

`error 1033` (a Cloudflare "tunnel not found/connected" error) with the tunnel
itself showing healthy in the dashboard usually means the DNS record predates the
current tunnel — e.g. left over from an earlier setup attempt with a different
tunnel ID. The script checks for and offers to fix this (step 5), but if you're
debugging by hand: `dig CNAME <hostname>` and compare the target's tunnel ID against
what's actually running (`cloudflared tunnel list` or the dashboard).

### Gotcha 3: `stelyph init` can default to the wrong mode

`init`'s network-mode detection recommends `standalone` (binds `:443` directly, gets
its own Let's Encrypt cert) whenever the machine has a bindable `:443` *and* a
reachable public IP — regardless of whether you actually intend to run behind a
tunnel. If both happen to be true on your box (common on a Mac with a public IP),
`init` will write `mode = "standalone"` into `stelyph.toml` even though you're
setting up a tunnel. Check `stelyph.toml` after `init` and fix it to `mode = "proxy"`
if so — no need to re-run `init` for this, it's one line, and re-running `init` either
fails (invite required for a non-first account, same DB) or mints a **second, separate
`did:plc` identity** if pointed at a different DB, leaving the first one permanently
published and orphaned. Just edit the file.

### Gotcha 4: `~/.stelyph.env` and `stelyph.toml` can drift

If `init` runs without your usual environment sourced, it falls back to its own
defaults (e.g. a `pds.db` relative to the current directory) instead of whatever
`PDS_DB_PATH`/`PDS_HOSTNAME` you normally export. `stelyph.toml` reflects what
`init` actually did — after any `init` run, reconcile your env file *against*
`stelyph.toml`, not the other way around, or `stelyph serve` will quietly point at
an empty database that isn't the one holding the account you just created.

## Teardown

```sh
curl -X DELETE -H "Authorization: Bearer $CF_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/accounts/<account_id>/cfd_tunnel/<tunnel_id>?cascade=true"
sudo cloudflared service uninstall
```

Then remove the DNS record and any bypass Worker Route from the dashboard if you
added one.

## Security notes

- Revoke the API token once setup is done — it's not needed for the tunnel to keep
  running (that uses the separate, longer-lived connector token from step 5).
- Prefer a short TTL and the narrowest possible resource scoping when creating the
  token in the first place.
