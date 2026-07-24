# Sign in with Stelyph — passwordless, phone-approved OAuth

Spec + status for remote sign-in to a cloud-hosted account, approved on the
phone with biometrics instead of a password typed into a website.

## The idea

atproto OAuth makes the PDS the authorization server, and fixes only the client
and token mechanics (PAR + PKCE + DPoP). **How the AS authenticates the human is
the AS's own choice.** Today that choice is a password on a login page. This
replaces it: the AS asks the account holder's Stelyph app to approve, the phone
confirms with Face ID and a signature, and the AS issues the session. No password
is typed anywhere, and the approving key never leaves the phone.

Because the approval is a signature over a per-request challenge, it is not a
shared secret the server could leak or replay — it is proof, for this one
request, that the approver holds a key the account enrolled.

## Three parts, landed in order of novelty

| Part | What | Status |
|---|---|---|
| **1. Device-approval core** | register a device key; start / poll / approve / deny a sign-in; issue the session | **LANDED** on the Worker, verified |
| **2. atproto OAuth surface** | `/oauth/par`, `/oauth/authorize`, `/oauth/token` on the Worker, with device-approval as the authenticate step | specced below; staged |
| **3. iOS approval UI** | Face-ID approval screen + device enrolment in the Stelyph app | specced below; staged |

Part 1 is the piece that did not exist and that 2 and 3 hang on. It stands alone:
it already performs a complete passwordless sign-in that issues account session
tokens, and it is what part 2 calls in place of the password check.

---

## Part 1 — device-approval core (landed)

All endpoints are per-account: they are served by the account's own Durable
Object, so the host *is* the account (e.g. `juice91.pds.spirallex.com`). A client
finds it the normal way — handle → DID → `serviceEndpoint`.

### Enrolment (once per device, password-gated)

```
POST /oauth/device/register
{ "handle", "password", "deviceDidKey": "did:key:zQ3s…", "label": "Joey's iPhone" }
→ { "deviceId": "…" }
```

Proving account control **once**, with the password, enrols a device public key.
From then on the password is never needed again — the device key, gated behind
Face ID on the phone, is the credential. The private half never leaves the phone;
only the `did:key` is sent.

### Sign-in (passwordless, from here on)

```
POST /oauth/signin/start           { "clientName": "Graysky" }
→ { "requestId", "userCode": "WXYZ-1234", "challenge": "<b64>", "expiresAt" }
```

The client shows `userCode`. The phone, having received the same request, shows
the client name and the same code so the human can confirm it is the sign-in they
started — then approves:

```
POST /oauth/device/approve
{ "requestId", "deviceId", "signature": "<b64 sig over challenge bytes>" }
→ { "ok": true }
```

The Worker verifies the signature over the exact challenge with the enrolled
device key (`verify_signature(deviceDidKey, challenge, sig)`), and only then mints
the session. The client, meanwhile, polls:

```
GET /oauth/signin/poll?requestId=…
→ { "status": "pending" | "approved" | "denied" | "expired",
    "did"?, "handle"?, "accessJwt"?, "refreshJwt"? }
```

`deny` is the same shape as `approve` and records an explicit refusal.

### Why each piece is there

- **Challenge signature, not a bearer code.** The device signs bytes bound to
  this one `requestId`. A challenge captured from one request cannot approve
  another, and the server stores nothing that could be replayed.
- **`userCode` is for the human, not the machine.** The signature already binds
  the approval to the request; the code lets the person verify *intent* — that
  the request on their phone is the one they just kicked off — which defeats a
  phisher who starts a sign-in and hopes the victim rubber-stamps it.
- **Password once, then never.** Enrolment needs proof of account control, and
  the password is what a fresh account has. After enrolment the security rests on
  possession of the device key + Face ID, which is stronger than a reusable
  password and never transits the network.
- **Single-use, expiring.** A request is consumed on approval/denial and expires
  (default 5 min); the challenge cannot be re-presented.

### Correctness notes / limits of this increment

- Sessions are issued as the account's access/refresh JWTs, matching the
  `createAccount` path. Binding them into the OAuth refresh-rotation chain
  (`OAuthStore`) comes with part 2.
- No rate limiting on `start`/`register` yet — noted, not built.
- Enrolment currently trusts the password over TLS; a future hardening is to
  enrol the first device during account creation, so a password is never sent
  post-signup.

---

## Part 2 — atproto OAuth surface on the Worker (staged)

For a *third-party* atproto app to use this, the Worker must serve the OAuth
endpoints it currently only advertises. The protocol logic is already portable in
`stelyph-core` (`oauth/{request,pkce,dpop,token,jwk,scope}.rs`) and `DoStore`
already implements `OAuthStore`; what is missing is the wasm HTTP glue — the same
"extract the axum handlers" work `rust-worker`'s crate note describes.

- `POST /oauth/par` — validate + store the pushed request (`oauth::request`),
  return `request_uri`.
- `GET /oauth/authorize` — resolve the pushed request and, **instead of a
  password page, call part 1**: create a sign-in request, show the `userCode`,
  and poll for approval. On approval, issue the authorization code
  (`issue_code`), redirect back.
- `POST /oauth/token` — exchange code → DPoP-bound access + rotating refresh
  (`oauth::token`), the parts already written and tested in core.

The only new idea versus a normal PDS is that the authenticate step is part 1
rather than a password — everything else is the existing, tested protocol code
re-hosted on wasm.

## Part 3 — iOS approval UI (staged)

- **Enrolment** on first cloud sign-in: generate a device keypair in the
  Secure Enclave, `POST /oauth/device/register` with the password once, store the
  private key non-exportable behind biometrics.
- **Approval**: a push (or foreground poll) surfaces "Graysky wants to sign in as
  @you — code WXYZ-1234". Face ID unlocks the device key; the app signs the
  challenge and calls `approve`. A mismatched code is a one-tap deny.
- Ties directly into the keys-on-device direction (see
  `docs/repo-on-device-pds-on-worker.md`): once the account signing key is on the
  phone, the same device that signs commits is the one that approves sign-ins.
```
