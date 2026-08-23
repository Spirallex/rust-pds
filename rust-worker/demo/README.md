# Sign in with Stelyph — web demo

`index.html` is a self-contained demo of passwordless, phone-approved sign-in
against the live Worker. No build step, no dependencies — just open the file.

## Run it

Open `index.html` in a browser (double-click, or host it anywhere). The Worker
answers with permissive CORS, so `file://` works too. It also deploys to
Cloudflare Pages as-is: `wrangler pages deploy rust-worker/demo`.

1. **Account** — type your handle (e.g. `c91.pds.spirallex.com`, or just `c91`).
2. **The website** (left) — click *Sign in with Stelyph*. It calls
   `POST /oauth/signin/start`, shows the user code, and polls
   `GET /oauth/signin/poll` for the result.
3. **Your phone** (right, simulated) — enroll the browser once with your account
   password (`POST /oauth/device/register`); a non-extractable **P-256** key is
   generated via WebCrypto and stored in IndexedDB. From then on it lists pending
   sign-ins (`GET /oauth/signin/pending`) and **approves** them by signing the
   challenge (`POST /oauth/device/approve`) — no password, exactly what the iOS
   app does behind Face ID.

For a true cross-device demo, open the page on your phone for panel 2 and on a
laptop for panel 1 (same handle). Or use the real Stelyph iOS app as the
approver and only panel 1 here.

## The flow

```
website                         account host (Durable Object)          phone/app
  │  POST /oauth/signin/start ─────────►                                   │
  │  ◄──── requestId, userCode ─────────                                   │
  │  (show userCode, poll) ────────────►  GET /oauth/signin/poll           │
  │                                        GET /oauth/signin/pending ◄──────┤
  │                                        (client_name, userCode) ────────►│
  │                                                       sign challenge ◄──┤
  │                              POST /oauth/device/approve ◄───────────────┤
  │  ◄──── status:approved + session ───  (verify sig, issue tokens)        │
```

The signed value is
`"stelyph-signin-approval:v1:" + requestId + ":" + userCode` — a per-request
challenge, so a signature proves control for this one sign-in and can't be
replayed. See `rust-worker/SIGN-IN-WITH-STELYPH.md` for the full spec.

## Notes

- Enrolling on the right panel is a real mutation on the named account (adds a
  device key). Use an account you control; the password is sent once, only to
  enroll, and never stored.
- The device private key is non-extractable and lives in IndexedDB — *Forget
  device* clears it. It does not remove the enrollment server-side.
