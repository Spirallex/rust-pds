# Security Policy

Stelyph is a self-hosted AT Protocol PDS: it guards your identity keys, your data,
and your federation presence. Security reports are taken seriously and handled
promptly.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

- Preferred: [**Report a vulnerability**](https://github.com/Spirallex/rust-pds/security/advisories/new)
  via GitHub's private vulnerability reporting (enabled for this repo).
- Alternatively: email <joey@spirallex.com> with a description, reproduction steps,
  and the version/commit affected.

What to expect:

- **Acknowledgement within 72 hours.**
- A fix or mitigation plan communicated within 14 days for confirmed issues.
- Coordinated disclosure: we ask for up to 90 days before public disclosure; credit
  is given in the advisory unless you prefer otherwise.

## Supported versions

Stelyph is **pre-1.0 alpha software**. Only the **latest release** receives security
fixes; there are no maintenance branches. If you run an older build, update before
reporting.

## Scope

In scope (examples):

- Authentication/authorization bypass on any XRPC endpoint
- Extraction or misuse of signing-key material (at rest or in memory)
- Invite/registration gate bypass
- Cross-account data access (repo records, blobs, preferences)
- Identity spoofing in federation surfaces (handle resolution, `/.well-known/*`, firehose)
- Vulnerabilities in the release/install pipeline (installer script, artifact integrity)

Out of scope:

- Denial of service against an instance you operate yourself
- Vulnerabilities requiring a compromised operator machine or root access
- Issues in third-party dependencies already tracked upstream (Dependabot monitors
  these), unless Stelyph uses the dependency unsafely
- Social engineering, physical attacks

## Security model (what protects your data)

- **Keys encrypted at rest:** account signing keys are stored encrypted with
  AES-256-GCM under a key derived via Argon2id with **pinned parameters** (a crate
  upgrade cannot silently weaken the KDF). Derived key material is zeroized from
  memory after use.
- **Secrets never touch the config file:** `PDS_JWT_SECRET` and
  `PDS_KEY_PASSPHRASE` are supplied via environment only; `stelyph init` prints the
  generated JWT secret exactly once and never persists it.
- **No privileged network surface:** admin operations (`stelyph admin …`) act
  directly on the local database file. There is no admin HTTP API to expose or
  misconfigure.
- **Invite-gated registration by default:** open registration is an explicit
  opt-in flag.
- **Key portability without leakage:** `export-keys` writes passphrase-verified,
  still-encrypted key material with `0600` permissions.

## Release integrity

- Every release artifact ships with a `.sha256` checksum.
- Releases are built by this repository's GitHub Actions workflow from tagged
  source; **Sigstore build-provenance attestations** are enabled for all releases
  after `v0.1.0-alpha.1`. Verify an artifact was built by this repo's CI:

  ```sh
  gh attestation verify stelyph-x86_64-unknown-linux-musl.tar.xz --repo Spirallex/rust-pds
  ```

- The `main` branch is protected (no force-pushes, no deletion, PR review
  required), and the repository has GitHub secret scanning with push protection
  enabled.

## Hardening tips for operators

- Run in proxy mode behind a TLS-terminating tunnel/proxy; don't expose the plain
  HTTP port beyond localhost.
- Back up `pds.db` — it is the whole PDS state. Treat backups as
  sensitive: they contain your (encrypted) keys and all account data.
- Keep `PDS_JWT_SECRET` and `PDS_KEY_PASSPHRASE` in a secrets manager or a
  `0600`-permission env file, never in shell history or the config file.
