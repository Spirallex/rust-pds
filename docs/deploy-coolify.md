# Deploying stelyph with Coolify on a Mac Studio

Coolify is a self-hosted PaaS (git-push deploys, dashboard, TLS via Traefik). It
runs on **Linux + Docker**, not macOS — so on a Mac Studio it lives inside a
Linux VM. This runbook sets that up and deploys the `stelyph` container with the
`Dockerfile` + `.dockerignore` at the repo root.

> If all you wanted was "keep it running across reboots," Coolify is overkill —
> a `launchd` service is simpler. This doc is the **git-push + dashboard + TLS**
> path you chose.

---

## 0. Architecture

```
Mac Studio (macOS, arm64)
└─ OrbStack Linux VM (arm64, Docker)
   └─ Coolify (control plane)
      ├─ Traefik (reverse proxy / TLS)
      └─ stelyph container  ──>  /data volume  (pds.db lives here)
Public ingress: Traefik+Let's Encrypt (if public IP) OR a tunnel (if CGNAT)
```

## 1. Linux VM on the Mac Studio (OrbStack)

OrbStack is the lightest Docker/Linux VM on Apple Silicon.

```bash
brew install orbstack          # then launch OrbStack.app once
orb create ubuntu coolify-host # an arm64 Ubuntu machine
orb -m coolify-host            # shell into it
```

Inside the VM, make it server-like: enable Docker (OrbStack provides it),
ensure the VM autostarts (OrbStack setting: "Start at login").

## 2. Install Coolify (inside the VM)

```bash
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | sudo bash
```

Open `http://<vm-ip>:8000`, create the admin account, and register
**localhost** as the deployment server (Coolify manages the VM's own Docker).

## 3. Create the app

In Coolify: **+ New → Resource → Public/Private Repository** →
`https://github.com/spirallex/stelyph` (or your fork).

- **Build pack:** `Dockerfile` (Coolify auto-detects the root `Dockerfile`).
- **Branch:** `main`.
- **Port:** `3000` (matches `EXPOSE`/`PDS_PORT`).
- Enable **automatic deploy on push** (Coolify installs a GitHub webhook → every
  push to `main` rebuilds + redeploys).

## 4. Environment variables (Coolify → app → Environment)

Set these — the binary reads them all (`ServeArgs` is fully env-driven):

| Var | Value | Notes |
|---|---|---|
| `PDS_HOSTNAME` | `pds.tailXXXXXX.ts.net` | **must equal the existing account's hostname** (see §7) |
| `PDS_MODE` | `proxy` | TLS terminated upstream, not by the app |
| `PDS_PORT` | `3000` | |
| `PDS_DB_PATH` | `/data/pds.db` | on the persistent volume |
| `PDS_JWT_SECRET` | _(from `~/.stelyph.env`)_ | **mark Secret.** Must match the existing DB |
| `PDS_KEY_PASSPHRASE` | _(from `~/.stelyph.env`)_ | **mark Secret.** Decrypts the signing key in the DB |
| `PDS_RELAY_URL` | `https://bsky.network` | |
| `PDS_PLC_URL` | `https://plc.directory` | |

## 5. Persistent volume + migrate the existing DB

Add a **persistent volume** mounted at `/data` (Coolify → Storage). Then copy
your current database into it so the existing account/DID is preserved:

```bash
# from the Mac, into the VM, into the volume's host path:
orb push -m coolify-host ~/.stelyph/pds.db /tmp/pds.db
orb -m coolify-host 'sudo cp /tmp/pds.db <coolify-volume-path>/pds.db'
```

Coolify shows the volume's host path in the Storage tab. **Do not** let the
container run `init` against an empty volume — that mints a *new* did:plc and
orphans your identity (the exact failure from the Tailscale bring-up).

## 6. Ingress / TLS

**If the Mac Studio has a public IP / port-forward (:80,:443):** point a real
domain at it; Coolify/Traefik gets Let's Encrypt certs automatically. Set
`PDS_HOSTNAME` to that domain (then see §7 about the DID).

**If you're behind CGNAT / no public inbound (your current setup):** keep the
**Cloudflare Tunnel / Tailscale Funnel** terminating TLS, and point its ingress
at the container's published port (or at Traefik). TLS stays at the tunnel edge;
Coolify just runs the container. This keeps `PDS_HOSTNAME` unchanged → no DID
work needed.

## 7. ⚠️ Keep the hostname stable (or update the DID)

Your account's did:plc records `serviceEndpoint = https://pds.tailXXXXXX.ts.net`.
Federation resolves your handle → DID → that URL. If you **change** the public
hostname, you must submit a PLC operation to update the endpoint — which the
current build doesn't expose — and until then the network can't reach you.

**Recommendation:** keep serving on `pds.tailXXXXXX.ts.net` (route the tunnel to
the Coolify container). Only change hostnames if you're prepared to do a PLC
rotation.

## 8. Mac-as-server hardening (independent of Coolify)

- System Settings → Energy: **Start up automatically after a power failure**;
  prevent sleep; disable display-sleep-forces-sleep.
- OrbStack: start at login, so the VM (and Coolify) come back after reboot.
- Backups: snapshot `/data/pds.db` regularly (the app has a `backup.rs` path /
  use SQLite `VACUUM INTO`). The whole PDS state is that one file.

## 9. Deploy loop

After setup: `git push origin main` → webhook → Coolify rebuilds the image →
rolling redeploy. Watch logs in the Coolify dashboard; the app logs
`rust-pds listening on 0.0.0.0:3000 (hostname=…)` on start.
