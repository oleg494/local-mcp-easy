# Reverse proxy setup

This guide covers exposing Local MCP Easy behind your **own** reverse proxy
(nginx, Caddy, Traefik) instead of the built-in Serveo tunnel. It is for
operators who already own a domain and a TLS certificate.

If you do not have a domain/VPS, use the bundled Serveo path instead — see
[SERVEO_SETUP.md](SERVEO_SETUP.md).

## What the server exposes

The local server (`server.py`) binds to **`127.0.0.1`** on the configured
port (default **8765**, overridable via `port` in `config.json` or the
`MCP_PORT` env var). It never listens on a public interface on its own. The
endpoints your proxy must reach:

- **`POST /mcp`** — the Streamable HTTP MCP endpoint. This is the one you
  point MCP clients at. It speaks HTTP request/response with optional SSE
  streaming, so the proxy must be WebSocket/SSE-friendly (long-lived
  connections, no aggressive buffering).
- `GET /health` — liveness probe, Bearer-token-gated. Useful for the proxy's
  health check, but not required for MCP traffic.
- `GET /.well-known/oauth-protected-resource/mcp` and the OAuth discovery /
  `/authorize`, `/token`, `/consent`, `/register`, `/revoke` routes — only
  present in `oauth` / `dual` auth modes. The proxy should pass the **whole
  host** through, not just `/mcp`, so OAuth discovery and redirects resolve
  to the public URL.

A reverse proxy should route the entire host (all paths) at
`https://<your-public-host>/` → `http://127.0.0.1:8765/`, with `/mcp` called
out specifically because that is the client-facing endpoint.

## TLS termination

**You own TLS termination.** The local server speaks plain HTTP on loopback.
The proxy must present the public HTTPS certificate and terminate TLS before
forwarding to `http://127.0.0.1:8765`. Never expose `127.0.0.1:8765` directly
to the network — there is no TLS on that port, and the Host allowlist trusts
the `Host` header the proxy sends (see the known limitation below).

The public URL **must** be `https://` for OAuth. The server enforces this:
OAuth mode refuses to start unless `PUBLIC_URL` is `https://` (or
`http://127.0.0.1` / `http://localhost` for local testing). See
[SECURITY.md](SECURITY.md), "Universal OAuth".

---

## THE INVARIANT (read this first)

> **`public_url` MUST EXACTLY equal the proxy's external base URL.**

Concretely: if nginx/Caddy/Traefik serves the public at
`https://mcp.example.com/`, then `public_url` (stored in `config.json`, set
via the OAuth setup wizard) must be exactly **`https://mcp.example.com`**
(no trailing slash, no `/mcp` suffix, matching scheme/host/port).

Why this is load-bearing: the OAuth Authorization Server's **issuer**,
**discovery metadata**, **registered redirect URIs** and **token audience**
(RFC 8707 resource indicators) are all derived from `PUBLIC_URL`, which in
turn comes from `public_url` → the `MCP_PUBLIC_URL` env var. If the public
URL the proxy serves and the URL the server believes it has diverge, then:

- OAuth metadata advertises the wrong issuer → clients cannot discover
  `/authorize`, `/token`, `/register`;
- redirect URIs registered by clients do not match what the server expects;
- issued access tokens have an `aud` that does not match the resource
  indicator the server computes for incoming requests → token validation
  fails;
- the Host check (below) can reject the request.

The same applies in the Bearer-token (`legacy`/`dual`) path: the URL you put
in the client must end in `/mcp` on this same host. The base URL (scheme +
host [+ port]) is the value that must match `public_url`.

OAuth additionally requires a **stable** URL — the public host must not change
across restarts. A reserved Serveo hostname satisfies this; so does your own
fixed domain. A `https://` public URL (or `http://127.0.0.1` for local
testing) is enforced server-side.

---

## How to set `public_url`

`public_url` is a key in `config.json` (under
`%LOCALAPPDATA%\LocalMcpEasy`). The supported way to set it is the OAuth setup
wizard — run **`OAUTH_SETUP.bat`** on the **Windows host** (where `config.json`
lives under `%LOCALAPPDATA%\LocalMcpEasy`), not on the proxy VPS — there is no
POSIX setup wrapper in this release. In the wizard:

1. Pick `oauth` or `dual` as the auth mode (a custom URL is only relevant for
   these; `legacy` does not use `public_url`).
2. At the *"Custom stable public URL (own domain/reverse proxy), or Enter to
   use a reserved Serveo hostname"* prompt, paste your public base URL, e.g.
   `https://mcp.example.com` (just the base — no path, no trailing slash).

The launcher reads `public_url` and passes it to the server as the
`MCP_PUBLIC_URL` environment variable (see `launcher.py: start_server`).
`server.py` then uses `MCP_PUBLIC_URL` as `PUBLIC_URL` for the OAuth issuer,
discovery documents and token audience.

The value must be `https://` (or `http://127.0.0.1` / `http://localhost` with
an optional port for local testing). Anything else is rejected.

## Serveo is skipped automatically

When `public_url` is set, the launcher does **not** start a Serveo tunnel.
`launcher.py: config_uses_serveo()` returns `False` whenever `public_url` is
non-empty, and `run()` takes the custom-URL branch: it starts the local
server, waits for the localhost `/health` check, publishes the connection
file with your `public_url`, and then just watches the server process. No
Serveo SSH process is spawned, and the launcher prints a reminder that *you*
are responsible for routing the public URL to `127.0.0.1:port`.

So once `public_url` is set: configure the proxy (below), run `START.bat`,
and point your MCP client at `https://<your-host>/mcp`.

---

## nginx

Route the whole host to the local port; `/mcp` is highlighted because that is
the client-facing endpoint. MCP Streamable HTTP uses request/response with
optional SSE, so set headers for WebSocket/SSE friendliness and a generous
read timeout.

```nginx
# /etc/nginx/conf.d/mcp.conf  (or sites-available/mcp)
server {
    listen 443 ssl http2;
    server_name mcp.example.com;

    ssl_certificate     /etc/letsencrypt/live/mcp.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mcp.example.com/privkey.pem;

    # Whole host → 127.0.0.1:8765 (loopback only; never expose the port directly)
    location / {
        proxy_pass http://127.0.0.1:8765;

        # Host header pass-through: the server's Host allowlist must see the
        # PUBLIC host (mcp.example.com), not 127.0.0.1. proxy_set_header Host
        # below sets it to the external host — keep this.
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE / Streamable HTTP friendly: disable buffering, allow long-lived
        # connections, long timeouts.
        proxy_buffering         off;
        proxy_cache             off;
        proxy_http_version      1.1;
        proxy_set_header        Upgrade    $http_upgrade;
        proxy_set_header        Connection "upgrade";

        # OAuth metadata fetches, /authorize round-trips and long tool calls
        # (builds, test runs) can outlast the default 60s timeout.
        proxy_read_timeout  600s;
        proxy_send_timeout  600s;
        proxy_connect_timeout 10s;
    }

    # /mcp is the client-facing endpoint; everything above already covers it,
    # but it is called out here for clarity. Same upstream, same headers.
    # location /mcp { proxy_pass http://127.0.0.1:8765; ... }  -- redundant

    # Optional health check target (Bearer-token-gated on the server side):
    #   GET https://mcp.example.com/health  with Authorization: Bearer <token>
}
```

Key points:

- **`proxy_set_header Host $host;`** — pass through the *public* Host
  (`mcp.example.com`). The server's Host allowlist compares the Host header to
  `localhost`, `*.serveousercontent.com`, and (in `oauth`/`dual` mode, when
  `public_url` is set) the configured public host. If nginx rewrites Host to
  `127.0.0.1`, that is still allowed (loopback is on the allowlist), but the
  cleanest setup is to pass the public Host so the OAuth `iss`/`aud` path and
  the Host check agree.
- `proxy_buffering off` + `proxy_http_version 1.1` + Upgrade/Connection
  headers keep Streamable HTTP SSE streams from stalling.
- `proxy_read_timeout 600s` — Serveo imposes a ~20–30s practical ceiling on
  long synchronous POSTs; your own proxy removes that ceiling, so set it
  generously for builds / `pip install` / test runs.

## Caddy

Caddyfile with automatic HTTPS (Let's Encrypt / ZeroSSL) and
`reverse_proxy` to the local port:

```caddyfile
# Caddyfile
mcp.example.com {
    reverse_proxy 127.0.0.1:8765 {
        # Pass the public Host through (Caddy does this by default; keep it).
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}

        # Streamable HTTP / SSE: long-lived connections, no flush buffering.
        flush_interval -1
        transport http {
            dial_timeout 10s
        }
    }

    # /mcp is covered by the whole-site reverse_proxy above. No extra block
    # needed — Caddy proxies all paths to 127.0.0.1:8765.
}
```

Caddy terminates TLS automatically and renews the certificate for
`mcp.example.com`. The **invariant** still applies: set `public_url` to
exactly `https://mcp.example.com` via **`OAUTH_SETUP.bat`** (run on the Windows
host where `config.json` lives, not on the proxy VPS). Caddy passes Host as the
public host by default; do not rewrite it to `127.0.0.1`.

## Traefik

Two equivalent options — labels (Docker provider) or a static file. The local
server is not in a container here, so the file provider is the direct fit;
the label form is shown for when the server runs in a container.

### File provider (recommended for a host-installed server)

```yaml
# traefik.yml (static)
entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

providers:
  file:
    directory: /etc/traefik/dynamic

certificatesResolvers:
  letsencrypt:
    acme:
      email: you@example.com
      storage: /acme.json
      httpChallenge:
        entryPoint: web
```

```yaml
# /etc/traefik/dynamic/mcp.yml (dynamic)
http:
  routers:
    mcp:
      rule: "Host(`mcp.example.com`)"
      entryPoints:
        - websecure
      service: local_mcp
      tls:
        certResolver: letsencrypt

  services:
    local_mcp:
      loadBalancer:
        passHostHeader: true          # pass the public Host to the server
        servers:
          - url: "http://127.0.0.1:8765"
```

### Labels (Docker provider) — when the server runs in a container

```yaml
# docker-compose.yml
services:
  local-mcp:
    image: your/local-mcp-image
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.mcp.rule=Host(`mcp.example.com`)"
      - "traefik.http.routers.mcp.entrypoints=websecure"
      - "traefik.http.routers.mcp.tls.certresolver=letsencrypt"
      - "traefik.http.routers.mcp.service=mcp"
      - "traefik.http.services.mcp.loadbalancer.server.port=8765"
      - "traefik.http.services.mcp.loadbalancer.passhostheader=true"
      # /mcp is the client-facing path; Host() routing covers the whole host.
```

For Traefik: `passHostHeader: true` (or `passhostheader=true`) is the
equivalent of nginx's `Host $host` — the server must see the public host, not
`127.0.0.1`. Traefik's default read timeout is generous; if you cap it, allow
several minutes for long tool calls. The **invariant** applies unchanged:
`public_url` = `https://mcp.example.com`.

---

## Known limitation: the Host allowlist vs. forwarded headers

The server validates the `Host` header on every request
(`server.py: _host_allowed`, enforced by `SecurityMiddleware` in `legacy`
mode and `HostCheckMiddleware` in `oauth`/`dual` mode; a mismatch returns
**HTTP 403 `forbidden host`**). The allowlist permits:

- `127.0.0.1` and `localhost` (loopback),
- `*.serveousercontent.com` (reserved Serveo hostnames), and
- **the host of `public_url`** (in `oauth`/`dual` mode, when `public_url` is
  set).

In legacy mode the public host is **not** added to the allowlist; pass
`Host: 127.0.0.1` or use `oauth`/`dual` for a public-host proxy.

The FastMCP SDK's own localhost-only DNS-rebinding Host check is **disabled**
(`transport_security=enable_dns_rebinding_protection=False`) precisely because
it returns HTTP 421 behind a tunnel/proxy; the project's Host allowlist
replaces it.

**What this means for a reverse proxy:** a proxy that forwards the Host
header as the public domain (nginx `Host $host`, Caddy default, Traefik
`passHostHeader: true`) **should pass** once `public_url` is set to that
domain — the public host is then on the allowlist. A proxy that rewrites the
Host to `127.0.0.1` also passes, because loopback is allowed.

However, the specific Host-check-vs-forwarded-header code path has **not**
been tested against every proxy configuration (e.g. proxies that strip the
Host header, set it to an IP, or inject a `X-Forwarded-Host` that the server
does not read — the server reads the `Host` header only, not
`X-Forwarded-Host`). If you see an unexpected **HTTP 403 `forbidden host`**
(or an HTTP 421 from the SDK path):

1. **Fallback:** temporarily switch to a reserved Serveo hostname via
   `SETUP.bat` (this is the supported, tested public-URL path and always
   passes the Host check).
2. **Or** report the failure (proxy, config, exact response) so it can be
   addressed in a 2.3.1 code fix.

Per the 2.3.0 release decision (§5 is docs-only), no Host-check code change
is made in this release unless a real 421/403 is reported against a
reverse-proxy setup.

## Security notes

- Keep `127.0.0.1:8765` bound to loopback; do not expose it on `0.0.0.0`.
  The server already binds to `127.0.0.1` only (`server.py: uvicorn.run`).
- Treat the public URL and the Bearer token as secrets — see
  [SECURITY.md](SECURITY.md).
- The Bearer token / OAuth owner code are stored in `config.json` under
  `%LOCALAPPDATA%\LocalMcpEasy`; never commit them.
- In `oauth`/`dual` mode, the `mcp:commands:run` scope is arbitrary code
  execution with the OS user's rights. Only approve fully trusted clients.
  See [SECURITY.md](SECURITY.md), "Trusted developer mode".

## See also

- [SERVEO_SETUP.md](SERVEO_SETUP.md) — the bundled Serveo tunnel path.
- [SECURITY.md](SECURITY.md) — the full security model, OAuth details, Host
  allowlist rationale.
- README — auth modes (`legacy` / `oauth` / `dual`), client setup.
