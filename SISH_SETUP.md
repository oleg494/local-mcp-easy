# sish self-hosted tunnel

This guide covers running your own [sish](https://github.com/antoniomika/sish)
server as the tunnel backend for Local MCP Easy, instead of the bundled
Serveo relay or a full external reverse proxy. It is for operators who have
(or are willing to run) a small VPS and want a stable, shareable `https://`
URL without asking the client to install anything.

Three `tunnel_backend` values exist; this document is about the middle one:

- **`serveo`** (default) — the bundled path, zero setup, see
  [SERVEO_SETUP.md](SERVEO_SETUP.md).
- **`sish`** — a self-hosted `ssh -R` relay, same mechanics as Serveo, but
  the server is yours. The launcher still manages the SSH tunnel process for
  you. **This document.**
- **`custom-ssh`** — you run your own reverse proxy (nginx/Caddy/Traefik) and
  set `public_url` directly; the launcher starts no tunnel at all. See
  [REVERSE_PROXY.md](REVERSE_PROXY.md).

## What this is, and why

sish speaks the exact same protocol Serveo does: the launcher opens
`ssh -R <subdomain>:80:127.0.0.1:<port> <your-sish-host>`, and your sish
server publishes `https://<subdomain>.<your-domain>` and forwards traffic
back down the SSH connection to the local server on `127.0.0.1:8765`.
Nothing about the client-side flow changes — same reserved-hostname model,
same `SHOW_CONNECTION`/`show_connection.sh` output shape.

What changes is who operates the relay. Serveo is a shared, third-party
service — you don't control its timeouts, and long synchronous POSTs or
streaming tool calls (builds, `pip install`, long-running commands) can get
cut off after roughly 20-30 seconds of no bytes moving (see
[REVERSE_PROXY.md](REVERSE_PROXY.md)'s nginx notes for the same ceiling from
the other side). Running sish yourself means **you** set the idle/read
timeouts on the one node your traffic passes through.

Be precise about what problem this solves: it is a root fix for the churn
(one relay you control, with timeouts you set), not "remove the limit." If
your sish server (or a proxy in front of it) still has a short idle timeout,
you will see the exact same symptom you saw with Serveo — you've just moved
the ceiling, not removed it. The verification section below is how you
confirm you actually fixed it, not just moved it.

## Threat model — read this first

> A self-hosted sish server is a public entry point to a server that
> executes commands.

If your Local MCP Easy config allows commands (`mcp:commands:run`, trusted
developer mode — see [SECURITY.md](SECURITY.md), "Trusted developer mode"),
then anything that can reach your sish server's HTTP listener and
successfully authenticate as an MCP client can run code as the Windows user
the launcher runs under. Treat the VPS and the subdomain like you'd treat
any other public-internet endpoint in front of a code-execution backend:

- **OAuth stays mandatory on the public URL, no exceptions.** Do not run
  `legacy` mode with a bare Bearer token as your only gate on a self-hosted
  sish endpoint, and do not add a dev bypass "just for testing" — a public
  sish subdomain is not a dev environment. `oauth`/`dual` plus the
  owner-code consent gate (see [SECURITY.md](SECURITY.md), "Universal
  OAuth") is the baseline, not an upgrade.
- **Decide who the client is, explicitly, before you open the port.** A
  self-hosted relay is more work than Serveo specifically because you now
  also own the perimeter. If the honest answer is "just me, from my own
  laptop and phone," read the last section below before you provision a
  VPS for this.
- **Consider narrowing further than OAuth alone.** An IP allowlist (sish's
  `--whitelisted-ips`, or a firewall rule) or mTLS in front of the HTTP
  listener are both reasonable if your set of clients is small and known.
  Neither replaces OAuth — they reduce who can even attempt the OAuth
  handshake.

## VPS setup

You need a small VPS with a public IP, a domain (or subdomain) you can point
wildcard DNS at, and either Docker or a Go toolchain to run
[sish](https://github.com/antoniomika/sish).

**1. Wildcard DNS.** Point `*.tunnel.example.com` (an `A`/`AAAA` record) at
the VPS. sish binds subdomains under one root domain (its own `-d/--domain`
flag) and needs the wildcard to resolve before it can serve any of them.

**2. Run sish.** Docker is the fastest path:

```bash
docker run -itd --name sish \
  -v ~/sish/ssl:/ssl \
  -v ~/sish/keys:/keys \
  -v ~/sish/pubkeys:/pubkeys \
  --net=host antoniomika/sish:latest \
  --domain=tunnel.example.com \
  --ssh-address=:2222 \
  --http-address=:80 \
  --https-address=:443 \
  --https=true \
  --force-https=true \
  --https-ondemand-certificate=true \
  --https-ondemand-certificate-accept-terms=true \
  --https-ondemand-certificate-email=you@example.com \
  --https-certificate-directory=/ssl \
  --authentication-keys-directory=/pubkeys \
  --private-keys-directory=/keys \
  --bind-random-subdomains=false \
  --force-requested-subdomains
```

(A prebuilt binary from sish's releases works the same way with the same
flags, if you'd rather not run Docker.)

What each piece is doing, mapped to the requirements:

- **`--ssh-address=:2222`** — a *non-standard* SSH port for sish's tunnel
  listener. Your VPS's own admin `sshd` should stay on port 22; sish gets
  its own port so the two don't collide. Whatever you pick here is what
  goes in the client's `tunnel_ssh_port`.
- **`--https-ondemand-certificate=true`** (+ `-accept-terms` + `-email`) —
  sish's built-in ACME/Let's Encrypt integration. It requests a certificate
  per subdomain on first use; you don't run certbot separately.
- **`--authentication-keys-directory=/pubkeys`** — pubkey-only auth. Drop
  the **public** half of the client's `ssh_key` in this directory (sish
  watches it live, no restart needed); anything not in there cannot open a
  tunnel.
- **`--bind-random-subdomains=false`** + **`--force-requested-subdomains`**
  — together these forbid random/anonymous tunnels: a client must request a
  specific subdomain (the reserved `serveo_hostname`), and the bind fails
  outright if that exact subdomain isn't available, instead of silently
  handing back a different one. Without this pair, sish's default behavior
  (`--bind-random-subdomains` defaults to `true`) is to assign a random
  subdomain, which breaks OAuth's requirement for a stable URL (see "The
  invariant" below).

**3. Firewall.** Open the ports you configured above (2222/tcp, 80/tcp,
443/tcp in this example) and nothing else related to sish. Leave your
normal admin SSH (22/tcp) locked down the way you already lock it down.

## Client setup (Local MCP Easy side)

On the Windows machine, either run the wizard:

```
python launcher.py --tunnel-setup
```

(ships alongside this guide as `TUNNEL_SETUP.bat` / `tunnel_setup.sh`), or
edit `config.json` directly (under `%LOCALAPPDATA%\LocalMcpEasy`) with these
fields — this is the full set; nothing else is read for the sish backend:

| Field | Meaning |
|---|---|
| `tunnel_backend` | `"sish"` (default is `"serveo"`; the third value is `"custom-ssh"`, see the top of this doc) |
| `tunnel_host` | The sish server's SSH endpoint, e.g. `tunnel.example.com` |
| `tunnel_ssh_port` | The port from `--ssh-address` above, e.g. `2222`. Leave empty for the standard port 22 |
| `tunnel_domain` | The public wildcard domain, e.g. `tunnel.example.com` (matches sish's own `-d/--domain`) |
| `serveo_hostname` | Reused field name — your reserved subdomain label, e.g. `mybox` (**not** a full hostname) |
| `ssh_key` | Path to the **private** key whose public half you dropped in sish's `--authentication-keys-directory` |

Example `config.json` fragment:

```json
{
  "tunnel_backend": "sish",
  "tunnel_host": "tunnel.example.com",
  "tunnel_ssh_port": "2222",
  "tunnel_domain": "tunnel.example.com",
  "serveo_hostname": "mybox",
  "ssh_key": "C:\\Users\\you\\.ssh\\sish_local_mcp"
}
```

The resulting public URL is printed (and used as the OAuth base) as:

```
https://<serveo_hostname>.<tunnel_domain>
```

— in the example above, `https://mybox.tunnel.example.com`. The key must be
authorized on sish (VPS setup, step 2) *before* you start the launcher, or
the tunnel fails to bind.

## The invariant

Same rule as [REVERSE_PROXY.md](REVERSE_PROXY.md)'s "THE INVARIANT,"
restated for this backend:

> **The subdomain sish actually publishes must exactly equal the URL the
> launcher prints and OAuth uses.**

With `tunnel_backend: "sish"` this is enforced by construction — the
launcher derives the public URL from `serveo_hostname` + `tunnel_domain`
(the same values it hands to `ssh -R`), it does not read it back from
anywhere else — so it holds automatically as long as
`--force-requested-subdomains` is set on the sish side (VPS setup, step 2).
If that flag is missing and sish silently reassigns a different subdomain,
the launcher keeps advertising the URL it *asked for*, not the one you
actually got, and OAuth discovery/redirect/audience checks break exactly
the way they do for a proxy mismatch in REVERSE_PROXY.md.

OAuth additionally needs the URL to be **stable** across restarts — a
reserved subdomain on your own domain satisfies that the same way a
reserved Serveo hostname does. `public_url` must be `https://`; that's
enforced server-side regardless of backend.

## Verify it actually fixes churn

Do not consider this "done" once the tunnel connects and `/mcp` responds —
that only proves the happy path. The thing you're actually fixing is
Serveo's timeout ceiling, and the only way to know it's fixed is to
reproduce the failure and watch it not happen. Each step here is
"configured → verified," not "flag removed → done":

1. **Stand it up.** Configure the fields above, start the launcher
   (`START.bat` / `start.sh`), and confirm `SHOW_CONNECTION.bat` /
   `show_connection.sh` reports `sish self-hosted
   (https://<hostname>.<tunnel_domain>)`.
2. **Reproduce the original symptom on purpose.** Run something that
   previously choked on Serveo around the ~20-30s mark — a real build, a
   `pip install` of something non-trivial, or any tool call whose output
   streams for a couple of minutes — through the sish URL.
3. **Confirm the failure is actually gone.** Watch the request to
   completion. You should *not* see `Terminating session: None` or a
   mid-stream disconnect in the launcher/server output. If you do, the
   ceiling moved but didn't disappear — check the idle/read timeout on sish
   itself and on anything sitting in front of it.
4. **If you additionally front sish with nginx/Caddy/Traefik** (extra
   routing, a second TLS layer, etc.) — apply the exact same treatment
   [REVERSE_PROXY.md](REVERSE_PROXY.md) documents for fronting the local
   server directly: disable response buffering, raise
   `proxy_read_timeout`/`proxy_send_timeout` (or the Caddy/Traefik
   equivalents) well past a minute. The SSE/streaming requirements are
   identical; sish being in the middle doesn't change them.
5. **Re-run step 2 after any timeout change** you make anywhere in the
   chain (sish flags, an extra proxy, the VPS's own network stack) before
   calling it fixed.

## Do you actually need this?

Be honest about the access pattern before provisioning a VPS. sish is the
right tool when you need a **public, shareable** `https://` URL and the
"the client installs nothing" property that makes Serveo/sish attractive in
the first place.

If the real answer is "I only ever connect from my own devices" — a laptop,
a phone, a second desk — [Tailscale](https://tailscale.com) or plain
WireGuard is simpler and safer than either Serveo or self-hosted sish: your
Windows machine never gets a public listener at all, there's no subdomain
to defend, no OAuth-vs-perimeter question to answer, and no VPS to patch.
Point your MCP client at the machine's Tailscale/WireGuard address and skip
the tunnel entirely.

Reach for sish specifically when at least one of these is true: the MCP
client itself needs a plain `https://` URL with no VPN client installed
alongside it, or you need to hand a working connection to someone or
something outside your own device mesh. If neither applies, this whole
document is solving a problem you don't have.

## See also

- [REVERSE_PROXY.md](REVERSE_PROXY.md) — the `custom-ssh` path (launcher
  manages no tunnel at all), the invariant in full, and the nginx/Caddy/
  Traefik configs referenced in the verification section above.
- [SECURITY.md](SECURITY.md) — the full security model: OAuth requirement,
  trusted developer mode, Host allowlist, secret handling.
