> Short English overview. The primary, most detailed documentation is in Russian: [README.md](README.md).

# Local MCP Easy

[![CI](https://github.com/oleg494/local-mcp-easy/actions/workflows/ci.yml/badge.svg)](https://github.com/oleg494/local-mcp-easy/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/oleg494/local-mcp-easy?sort=semver)](https://github.com/oleg494/local-mcp-easy/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10--3.13-blue.svg)
![Tests](https://img.shields.io/badge/tests-259%20passing-brightgreen.svg)

Run local filesystem, command and Git tools through MCP using
Streamable HTTP and OAuth 2.1.

One-click local MCP server for Windows: your AI agent gets safe, bounded
tools to read, search and edit files in a workspace folder you choose — with
an optional trusted developer mode (Python, Git, Node) and a guarded Git
setup-flow. A stable public URL is provided by a reserved Serveo tunnel or
your own reverse proxy.

Compatible with Hyperagent, Notion and other MCP clients.

> Built for personal use on your own computer. This is not a multi-user
> public service. See [SECURITY.md](SECURITY.md) for the security model.

## Authentication modes

- **Dual** — OAuth and legacy clients simultaneously on the same `/mcp` endpoint (**default** since 2.1.0)
- **OAuth** — standards-based OAuth 2.1 with Dynamic Client Registration and PKCE (`S256`)
- **Legacy** — static Bearer token (the classic 1.x behaviour)

```text
Static-token client ── Bearer ─┐
                               ├─ /mcp → the same MCP tool set
OAuth client ──── OAuth 2.1 ───┘
```

Pick the mode with `OAUTH_SETUP.bat`. Since 2.1.0 the default for new installs
is `dual` (Bearer token + OAuth on one endpoint) and `SETUP.bat` generates the
owner code automatically; upgrades keep an existing config unchanged (a config
that predates `auth_mode` stays `legacy`).

## Quick start (Windows)

1. Unpack the release archive anywhere.
2. Double-click `START.bat` and pick a workspace folder on first run.
3. Keep **trusted developer mode off** unless you need to run commands.
4. Connect your MCP client:
   - **Static-token client (e.g. Notion Custom MCP):** copy the shown URL and
     Bearer token.
   - **OAuth client (e.g. Hyperagent):** run `OAUTH_SETUP.bat` once, choose
     `dual` or `oauth`, then add the server URL
     (`https://<hostname>.serveousercontent.com/mcp`) in the client. The
     client discovers OAuth metadata automatically, registers itself (DCR)
     and opens the `/consent` page — approve it with your **owner code**.
5. Keep the launcher window open while the server runs.

OAuth needs a stable public URL: a reserved Serveo hostname
([SERVEO_SETUP.md](SERVEO_SETUP.md)) or your own domain via a custom
`public_url` (your reverse proxy, no Serveo involved; see
[REVERSE_PROXY.md](REVERSE_PROXY.md) for nginx/Caddy/Traefik configs). Pure `oauth` refuses to
start without one; `dual` starts with a warning (the Bearer half works; the
OAuth half stabilises once the URL is stable). On a free Serveo tunnel the
one-time "you are about to visit…" interstitial can strip the `/authorize`
query string on the first visit — if you hit a `Field required` error, press
Back and retry Connect; the server shows a friendly hint page for this case.

## What's implemented (OAuth)

- Authorization Code Flow + PKCE `S256` (the only supported method)
- Dynamic Client Registration (`POST /register`) and pre-registered
  "bring your own app" clients (`REGISTER_OAUTH_CLIENT.bat`)
- Owner consent page: open DCR grants nothing by itself — every authorization
  must be approved with the owner code (constant-time compare, per-transaction
  attempt cap, self-healing rate limit; a correct code always works, so the
  owner can never be locked out)
- Short-lived access tokens audience-bound to `/mcp` (RFC 8707), rotating
  refresh tokens, single-use authorization codes with replay revocation,
  `POST /revoke`
- Discovery: RFC 8414 authorization-server metadata, RFC 9728 protected
  resource metadata (path-aware and root alias), `WWW-Authenticate` with
  `resource_metadata` on 401
- OAuth state stores **SHA-256 hashes** of tokens only, survives restarts, and
  a corrupted state file never crashes startup

## Scopes

| Scope | Tools |
| --- | --- |
| `mcp:files:read` | `workspace_info`, `list_dir`, `file_info`, `read_file`, `glob_files`, `grep_files` |
| `mcp:files:write` | `write_file`, `append_file`, `edit_file`, `create_dir`, `delete_file`, `copy_file`, `move_file` |
| `mcp:commands:run` | `run_command` (also requires trusted developer mode) |
| `mcp:git` | `repo_context_status`, `inspect_git_repository`, `configure_repo_context`, `setup_git_context` |

Scope checks run before every tool call, deny-by-default. Clients that
register without requesting scopes get the least-privilege default
(`mcp:files:read` + `mcp:files:write`). **`mcp:commands:run` is near-full
system access** in trusted developer mode — grant it explicitly and only to
fully trusted clients. For a single-owner setup you can also pin a fixed
grant for every approved client via `MCP_OAUTH_OWNER_GRANT_SCOPES`.

## Management

- `START.bat` — create the local `.venv`, install dependencies, start the server and tunnel
- `STOP.bat` — stop only this MCP's processes after identity checks
- `SETUP.bat` — re-run the setup wizard (token is kept)
- `OAUTH_SETUP.bat` — choose `legacy / oauth / dual`, set a custom public URL, manage the owner code
- `REGISTER_OAUTH_CLIENT.bat` — pre-register an OAuth client (public PKCE or confidential)
- `SHOW_CONNECTION.bat` — show connection info with secrets masked (`--full` reveals)
- `launcher.py --add-command NAME` / `--remove-command NAME` — safely edit the
  command allowlist without hand-editing JSON

Configuration lives in `%LOCALAPPDATA%\LocalMcpEasy` (settings from the
pre-2.0 `NotionMcpEasy` directory are migrated automatically on first run).

## Compatible clients

- Hyperagent (OAuth, Streamable HTTP)
- Notion Custom MCP (static Bearer token)
- Other Streamable HTTP MCP clients — OAuth 2.1 or static token

## Documentation

- [README.md](README.md) — primary documentation (Russian)
- [SECURITY.md](SECURITY.md) — security model
- [SERVEO_SETUP.md](SERVEO_SETUP.md) — stable tunnel setup
- [REVERSE_PROXY.md](REVERSE_PROXY.md) — own-domain reverse proxy (nginx/Caddy/Traefik)
- [CHANGELOG.md](CHANGELOG.md) — release history

## Verification

```bat
.venv\Scripts\python -m unittest discover -s tests -v
.venv\Scripts\ruff check .
```

The suite (147 tests) covers path traversal, token auth, the full OAuth flow
(DCR, PKCE, consent, rotation, replay revocation, revocation, restart
survival), per-tool scope enforcement, dual mode, the git guard-layer and the
launcher.

## Project history

Local MCP Easy evolved from the original `notion-local-mcp-easy` project.

The Universal version incorporates work from:

- the original `notion-local-mcp-easy` project by Oleg Alioshin;
- the LEADBERG fork and its stabilization improvements;
- OAuth and compatibility work developed with the Hyperagent/Fable team.

The 1.x Notion-focused line is preserved on the `legacy` branch.

## License

[MIT](LICENSE)
