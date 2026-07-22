# Changelog

## 2.2.0 — 2026-07-22 (Background command jobs)

### Added

- Background command execution so long or parallel commands no longer depend on
  a single synchronous HTTP request (the free Serveo tunnel drops a POST after
  ~20–30 s). Four new tools, all gated by the same `mcp:commands:run` scope as
  `run_command`:
  - `start_command(program, args, cwd, timeout)` — start an allow-listed program
    in the background and get a `job_id` back immediately.
  - `get_command_status(job_id)` — poll status and, once finished, the full
    output in the same format as `run_command`.
  - `cancel_command(job_id)` — kill a running job's process tree.
  - `list_commands()` — list tracked jobs (id, status, elapsed, command).
- Concurrency cap (`MCP_MAX_COMMAND_JOBS`, default 4) and automatic pruning of
  finished jobs (10-minute retention plus a hard cap on tracked jobs), with the
  captured output files cleaned up on eviction.
- Graceful-shutdown cleanup: still-running background jobs are cancelled and
  their process trees killed when the server stops, so nothing is orphaned on
  Windows.

### Internal

- `run_command` and the background jobs share one validation path
  (`_prepare_command`) and one result formatter (`_format_command_result`), so
  their allow-list / cwd / trusted-mode security posture can never drift apart.
- New test suite `tests/test_command_jobs.py` covers security parity, the
  concurrency cap, TTL + count pruning, the shutdown hook, and live end-to-end
  execution.

## 2.1.1 — 2026-07-22 (Fix: CRLF corruption in edit_file/write_file)

### Bug fix — data corruption (affects 1.3.0–2.1.0)

- `_atomic_write_text()` (used by `write_file`, `edit_file`, the repo-context
  writer and the chunked-output saver) opened its temp file in text mode
  without `newline=`, i.e. `newline=None`. On Windows that blindly rewrites
  every `\n` to `os.linesep` (`\r\n`). Because `edit_file` reads a file with
  `read_bytes().decode()` **without** normalizing line endings, an existing
  `\r\n` was written back as `\r\r\n`, and one extra `\r` accumulated on the
  file on **every** `edit_file` call. The bug has existed since 1.3.0 (when
  atomic temp-file writes were introduced) and is present in every published
  release through 2.1.0.
- Fix: pass `newline=""` to `os.fdopen` in `_atomic_write_text`, disabling all
  newline translation so content is written byte-for-byte. `append_file` (its
  own `open(..., "a")` path) received the same one-line fix for consistency.
- Behaviour change: files written by `write_file` now keep exactly the line
  endings of the provided content (LF stays LF) instead of being implicitly
  converted to CRLF on Windows. The line-ending convention is now owned by the
  tool/caller, not silently by the OS text layer.

### Recovering already-corrupted files

If a file was mangled by an earlier release (stray single `\r` characters),
strip them without touching real line breaks:

```python
data = path.read_bytes()
clean = data.replace(b"\r\n", b"\n").replace(b"\r", b"")  # normalize to LF
path.write_bytes(clean)
```

### Tests

- New `tests/test_edit_file_newlines.py`: repeated `edit_file` on a CRLF file
  never introduces a lone `\r`; `write_file` keeps LF-only content and writes
  mixed CRLF verbatim; `append_file` does not accumulate `\r`;
  `_atomic_write_text` preserves CRLF. Suite is now 152 tests.

## 2.1.0 — 2026-07-22 (Smart dual default + Serveo authorize hint)

### Default auth mode is now `dual`

- Fresh installations default to **`dual`** (static Bearer token **and** OAuth
  2.1 on the same `/mcp`) instead of `legacy`, so a new setup works with both
  classic token clients (e.g. Notion) and OAuth clients (e.g. Hyperagent) out
  of the box. `SETUP.bat` generates the **OAuth owner code** automatically and
  prints it. Existing configurations are never changed on upgrade: a config
  that predates `auth_mode` stays `legacy`, an explicitly chosen mode is
  preserved — only brand-new installs get `dual`.
- Open DCR + owner-code consent is therefore active out of the box. Nothing is
  granted by registration alone: every authorization must still be approved on
  `/consent` with the owner code (see SECURITY.md).

### Temporary-URL policy relaxed for `dual` (still strict for `oauth`)

- Pure **`oauth`** on a temporary tunnel URL is still **blocked** — its issuer,
  discovery metadata, redirects and token audience would break on the next
  restart, leaving no working auth path. **`dual`** now **warns and starts**
  instead of blocking: the Bearer half works everywhere, so a first run on a
  temporary URL is no longer a dead end; only the OAuth half is unstable until
  a reserved hostname or a custom `public_url` is configured. New helper
  `stable_url_policy()` returns `ok` / `warn` / `block`;
  `MCP_OAUTH_ALLOW_TEMPORARY_URL=1` forces `ok`.

### Friendly `/authorize` hint for the Serveo interstitial

- On a free Serveo tunnel the one-time "you are about to visit…" interstitial
  can strip the query string from the first `/authorize` hit, which made the
  SDK answer with a raw JSON 400 (`client_id / response_type / code_challenge:
  Field required`) in the middle of Connect. A narrow new middleware detects a
  `GET /authorize` missing the required OAuth parameters and returns a short
  HTML page explaining the interstitial and how to recover (press Back / retry
  Connect, or use a custom domain / paid Serveo). Well-formed authorization
  requests pass straight through untouched.

### Tests

- Suite grew to 147 tests: `stable_url_policy` classification and the
  temporary-URL override, plus a live end-to-end check that a parameter-less
  `/authorize` returns the HTML hint (not raw JSON) while a valid request still
  redirects to `/consent`.

## 2.0.0 — 2026-07-22 (Local MCP Easy)

### Rename and repositioning

- The project is now **Local MCP Easy** (`local-mcp-easy`): a universal local
  MCP server over Streamable HTTP with OAuth 2.1, static-token and dual auth.
  Notion is one of the compatible clients, not the project's purpose. The
  Notion-focused 1.x line is preserved on the `legacy` branch.
- Configuration moved to `%LOCALAPPDATA%\LocalMcpEasy`; settings from the old
  `NotionMcpEasy` directory (token, workspaces, connections.cfg, OAuth state)
  are migrated automatically on first run.
- Release archives are now `local-mcp-easy-<version>.zip`.
- Added the MIT `LICENSE` (the repository previously had no license), a
  Russian-first `README.md`, an English `README.en.md` overview and a project
  history section crediting the original project, the LEADBERG fork and the
  OAuth work developed with the Hyperagent/Fable team.

### Fixes and improvements over 1.5.0

- **Consent page CSP fix (real-world bug):** `form-action 'self'` silently
  blocked the post-approval redirect back to the OAuth client in browsers
  that apply CSP Level 3 to redirects, so clients never reached `/token`.
  The consent response now allows the client's redirect origin explicitly.
  (Found and fixed during a live Hyperagent connection.)
- **Owner grant override:** optional `MCP_OAUTH_OWNER_GRANT_SCOPES` /
  `oauth_owner_grant_scopes` — on a single-owner server every approved client
  receives a fixed scope set regardless of what it requested. Off by default;
  invalid scopes are filtered out.
- **Config robustness (real-world bug):** a hand-edited `config.json` with a
  UTF-8 BOM or a stray comma used to be treated as a missing config — the
  launcher silently ran first-time setup and regenerated the token, breaking
  every connected client. Now: JSON is read BOM-tolerantly (`utf-8-sig`), an
  existing-but-corrupt config aborts with a clear error WITHOUT overwriting
  anything, and `launcher.py --add-command NAME` / `--remove-command NAME`
  edit the command allowlist parse-safely so the file never needs hand-editing.
- Test suite grew to 140 tests (CSP form-action, owner-grant override,
  config corruption/BOM/migration, allowlist editing).

### Pre-release audit follow-ups

- `build_release.py` now excludes any `*.local.json` / `*.local.md` file, not
  just the two named ones, so stray local files can never leak into an archive.
- The `test_process_limits` and `test_repo_context` suites force
  `MCP_AUTH_MODE=legacy` for their in-process server import, so the full suite
  is 140/140 even when run inside an active oauth/dual MCP session (the
  per-tool scope gate needs a request auth context that direct calls lack).
- Documented the Streamable-HTTP/Serveo duration ceiling for long
  `run_command` calls (detached + poll pattern, or a custom `public_url`
  reverse proxy), and made explicit in SECURITY.md that `run_command` with an
  interpreter is arbitrary code execution independent of the file-tool sandbox.

## 1.5.0 — 2026-07-21 (Universal OAuth)

### Universal auth modes

- Added `AUTH_MODE = legacy | oauth | dual`. `legacy` keeps the exact 1.4.x
  behaviour (static Bearer token, Notion); `oauth` serves OAuth 2.1 clients
  such as Hyperagent; `dual` accepts both on the same `/mcp` endpoint.
- Built an embedded OAuth 2.1 Authorization Server on the official `mcp` SDK
  auth machinery (`/authorize`, `/token`, `/register`, `/revoke`): Dynamic
  Client Registration, PKCE `S256` only, exact `redirect_uri` matching,
  `state` round-trip, short-lived access tokens, rotating refresh tokens and
  authorization-code replay revocation.
- Added OAuth discovery: RFC 8414 Authorization Server Metadata, RFC 9728
  Protected Resource Metadata (path-aware `/.well-known/oauth-protected-resource/mcp`
  plus a root alias), and `WWW-Authenticate` with `resource_metadata` on 401.
- Access tokens are audience-bound to this server's `/mcp` resource URL
  (RFC 8707); tokens minted for another URL are rejected.
- New `/consent` page: every authorization request must be approved with the
  OAuth owner code, so open Dynamic Client Registration cannot grant access
  to anyone who merely knows the public URL. Wrong codes are rate-limited
  with a lockout.
- Introduced per-tool OAuth scopes with deny-by-default:
  `mcp:files:read`, `mcp:files:write`, `mcp:commands:run`, `mcp:git`.
  A read-only token cannot write files, run commands or touch git. The
  legacy master token keeps full access and is documented as such.
- OAuth state (registered clients and SHA-256 hashes of tokens — never raw
  token values) lives in `%LOCALAPPDATA%\NotionMcpEasy\oauth_state.json`,
  outside the repository and release archives. Registered clients and
  refresh/access tokens survive server restarts on a stable hostname, so
  OAuth clients reconnect without re-approval.
- Launcher: new `OAUTH_SETUP.bat` (`launcher.py --oauth`) wizard for choosing
  the auth mode and generating the owner code, and
  `REGISTER_OAUTH_CLIENT.bat` (`launcher.py --register-oauth-client`) for
  pre-registered "Bring my own OAuth app" clients (public PKCE or
  confidential).
- The launcher refuses to start `oauth`/`dual` mode on a temporary tunnel
  URL: OAuth needs a reserved Serveo hostname (issuer, metadata, redirect
  configuration and token audience all break when the URL changes).
  `MCP_OAUTH_ALLOW_TEMPORARY_URL=1` remains as an explicit local-testing
  override.
- `SHOW_CONNECTION.bat` masks both the Bearer token and the OAuth owner
  code; `--full` reveals them.
- `/health` now accepts the operator (legacy) token in every mode so the
  launcher health checks keep working even when `/mcp` is OAuth-only. In
  `dual` mode legacy clients may keep sending `X-API-Key`.
- Added 47 new tests: provider/store unit tests (hashing, rotation, replay
  revocation, audience checks, persistence), consent-page tests (CSRF,
  lockout, deny), full end-to-end OAuth and dual-mode integration tests
  against a live server process, and launcher policy tests. Full suite:
  105 tests.

### Security review hardening

- Consent brute-force protection is now asymmetric: a CORRECT owner code is
  always honoured, so wrong attempts can no longer lock the legitimate owner
  out. Wrong attempts are capped per authorization transaction and
  rate-limited by a short, self-healing rolling window instead of a blanket
  15-minute lockout of the whole consent handler.
- Dynamic Client Registration can no longer grow `oauth_state.json` without
  bound: the client registry is capped (`MCP_OAUTH_MAX_CLIENTS`, default 100),
  registered-but-unused DCR clients are pruned after
  `MCP_OAUTH_UNUSED_CLIENT_TTL` (default 1 h), and clients holding live tokens
  or manually pre-registered (BYO) clients are never evicted.
- Least-privilege default scopes: a client that registers without asking for
  scopes now receives only `mcp:files:read` + `mcp:files:write`.
  `mcp:commands:run` (near-full system access in trusted developer mode) and
  `mcp:git` must be requested explicitly. `mcp:commands:run` is documented as
  a near-full system-access grant, not a workspace-scoped one.
- Stricter redirect_uri validation at registration: fragments, userinfo and
  hostless/opaque forms are rejected; http is accepted only on loopback.
- `oauth_state.json` loading is resilient to a corrupted or hand-edited file
  (null/scalar sections, non-dict entries, unknown newer schema version) and
  starts clean instead of crashing on startup.
- Replay markers for exchanged authorization codes (`_used_codes`) now expire
  (`USED_CODE_TTL`, 1 h) so long-running servers do not accumulate them.
- `MCP_PUBLIC_URL` / a custom stable domain now works through the normal
  launcher: `OAUTH_SETUP.bat` accepts a custom public URL, the launcher treats
  it as a stable URL, skips Serveo tunnel management (operator runs their own
  reverse proxy) and no longer overwrites it.
- Release note: the distributable is the audited `build_release.py` archive
  (`release/local-mcp-easy-<version>.zip`; `notion-mcp-easy-*` on the 1.x line), never the working directory —
  the working directory's `.git` must not be shipped.

### Maintenance (previously unreleased)

- Blocked multi-ref and destructive push modes that bypass branch policy (`--all`, `--mirror`, `--tags`, `--delete`, and `--prune`).
- Validate Git's effective push remote when `git push` omits the remote argument.
- Moved user-populated `connections.cfg` to `%LOCALAPPDATA%\NotionMcpEasy`, with automatic migration from 1.4.2 release folders and atomic writes.
- Replaced the packaged user file with `connections.example.cfg` and excluded legacy `connections.cfg` from release archives.
- Clarified that temporary Serveo URLs still require updating the Notion connection after restart.

## 1.4.2 — 2026-07-20

- Added a root-level `connections.cfg` file with documented Russian comments, `MENU = on` by default, and pre-created `PATH[1]`–`PATH[9]` workspace slots.
- Added a startup workspace-selection menu that can switch projects by updating only `workspace` in `config.json`, without regenerating the MCP token or forcing the agent to reconnect.
- First-time setup now saves the chosen workspace both to `config.json` and to the first available slot in `connections.cfg`.
- Added support for saving new workspaces from the startup menu, reusing existing slots, extending beyond slot 9 when needed, and disabling the menu while keeping the last selected workspace as the default.
- Updated launcher messaging and README documentation so users can see where `connections.cfg` and `config.json` live and edit them manually.
- Added launcher regression tests for config bootstrap, workspace switching, saving new paths, extended slot numbers, and menu disable mode.

## 1.4.1 — 2026-07-19

- Tightened git policy so ordinary mutating git commands such as `reset`, `checkout -B`, `tag`, `config`, and `remote set-url` no longer bypass the repo guard-layer.
- Added an explicit consent-layer for git setup changes: defaults now require confirmation, and changing an existing repo binding requires `confirm_reconfigure`.
- `workspace_info()` now shows a compact root-repo plus nested-repo overview instead of only a single-layer summary.
- Fixed repo-context handling for nested repositories and extended the repo-context regression coverage.
- Added tests for consent-layer flows, nested repo summaries, mutating git command blocking, large-file / long-line safety, and `git -C` target validation.

## 1.4.0 — 2026-07-18

- Added a full git setup-flow for MCP workspaces instead of a guard-only model.
- Added `setup_git_context()` with explicit modes for `bind_existing_repo`, `init_new_repo`, `attach_to_remote`, and `disable_git`.
- Added `inspect_git_repository()` and expanded `repo_context_status()` / `workspace_info()` so agents can see the current state and the next safe action after restart.
- Git commands are now blocked until the user-facing setup choice is completed for the folder, including the explicit “disable git for now” path when `.git` is absent.
- Repo context now stores persisted local policy in `agent-repo-config.local.json`, including configured/disabled state, last detected origin, branch, fork metadata, and explicit commit branch policy.
- MCP now refuses git whenever the detected `remote.origin.url` no longer matches the saved local binding after restart, and blocks commit/push/merge/rebase outside the configured branch target.
- Added tests for repo bootstrap, disable mode, origin mismatch, and URL normalization.
- Release archives are now built into a local `release/` folder inside the project; that folder is excluded from Git and from the archive contents themselves.

## 1.3.5 — 2026-07-18

- Added mandatory local repo context file `agent-repo-config.local.json` for Git work in each workspace.
- Added `configure_repo_context()` so the client must explicitly store `repository_url` and `is_fork` before Git is allowed through MCP.
- Added `repo_context_status()` and extended `workspace_info()` so the saved repo binding is visible after MCP restarts.
- `run_command()` now blocks `git` when repo context is missing, invalid, or mismatched against the detected `remote.origin.url`.
- Added local packaging / ignore rules so repo-context files stay out of Git and release archives.

## 1.3.3 — 2026-07-18

- `server.py` now delivers large outputs in safe chunks instead of sending oversized responses directly to the model.
- `read_file()` now returns chunked output with line ranges, total line count and continuation offsets.
- Chunking now prioritizes a safe character budget while preserving whole lines.
- Added adaptive chunk reflow: if wrapper text makes a chunk exceed the hard output limit, the chunk is rebuilt with a smaller working character budget.
- `run_command()`, `grep_files()` and `list_dir()` now return small results directly and spill large results to temp files for continued reading via `read_file()`.
- Added temp output storage in `temp/` next to `server.py`, outside `BASE_DIR`.
- Added `@temp/...` virtual paths so long temporary outputs can be continued through `read_file()`.
- Temp output files are deleted automatically after the final read.
- Leftover temp output files are cleaned up on server startup.
- `edit_file()` now refuses to edit files that look binary.
- Empty outputs are now normalized to safe non-empty responses.

## 1.3.2 — 2026-07-17

- Atomic writes now use a unique temp file per call (`tempfile.mkstemp`): parallel `write_file`/`edit_file` calls on the same file no longer race on a shared temp name; temp files are cleaned up on failure.
- Tests no longer inherit `MCP_SERVEO_HOSTNAME` from an active MCP session — the suite is reproducible regardless of where it runs.
- Public health polling stops early if the SSH process dies instead of polling to timeout.
- Reconnect no longer claims the stable tunnel is restored when its health check has not passed yet.

## 1.3.1 — 2026-07-17

- Fixed: removed `BatchMode=yes` from the SSH command. Serveo completes auth via keyboard-interactive with an empty challenge even for registered keys (the key only authorizes the reserved hostname), so BatchMode broke both temporary and stable tunnels with `Permission denied`. Verified live.
- Dead server/tunnel processes are no longer "stopped" on shutdown, removing a false "Refusing to stop PID" warning after PID reuse.

## 1.3.0 — 2026-07-17

- SSH tunnel briefly used `BatchMode=yes` — reverted in 1.3.1, see above.
- Startup now polls the public `https://.../health` endpoint and reports success only after the tunnel actually serves traffic.
- Tunnel errors now print the last lines of `tunnel.log` directly in the console.
- `write_file` and `edit_file` write atomically (temp file + replace) to survive crashes and OneDrive sync races.
- Host header check restored in `SecurityMiddleware`: only `localhost`, `127.0.0.1` and `*.serveousercontent.com` are accepted (in stable mode — only the reserved hostname); other hosts get HTTP 403.
- `SHOW_CONNECTION.bat` masks the Bearer token by default; pass `--full` to reveal it.
- Added tests: symlink escape from workspace, Cyrillic paths, atomic write, Host check, `BatchMode`, public health-check, token masking.

## 1.2.2 — 2026-07-17

- Fixed reserved-hostname startup when Serveo keeps SSH output silent.
- Stable mode now derives its known public URL instead of waiting for an announcement.
- Added regression tests for silent and failed stable SSH processes.

## 1.2.1 — 2026-07-17

- Added a standalone full Serveo setup guide for temporary and stable URLs.
- Added step-by-step SSH key, reserved hostname, Notion connection and troubleshooting instructions.
- Added a ready-to-use prompt for AI-assisted installation.

## 1.2.0 — 2026-07-17

- Added optional stable Serveo mode with a reserved hostname and dedicated SSH key.
- Setup wizard now supports both zero-config temporary URLs and persistent URLs.
- Stable reconnects reuse the same URL and no longer require editing Notion.
- Added live verification and unit tests for the reserved-hostname SSH command.

## 1.1.0 — 2026-07-17

- File-only mode is now the default for new installations.
- Renamed command access to trusted developer mode and documented that it is not a sandbox.
- Added bounded streaming capture for command output; the process tree is stopped at the limit.
- Added authenticated `/health` checks and wrong-token tests.
- Launcher now rejects an occupied port before creating a tunnel.
- Runtime process IDs are checked against expected command lines before stopping them.
- Append operations now enforce the final file-size limit.
- Directory moves are no longer supported by `move_file`.
- Regex search mode is disabled to avoid pathological expressions.
- Reconnect output now explicitly tells the user to update the URL in Notion.
- Added launcher, process-limit, authentication and occupied-port tests.

## 1.0.0 — 2026-07-16

- Initial one-click Windows fork with FastMCP, Serveo launcher, workspace file tools and optional developer commands.
