# Changelog

## 2.5.0 — 2026-07-26 (Agent skills and persistent memory)

Two things an autonomous agent usually has and an MCP server usually does not: a
library of reusable procedures, and memory that survives the session. Here every
connected MCP client gets them, not one particular agent.

Both reach the model through the MCP `instructions` field returned at
`initialize` — the only channel a server has into a client's system prompt.
Anything else would have to be pulled with a tool call the client must first
know to make.

### Added — skills

- A skill is a folder holding `SKILL.md`: YAML frontmatter plus markdown
  instructions. The format is the portable core of the
  [agentskills.io](https://agentskills.io/specification) spec (`name`,
  `description`, `license`, `compatibility`, `metadata`) with none of the
  client-specific extensions, so the same skill also loads in Claude Code.
- Two locations: `<config>/skills/<name>/SKILL.md` for personal skills available
  in every workspace, and `<workspace>/.mcp-skills/<name>/SKILL.md` for skills
  that belong to one project.
- **Progressive disclosure, three levels**, so a large library stays affordable:
  1. always — `name: description`, one line per skill, in the server
     instructions and via `skills_list()`;
  2. on demand — the `SKILL.md` body, via `skill_view(name)`;
  3. separately — `references/`, `scripts/` and `assets/` are never inlined even
     at level 2; the rendered skill ends with a list of them and a
     `skill_view(name, file_path=...)` pointer.
- **A skill is instructions the model will follow, so it is a trust boundary,
  not data.** A personal skill always wins over a workspace skill of the same
  name — the workspace is writable by any client holding `mcp:files:write`, so
  the other precedence would be a privilege escalation — and a workspace skill
  is labelled `[workspace]` everywhere it is rendered. Descriptions are
  flattened to one line so they cannot forge extra index entries in the system
  prompt. Nothing here executes: a skill may *tell* the model to run something,
  which then goes through `run_command` and its allow-list like any other
  command.
- The frontmatter parser is hand-rolled (~60 lines) rather than adding PyYAML to
  a three-dependency project. It handles scalars, quoted values, `>`/`|` block
  scalars and a one-level `metadata` map, and ignores anything else rather than
  guessing at it.

### Added — memory

- Two flat files under `<config>/memory/`: `MEMORY.md` for what the agent
  learned about the environment and the work, `USER.md` for what it learned
  about the person. Entries are separated by a lone `§` line. No database, no
  embeddings — recall here means the whole store is put in front of the model,
  so there is nothing to rank, and an index would add a dependency, a build step
  and a failure mode to answer a query that is never asked.
- Budgets are measured in **characters**, not entries (2200 / 1375, both
  env-overridable). An entry cap would let one rambling entry crowd out ten
  useful ones; the character cap manages what is actually scarce. An over-budget
  write is **refused** and hands back the current contents so the model can
  consolidate and retry — never silently truncated.
- The store lives outside the workspace, so no filesystem tool can reach it:
  memory changes only through `memory_write`, where the scope check applies.
  Files are written atomically and are owner-only (`0600`) on POSIX.
- An entry containing the delimiter is refused, since it would silently become
  two entries — a second, unreviewed memory forged by one write. Mutations take
  a lock: they are read-modify-write of a whole file from `asyncio.to_thread`
  worker threads, so concurrent writes would otherwise lose one.

### Added — tools

| Tool | Scope |
| --- | --- |
| `skills_list()` | `mcp:files:read` |
| `skill_view(name, file_path="")` | `mcp:files:read` |
| `memory_read(target="all")` | `mcp:files:read` |
| `memory_write(action, content, target, old_text)` | `mcp:files:write` |

No new OAuth scopes, deliberately: tokens already issued keep working. Under
`MCP_READ_ONLY=1`, `memory_write` is simply not registered.

New environment variables: `MCP_SKILLS_DIR`, `MCP_MEMORY_DIR`, `MCP_MEMORY`,
`MCP_MEMORY_CHAR_LIMIT`, `MCP_USER_CHAR_LIMIT`.

### Changed

- `launcher.py --doctor` reports how many skills are visible and whether a
  memory store exists.

### Tests

- 370 → 449. Frontmatter parsing (block scalars, nesting, BOM, malformed input),
  discovery precedence including the personal-over-workspace rule, all three
  disclosure levels, support-file traversal, index-forgery via a multi-line
  description, memory format and budget boundaries, delimiter injection, and an
  eight-thread concurrent-write race.

## 2.4.1 — 2026-07-26 (Process-group kill fix)

- **`_kill_tree` signalled the process group unconditionally.** On POSIX it
  ran `os.killpg(os.getpgid(proc.pid), SIGKILL)` on any child. A process that
  was *not* spawned with `start_new_session` shares the server's own group, so
  that call SIGKILLs the server. Every production spawn goes through
  `_spawn_process`, which always sets `start_new_session=True`, so a running
  server was never at risk — but the footgun was one forgotten keyword away,
  and it did fire: 2.4.0's own test suite creates a bare subprocess, and all
  eight POSIX CI cells hung at the test step with no output while all four
  Windows cells passed (`taskkill /T` targets one PID's tree, so Windows never
  had the bug). The group is now signalled only when the child really leads
  its own group; otherwise the child alone is killed.
- **CI: `timeout-minutes: 10` on the test step.** The hang above occupied
  runners for 17 minutes before it was noticed and would have run to the
  six-hour default. A cap turns a hang into a failed cell in two minutes.
- Two regression tests, both POSIX-only: a child sharing our group must be
  killed alone (the test surviving to make its assertion *is* the assertion),
  and a correctly spawned session leader's grandchild must still be reaped.
  The second checks the grandchild PID directly rather than the group —
  a group stays alive while any member is an unreaped zombie.
- `tests/test_sandbox_walk.py` no longer assumes POSIX `os.walk` descends a
  symlinked directory (it correctly does not; only Windows junctions slip
  past). Added the escape that *does* survive on POSIX — a symlinked **file**
  is listed by `os.walk` and was read through — so `is_inside()` is covered on
  Linux and macOS too, not just Windows.

## 2.4.0 — 2026-07-26 (Security audit, tool annotations, read-only mode, audit log)

A full multi-dimension review of 2.3.2 (auth, filesystem, command execution,
git gating, launcher, async lifecycle, packaging, tests, MCP conformance,
simplification), with every finding independently re-checked before it was
accepted. Each item below was reproduced against a real git / npm / Windows
before being fixed, and each has a regression test. Tests: 261 → 370.

### Security — arbitrary code execution

- **`git grep -O'<cmd>'` / `--open-files-in-pager` ran an arbitrary program**
  once per matching file. `grep` was classified read-only, so this bypassed
  `MCP_ALLOWED_COMMANDS` entirely.
- **`git rebase --exec` / `-x '<cmd>'`** runs a command after every replayed
  commit, and `rebase` was branch-bound-allowed.
- **`git fetch --upload-pack=` / `git push --receive-pack=`** execute the given
  program locally for local-path and ssh transports.
- **BatBadBut on Windows (`npm`, `npx`).** Windows cannot launch a `.cmd`/`.bat`
  without cmd.exe, which re-parses the command line; Python's argv quoting only
  quotes arguments containing whitespace and never escapes cmd's
  metacharacters. An allow-listed `npm` handed the single argument
  `--version&whoami` ran `whoami`, despite `shell=False` and a list argv.
  Arguments to a batch target are now rejected if they contain
  ``& | < > ^ " % !`` or a newline.

### Security — sandbox escape

- **`git diff --no-index <path> /dev/null` read any file on the host**, and
  **`git diff|log|show --output=<path>` wrote any file on the host**;
  `git commit -F <path>` embedded any file in a commit message. Options that
  execute a program or name a path are now rejected before the subcommand
  policy runs, and file-valued options are resolved through the workspace guard.
- **Windows directory junctions escaped the workspace.** `mklink /J` needs no
  admin rights and a junction is not a symlink, so `os.walk(followlinks=False)`
  descended straight through one: `grep_files` returned file contents from
  outside `BASE_DIR` to a client holding only `mcp:files:read`. `safe_path`
  itself was always correct; the tree walks never re-validated what `os.walk`
  handed them. `grep_files`, recursive `list_dir`, `glob_files` and the orphan
  sweep now re-check every entry.

### Security — policy bypass

- **Clustered short options.** git parses `-uf` as `-u -f`, so the force-push
  blocklist never fired on `git push -uf origin main`. Short options are now
  expanded before matching, in the push, branch, tag and config classifiers.
- **`git push --follow-tags`** pushes tag refs the refspec analysis never sees.
- **`git symbolic-ref HEAD <ref>`** repoints HEAD; it was in the read-only set.
- **The repo-context trust anchor was compared case-sensitively.** On Windows
  and macOS a client holding only `mcp:files:write` could create
  `Agent-Repo-Config.Local.Json` — a different string, the same file — and forge
  the approved git remote with no git scope at all.
- **Background jobs were shared across OAuth clients.** `CommandJob` now records
  the client that started it; `list_commands`, `get_command_status` and
  `cancel_command` only see the caller's own jobs, and a foreign job id is
  indistinguishable from an unknown one.
- **`/revoke` did not enforce confidential-client secrets.** It shares the SDK's
  `ClientAuthenticator` with `/token`, where `get_client()` returns
  `client_secret=None`, so only `/token` was actually protected.
- **`tunnel_host` reached ssh as an unvalidated destination.** ssh parses its own
  argv, so `-oProxyCommand=...` would have run that command. Option-shaped hosts
  and non-numeric ports are refused, and `--` precedes the destination.

### Added

- **MCP tool annotations** on all 22 tools (`readOnlyHint`, `destructiveHint`,
  `idempotentHint`, `openWorldHint`) so a client can tell what is safe to run
  unattended. `readOnlyHint` is derived from the tool's scope unless it opts out
  explicitly, so it cannot drift from reality.
- **`MCP_READ_ONLY=1`** — the mutating tools are never registered, so the
  guarantee does not depend on a scope check holding. For exposing a workspace
  over a tunnel for review or inspection.
- **`MCP_AUDIT_LOG=<path>`** — one append-only JSON line per tool call with the
  OAuth client id, named arguments (bound from positional ones too) and outcome.
  Never raises: a log that can break the tool it audits is worse than none.
- **Secret redaction.** Tool output is scanned for the master token and the
  OAuth owner code before it leaves the process, so a stray `.env` picked up by
  `grep_files` cannot hand a client credentials it was never granted.
- **`tail_file(path, lines)`** — the last N lines of a text file. `read_file`
  counts from the start, so following a log meant recomputing an offset per poll.
- **`launcher.py --doctor`** (`DOCTOR.bat` / `doctor.sh`) — checks Python
  version, dependencies, config, token, workspace, auth mode, owner code, tunnel
  backend, ssh/git availability and whether the port is already taken.

### Fixed

- `_kill_tree` signals the process group on POSIX instead of only the direct
  child, so `npm run`'s grandchildren are no longer orphaned on timeout, cancel
  or shutdown — the result already claimed "process tree stopped".
- Graceful shutdown waits (bounded) for job driver tasks to finish, not just for
  the processes to die.
- `run_command` / `get_command_status` / `list_commands` no longer run a
  full-workspace `os.walk` on the event loop when output exceeds the chunk limit.
- `write_file` / `append_file` on a directory raise `ValueError` like the rest of
  the API, instead of a raw `OSError` from `os.replace`.
- The orphan-sweep throttle is now taken under a lock; concurrent tool calls on
  worker threads could all pass the check and each start a full tree walk.
- `stop.sh` no longer `pip install`s before stopping. `--stop` only reads
  `runtime.json` and signals PIDs, but under `set -e` a failed install (no
  network — a likely reason to be stopping) aborted before anything stopped.
- `REGISTER_OAUTH_CLIENT.bat` installs dependencies like its `.sh` counterpart;
  `--register-oauth-client` imports `mcp` and crashed with `ModuleNotFoundError`
  after `SETUP.bat` but before `START.bat`.
- The server PID identity check anchors on the absolute script path rather than
  the bare name `server.py`.
- `glob_files` skips a match resolving outside the workspace instead of failing
  the whole call.

### Changed

- `grep_files` drops its `regex` parameter, which only ever raised. The
  docstring now explains why matching is literal (a client-supplied regex is a
  denial-of-service primitive against a server with no request budget).
- One `atomic_write_text` in `core.py`, shared by the server, the launcher and
  the OAuth store. The three copies had drifted — the OAuth one never `fsync`'d,
  so a power loss could truncate the token store.
- `checkout` / `switch` / `branch` target extraction is one scanner instead of
  three near-identical copies, and now also understands the `--opt=value` form.
- `ruff.toml` sets `required-version = "0.15.22"`, so a mismatched ruff fails
  loudly instead of silently linting with a different rule set (0.16.0 reports
  47 findings on this tree). `CONTRIBUTING.md` names the same pin as CI.

### Tests

- 261 → 370. New coverage for the batch-argument guard (including a live
  Windows proof that cmd.exe really does re-parse), junction escapes, the
  `@temp/` virtual path resolver (previously untested), job ownership,
  read-only mode, the audit log, redaction, tool annotations, `--doctor`, the
  ssh argv hardening, and a default-deny regression test for unclassified git
  subcommands (`submodule`, `clone`, `filter-branch`, `worktree`, `bisect`, …).
- `safe_path`'s only link-escape test was skipped on any Windows box without
  Developer Mode, including CI's Windows leg. A junction-based companion test
  needs no privileges and always runs.

### CI

- A step that fails when line endings disagree with `.gitattributes`. Two `.bat`
  files showed as modified straight after clone, which trains contributors to
  ignore a dirty `git status`.

## 2.3.2 — 2026-07-23 (CI/test fixes, sish docs)

### Fixed

- The orphan `.mcp-tmp` sweep now runs on its very first call (server startup)
  even on a freshly booted host: the monotonic throttle stamp is initialized to
  `-inf` instead of `0.0`, so `time.monotonic()` being below the throttle
  interval no longer skips the first sweep.

### Tests

- Path assertions resolve their temp base so they pass on macOS, where the temp
  dir under `/var` is a symlink to `/private/var` (the code canonicalizes paths
  with `.resolve()` as a symlink-escape defence). Fixes the macOS CI cells; the
  full 12-cell matrix (Ubuntu/macOS/Windows × Python 3.10–3.13) is green.

### Docs

- `SISH_SETUP.md`: add an on-demand-certificate (certmagic/ACME) troubleshooting
  section — stale account caches, SNI-multiplexed on-demand issuance sharp
  edges, and the DNS-01 wildcard fallback.

## 2.3.1 — 2026-07-23 (Security patch)

### Security

- **Bump `mcp` to 1.28.1 and `starlette` to 1.3.1** to clear known CVEs
  (CVE-2026-59950 in mcp; PYSEC-2026-248/249/2280/2281 in starlette) that
  `pip-audit --strict` flags in the 2.3.0 pins — CI is green again.
- **`connection.txt` is now created owner-only (`0600`) on POSIX.**
  `publish_connection()` secured the config dir (`0700`) but never chmod'd the
  file itself, so the Bearer token could be world-readable on shared POSIX
  hosts.

### Fixed

- `build_release.py` excludes `.remember/` so stray local files never enter the
  release archive.
- Docs: `SISH_SETUP.md` ssh-forward example uses `127.0.0.1`; `SECURITY.md`
  documents the sish threat model; `README.en.md` refreshed (sish/POSIX
  wrappers, correct test count).

## 2.3.0 — 2026-07-23 (Cross-platform, supply-chain, self-hosted tunnels)

### Added

- **Self-hosted `sish` tunnel backend.** A new `tunnel_backend` setting
  (`serveo` | `sish` | `custom-ssh`) lets you front the server with your own
  sish server over the same `ssh -R` remote-forward as Serveo, so you own the
  POST/streaming timeouts (the real fix for edge churn, not a symptom patch).
  Configure it with `TUNNEL_SETUP.bat` / `./tunnel_setup.sh`
  (`launcher.py --tunnel-setup`); see `SISH_SETUP.md`. OAuth stays mandatory on
  a public entry point. Serveo remains the default and existing configs are
  unchanged.
- **POSIX wrappers** mirroring the `.bat` scripts for Linux/macOS: `setup.sh`,
  `start.sh`, `stop.sh`, `oauth_setup.sh`, `register_oauth_client.sh`,
  `show_connection.sh`, `build_release.sh`, `tunnel_setup.sh`.
- **Reverse-proxy guide** (`REVERSE_PROXY.md`) for nginx / caddy / traefik.
- `MCP_TEMP_FILE_TTL` and `MCP_MAX_COPY_MOVE_BYTES` environment overrides.
- `.gitattributes` pins `VERSION` (CRLF) and shell/batch line endings.

### Changed

- **Dependencies:** `mcp` pinned to `1.27.2` and the unused `[cli]` extra
  dropped. Operators who relied on the `mcp` CLI being installed by this
  package must `pip install "mcp[cli]"` separately; the server never used it.
- **CI:** matrix over Ubuntu / macOS / Windows × Python 3.10–3.13 (3.13 is
  allowed-failure for now), `pip-audit --strict`, Dependabot, and a pinned ruff.
- `copy_file` / `move_file` now reject sources larger than ~100 MB
  (override with `MCP_MAX_COPY_MOVE_BYTES`), enforced after the existing
  trust-anchor guard, to stop a `mcp:files:write` holder from exhausting disk.

### Fixed

- Orphaned `.mcp-tmp` files left by a crash between write and atomic rename are
  now swept from the workspace (rate-limited), not only `temp/*.txt`.
- A configured public host (Serveo, a custom proxy, or a self-hosted sish
  domain) is accepted by the host allowlist in legacy/Bearer mode too, not only
  under OAuth.

### Internal

- Removed the dead `_capture_process` helper; `allowed_commands` now has a
  single source of truth in `core.py`.

## 2.2.1 — 2026-07-23 (Security & stability hardening)

### Security — may require client changes

- **Confidential OAuth clients must now authenticate.** A new
  `ClientSecretAuthMiddleware` enforces `client_secret_basic` /
  `client_secret_post` for every confidential client whenever OAuth is
  enabled (all modes except `legacy`). Clients that previously connected
  without presenting their registered `client_secret` will now be rejected;
  re-supply the secret or re-register as a public PKCE client. Client
  secrets are stored only as SHA-256 hashes at rest (`oauth_state.json`
  never holds the plaintext); the raw secret is still returned once at
  registration time per RFC 7591.
- **Refresh-token reuse now revokes the whole token family** (RFC 9700
  §4.14.2). Replaying an already-rotated refresh token revokes the entire
  family, including the currently-valid latest token — not just the
  replayed one. A client that accidentally reuses an old refresh token must
  restart the authorization flow.

### Fixed (security)

- Sanitized the environment passed to child processes so secrets no longer
  leak into `run_command` / background jobs.
- Closed a `git -c` / global-option argument-injection (RCE gadget) path,
  and hardened git handling: refspec branch-delete guard, force-push block,
  fetch/pull refspec validation, and a `.git` / repo-context write guard.
- Constant-time comparison (`_consteq`) for all token/secret checks
  (5 call sites).
- Guarded `urlsplit` port parsing against `ValueError`.
- OAuth consent now requires an explicit `action == "approve"`.

### Changed (launcher hardening)

- Config directory created `0700` and `connection.txt` `0600`; the Bearer
  token is masked in console output, so it is no longer group/world-readable
  on shared POSIX hosts.
- Process identity works off-Linux: `process_command_line()` falls back to
  `ps` when `/proc` is absent (macOS/BSD), so start/stop detection works.
- `stop_pid()` escalates SIGTERM → wait → SIGKILL and returns real process
  liveness instead of an unconditional success.
- Tunnel reconnect uses exponential backoff (3s, 6s, 12s … capped at 5 min)
  instead of a tight retry loop.

### Changed (logging)

- The launcher is now the single owner of `server.log`: it spawns the
  server with piped output and writes through a `RotatingFileHandler`
  (append + size-based rotation, bounded at `(backups+1) × maxBytes`)
  instead of truncating the log on every launch. This fixes a Windows
  `PermissionError` on rotation caused by two writers holding the file.
- `mcp.server.streamable_http` is quieted to `WARNING` to cut transport
  noise, while `uvicorn.access` stays at `INFO` so tunnel/transport drops
  remain visible.

### Internal / tests

- Async file tools run via `asyncio.to_thread` so slow disk I/O no longer
  blocks the event loop.
- New test suites: `test_env_sanitization`, `test_git_hardening`,
  `test_file_trust_anchor`, `test_async_fs_tools`, `test_logging_hygiene`,
  plus `test_oauth_store` / `test_oauth_flow` additions for refresh-token
  family revocation and confidential-client secret enforcement.
- Fixed a spurious local failure by using the bare allow-listed `python`
  interpreter in the env-sanitization spawn test.

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
