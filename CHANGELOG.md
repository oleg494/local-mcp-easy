# Changelog

## 1.4.0 — 2026-07-18

- Added a full git setup-flow for MCP workspaces instead of a guard-only model.
- Added `setup_git_context()` with explicit modes for `bind_existing_repo`, `init_new_repo`, `attach_to_remote`, and `disable_git`.
- Added `inspect_git_repository()` and expanded `repo_context_status()` / `workspace_info()` so agents can see the current state and the next safe action after restart.
- Git commands are now blocked until the user-facing setup choice is completed for the folder, including the explicit “disable git for now” path when `.git` is absent.
- Repo context now stores persisted local policy in `agent-repo-config.local.json`, including configured/disabled state, last detected origin, branch, fork metadata, and explicit commit branch policy.
- MCP now refuses git whenever the detected `remote.origin.url` no longer matches the saved local binding after restart, and blocks commit/push/merge/rebase outside the configured branch target.
- Added tests for repo bootstrap, disable mode, origin mismatch, and URL normalization.

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
