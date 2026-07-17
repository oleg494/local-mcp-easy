# Changelog

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
