# Security model

Notion Local MCP Easy is intended for **personal, trusted use on your own Windows computer**.

## Default mode

New installations start in **file-only mode**. Built-in file tools resolve paths and reject access outside the selected workspace. The server listens only on `127.0.0.1` and every endpoint, including `/health`, requires the generated Bearer token.

## Trusted developer mode

The setup wizard can enable commands such as Python, Git and Node. This mode is **not a sandbox**. Interpreters and build tools can access the wider filesystem, network and processes with the rights of the current Windows user. Git still has an extra guard: MCP blocks ordinary git commands until the workspace completes an explicit local setup-flow, it requires the user to choose whether commits belong on the default branch or on a named branch, and it refuses git whenever the detected `origin` does not match the saved binding after a restart. Enable it only when the connected Notion agent and everyone who can access its settings are trusted.

## Tunnel

Serveo is a third-party SSH tunnel. The public URL and Bearer token must be treated as secrets. Anonymous Serveo URLs are temporary. A reserved hostname authenticated with a dedicated SSH key keeps the URL stable; the private SSH key must never be shared or included in an archive.

## Secret handling

Configuration is stored in `%LOCALAPPDATA%\NotionMcpEasy`, not in the project folder or release archive. Large temporary MCP outputs are stored in `temp/` next to `server.py`, not inside the selected workspace. Release ZIP files are built into `release/` inside the project, and that folder is intentionally excluded from both Git sync and the release archive itself. The local git binding file `agent-repo-config.local.json` stays in the project root and is intentionally excluded from release archives and normal Git sync. This file records whether git is configured, rebound, or explicitly disabled for the folder, plus the chosen commit-branch policy, so MCP can safely recover after a restart. Never post `connection.txt`, `config.json`, the tunnel URL, the token, or `@temp/...` output files in a public chat.

## Reporting

When sharing a security report, redact tokens, cookies, account files and private paths. Do not attach `.venv`, logs, LocalAppData configuration, runtime files, the MCP `temp/` directory, or the local `release/` directory contents back into another release archive.
