# Security model

Notion Local MCP Easy is intended for **personal, trusted use on your own Windows computer**.

## Default mode

New installations start in **file-only mode**. Built-in file tools resolve paths and reject access outside the selected workspace. The server listens only on `127.0.0.1` and every endpoint, including `/health`, requires the generated Bearer token.

## Trusted developer mode

The setup wizard can enable commands such as Python, Git and Node. This mode is **not a sandbox**. Interpreters and build tools can access the wider filesystem, network and processes with the rights of the current Windows user. Enable it only when the connected Notion agent and everyone who can access its settings are trusted.

## Tunnel

Serveo is a third-party SSH tunnel. The public URL and Bearer token must be treated as secrets. Anonymous Serveo URLs are temporary. A reserved hostname authenticated with a dedicated SSH key keeps the URL stable; the private SSH key must never be shared or included in an archive.

## Secret handling

Configuration is stored in `%LOCALAPPDATA%\NotionMcpEasy`, not in the project folder or release archive. Never post `connection.txt`, `config.json`, the tunnel URL, or the token in a public chat.

## Reporting

When sharing a security report, redact tokens, cookies, account files and private paths. Do not attach `.venv`, logs, LocalAppData configuration, or runtime files to a release archive.
