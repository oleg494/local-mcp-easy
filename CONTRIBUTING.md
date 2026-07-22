# Contributing to Local MCP Easy

Thanks for taking the time to contribute! This project is a local developer MCP
server (Streamable HTTP + OAuth 2.1) for Windows. The primary documentation is
in Russian ([README.md](README.md)); a short English overview lives in
[README.en.md](README.en.md).

> Кратко по-русски: PR приветствуются. Перед отправкой прогоните линтер и тесты
> (`ruff check .` и `python -m unittest discover -s tests`), опишите изменения в
> `CHANGELOG.md` и держите правки сфокусированными.

## Development setup

1. Use Python 3.12.
2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate        # Windows
   pip install -r requirements.txt
   pip install ruff
   ```
3. On Windows you can also just double-click `START.bat` for an end-to-end run.

## Before you open a pull request

Run the same checks CI runs:

```bash
ruff check .
python -m compileall -q server.py launcher.py core.py auth tests
python -m unittest discover -s tests -v
```

All tests must pass and the tree must be lint-clean.

## Guidelines

- Keep pull requests focused; one logical change per PR.
- Add or update tests under `tests/` for any behaviour change.
- Update `CHANGELOG.md` under an appropriate version heading.
- Update `SECURITY.md` when you touch anything in the auth, scopes, command
  allow-list, or filesystem-boundary logic.
- Preserve line endings. `write_file`/`edit_file` are byte-exact since 2.1.1;
  do not let an editor mass-convert LF <-> CRLF.
- Never commit local/secret files (`config.json`, `oauth_state.json`,
  `connections.cfg`, `*.local.*`). They are already git-ignored.

## Reporting bugs and requesting features

Use the issue templates. For questions and usage help, prefer
[Discussions](https://github.com/oleg494/local-mcp-easy/discussions).

## Security

Please do not file public issues for security-sensitive reports. See
[SECURITY.md](SECURITY.md) for the security model and how to report privately.
