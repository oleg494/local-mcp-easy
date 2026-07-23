#!/usr/bin/env bash
# POSIX wrapper for `launcher.py --register-oauth-client` (mirrors register_oauth_client.bat).
set -e
cd "$(dirname "$0")"

if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN=python3
else
    PYTHON_BIN=python
fi

if [ ! -x ".venv/bin/python" ]; then
    "$PYTHON_BIN" -m venv .venv
fi

if ! .venv/bin/python -c "import mcp, uvicorn, starlette" >/dev/null 2>&1; then
    .venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt
fi

exec .venv/bin/python launcher.py --register-oauth-client "$@"
