#!/usr/bin/env bash
# POSIX wrapper for `launcher.py --stop` (mirrors stop.bat).
set -e
cd "$(dirname "$0")"

if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN=python3
else
    PYTHON_BIN=python
fi

# No dependency check here, deliberately: launcher.py --stop only reads
# runtime.json and signals PIDs -- it never imports mcp/uvicorn/starlette. The
# old check ran `pip install` first, so with `set -e` a down network (a very
# likely reason to be stopping things) aborted the script before anything was
# stopped. STOP.bat never had this failure mode; now neither does this.
if [ -x ".venv/bin/python" ]; then
    exec .venv/bin/python launcher.py --stop "$@"
fi
exec "$PYTHON_BIN" launcher.py --stop "$@"
