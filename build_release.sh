#!/usr/bin/env bash
# POSIX wrapper for `build_release.py` (mirrors build_release.bat).
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

# build_release.py uses only the stdlib (zipfile/pathlib), so no dependency
# install is needed here.
exec .venv/bin/python build_release.py "$@"
