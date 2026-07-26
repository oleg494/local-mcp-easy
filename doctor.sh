#!/usr/bin/env bash
# POSIX wrapper for `launcher.py --doctor` (mirrors DOCTOR.bat).
# No dependency check: doctor's whole job is to report what is missing, so it
# must run even when nothing is installed.
set -e
cd "$(dirname "$0")"

if [ -x ".venv/bin/python" ]; then
    exec .venv/bin/python launcher.py --doctor "$@"
fi
if command -v python3 >/dev/null 2>&1; then
    exec python3 launcher.py --doctor "$@"
fi
exec python launcher.py --doctor "$@"
