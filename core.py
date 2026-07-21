from __future__ import annotations

import os
import shutil
from pathlib import Path

DEFAULT_EXCLUDES = {
    ".git",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "node_modules",
    "venv",
}

DEFAULT_ALLOWED_COMMANDS = {
    "git",
    "make",
    "node",
    "npm",
    "npx",
    "pip",
    "py",
    "pytest",
    "python",
    "ruff",
    "uv",
}


def safe_path(base_dir: Path, value: str | os.PathLike[str]) -> Path:
    """Resolve a user path and guarantee that it stays inside base_dir."""
    base = base_dir.resolve()
    raw = Path(value).expanduser()
    candidate = raw.resolve() if raw.is_absolute() else (base / raw).resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"Access denied: path is outside {base}") from exc
    return candidate


def normalized_program_name(program: str) -> str:
    name = Path(program).name.lower()
    for suffix in (".exe", ".cmd", ".bat", ".com"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return name


def resolve_program(base_dir: Path, program: str, allowed: set[str]) -> str:
    """Resolve an executable without enabling a command shell."""
    if not program or "\x00" in program:
        raise ValueError("Program is required")

    name = normalized_program_name(program)
    if name not in allowed:
        raise ValueError(
            f"Program '{name}' is not allowed. Allowed: {', '.join(sorted(allowed))}"
        )

    if any(sep in program for sep in ("/", "\\")) or Path(program).is_absolute():
        # Reject path-qualified programs. Otherwise a client holding
        # mcp:files:write could drop an executable inside the workspace whose
        # basename matches an allow-listed name (e.g. sub/git.exe) and run it,
        # bypassing the allow-list. Require a bare name resolved from PATH.
        raise ValueError(
            "Path-qualified programs are not allowed; install the tool and "
            "reference it by bare name (resolved from the system PATH)."
        )

    resolved = shutil.which(program)
    if not resolved:
        raise ValueError(f"Program is not installed or not on PATH: {program}")
    return resolved


def should_skip(path: Path, include_hidden: bool, excludes: set[str]) -> bool:
    name = path.name
    return name in excludes or (not include_hidden and name.startswith("."))
