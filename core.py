from __future__ import annotations

import contextlib
import hmac
import os
import shutil
import tempfile
from pathlib import Path


def _consteq(a: str, b: str) -> bool:
    """Constant-time string comparison that never raises on hostile input.

    hmac.compare_digest raises TypeError when handed a non-ASCII str (or a
    str/bytes mix), which would surface as an unhandled 500 instead of a clean
    401/403. Encoding both sides to bytes first keeps the comparison
    timing-safe while making an attacker-controlled token fail closed.
    """
    return hmac.compare_digest(a.encode("utf-8", "ignore"), b.encode("utf-8", "ignore"))

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


# Characters cmd.exe treats as syntax rather than data. Windows has no way to
# launch a .bat/.cmd file without cmd.exe: CreateProcess silently re-invokes
# `cmd.exe /c` for them, and cmd re-parses the command line it is handed.
BATCH_METACHARACTERS = frozenset('&|<>^"%!\r\n')


def is_batch_executable(executable: str) -> bool:
    return Path(executable).suffix.lower() in {".bat", ".cmd"}


def ensure_safe_batch_args(executable: str, args: list[str]) -> None:
    """Reject cmd.exe metacharacters in arguments to a .bat/.cmd program.

    Known as "BatBadBut" (CVE-2024-24576 in Rust; the same flaw exists in
    Python's subprocess). Passing args as a list with shell=False is NOT enough:
    for a batch target, Windows re-invokes cmd.exe, and Python's argv quoting
    (subprocess.list2cmdline) only quotes an argument containing whitespace or a
    quote -- it never escapes cmd's metacharacters. So an allow-listed
    `npm.cmd` handed the single argument `--version&whoami` runs `whoami`,
    defeating the entire allow-list.

    Verified against this repo's own venv: asyncio.create_subprocess_exec(
    r"...\\npm.cmd", "--version&whoami>marker.txt") wrote whoami's output to the
    marker file. Rejecting the metacharacters outright is the mitigation the
    upstream advisory recommends when the program cannot be re-pointed at a
    native executable; the alternative (dropping npm/npx from the allow-list)
    would break ordinary Node development.
    """
    if not is_batch_executable(executable):
        return
    for arg in args:
        bad = sorted(BATCH_METACHARACTERS.intersection(arg))
        if bad:
            raise ValueError(
                f"Argument contains characters that {Path(executable).name} would "
                f"re-interpret as shell syntax: {' '.join(repr(c) for c in bad)}. "
                "Windows runs .bat/.cmd programs through cmd.exe, so these could "
                "start a second, un-allow-listed command. Remove them, or invoke "
                "the underlying native executable instead."
            )


def atomic_write_text(path: Path, content: str, *, newline: str = "") -> None:
    """Write via unique temp file + fsync + replace: crash-safe and safe for
    parallel writers.

    newline="" disables translation so existing line endings survive a
    read-modify-write byte-for-byte; pass newline="\\n" to force LF.

    Single implementation shared by the server, the launcher and the OAuth
    store -- these had drifted into three copies with three different crash
    guarantees (the OAuth one never fsync'd, so a power loss could leave the
    token store truncated).
    """
    fd, temp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=path.name + ".", suffix=".mcp-tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline=newline) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise


def should_skip(path: Path, include_hidden: bool, excludes: set[str]) -> bool:
    name = path.name
    return name in excludes or (not include_hidden and name.startswith("."))


def is_inside(base_dir: Path, path: Path) -> bool:
    """True when path resolves inside base_dir, following links and junctions.

    os.walk cannot be trusted to stay inside the workspace on Windows: a
    directory junction (`mklink /J`, no admin rights needed) is not reported by
    is_symlink(), so followlinks=False does not stop os.walk descending through
    it. Every tree walk re-checks each entry with this instead.
    """
    try:
        safe_path(base_dir, path)
    except (ValueError, OSError):
        return False
    return True
