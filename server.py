from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import datetime as dt
import fnmatch
import functools
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import unquote, urlsplit

from core import (
    DEFAULT_ALLOWED_COMMANDS,
    DEFAULT_EXCLUDES,
    _consteq,
    normalized_program_name,
    resolve_program,
    safe_path,
    should_skip,
)
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.routes import TOKEN_PATH
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import HTMLResponse, JSONResponse

from auth import (
    ALL_SCOPES,
    AUTH_MODE_DUAL,
    AUTH_MODE_LEGACY,
    AUTH_MODE_OAUTH,
    ConsentHandler,
    LegacyTokenVerifier,
    LocalOAuthProvider,
    OAuthStore,
    SCOPE_COMMANDS_RUN,
    SCOPE_FILES_READ,
    SCOPE_FILES_WRITE,
    SCOPE_GIT,
    build_auth_settings,
    parse_auth_mode,
    protected_resource_document,
    resource_url_for,
)
from auth.oauth import hash_client_secret

TOKEN = os.environ.get("MCP_TOKEN", "").strip()
BASE_DIR = Path(os.environ.get("MCP_BASE_DIR", str(Path.home() / "Documents"))).resolve()
SERVER_DIR = Path(__file__).resolve().parent
PORT = int(os.environ.get("MCP_PORT", "8765"))
STABLE_HOSTNAME = os.environ.get("MCP_SERVEO_HOSTNAME", "").strip().lower()
SERVEO_SUFFIX = ".serveousercontent.com"
ALLOW_COMMANDS = os.environ.get("MCP_ALLOW_COMMANDS", "0").lower() in {"1", "true", "yes"}
ALLOWED_COMMANDS = {
    item.strip().lower()
    for item in os.environ.get(
        "MCP_ALLOWED_COMMANDS", ",".join(sorted(DEFAULT_ALLOWED_COMMANDS))
    ).split(",")
    if item.strip()
}
EXCLUDES = set(DEFAULT_EXCLUDES)
MAX_TEXT_FILE = 5 * 1024 * 1024
MAX_WRITE = 2 * 1024 * 1024
# Cap for copy_file/move_file. A client holding mcp:files:write must not be
# able to exhaust disk by duplicating a multi-GB artifact. Enforced AFTER the
# _ensure_writable trust-anchor guard, never instead of it. Env-overridable.
MAX_COPY_MOVE_BYTES = int(
    os.environ.get("MCP_MAX_COPY_MOVE_BYTES", "") or 100 * 1024 * 1024
)
MAX_COMMAND_OUTPUT = 200_000
MAX_RESULTS = 1000
MAX_OUTPUT_CHARS = 10_000
DEFAULT_READ_LINES = 400
CHUNK_CHAR_LIMIT = 9_500
TEMP_DIRNAME = "temp"
TEMP_PATH_PREFIX = "@temp/"
# Temp-file TTL for the sweepers below. Env-overridable via MCP_TEMP_FILE_TTL.
TEMP_FILE_TTL_SECONDS = int(os.environ.get("MCP_TEMP_FILE_TTL", "") or 24 * 60 * 60)
# Minimum interval between orphan .mcp-tmp sweeps, so the BASE_DIR walk
# doesn't run on every tool call. Picked to be well below TEMP_FILE_TTL_SECONDS
# yet large enough to coalesce bursts of tool invocations.
ORPHAN_SWEEP_MIN_INTERVAL_SECONDS = 60.0
REPO_CONTEXT_FILE = "agent-repo-config.local.json"
REPO_CONTEXT_SCHEMA_VERSION = 3

if not TOKEN:
    raise RuntimeError("MCP_TOKEN is required")
if not BASE_DIR.is_dir():
    raise RuntimeError(f"MCP_BASE_DIR does not exist: {BASE_DIR}")

SERVER_NAME = "Local MCP Easy"
SERVER_VERSION = (SERVER_DIR / "VERSION").read_text(encoding="utf-8").strip() \
    if (SERVER_DIR / "VERSION").is_file() else "dev"

# --- Universal auth configuration (legacy | oauth | dual) -------------------
try:
    AUTH_MODE = parse_auth_mode(os.environ.get("MCP_AUTH_MODE"))
except ValueError as exc:
    raise RuntimeError(str(exc)) from exc
OAUTH_ENABLED = AUTH_MODE in (AUTH_MODE_OAUTH, AUTH_MODE_DUAL)

OWNER_CODE = os.environ.get("MCP_OAUTH_OWNER_CODE", "").strip()
_default_public_url = (
    f"https://{STABLE_HOSTNAME}{SERVEO_SUFFIX}"
    if STABLE_HOSTNAME
    else f"http://127.0.0.1:{PORT}"
)
PUBLIC_URL = (os.environ.get("MCP_PUBLIC_URL", "").strip() or _default_public_url).rstrip("/")
PUBLIC_HOST = (urlsplit(PUBLIC_URL).hostname or "").lower()
OAUTH_STATE_DIR = Path(
    os.environ.get("MCP_OAUTH_STATE_DIR", "").strip()
    or Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "LocalMcpEasy"
)
OAUTH_ACCESS_TTL = int(os.environ.get("MCP_OAUTH_ACCESS_TTL", "3600"))
OAUTH_REFRESH_TTL = int(os.environ.get("MCP_OAUTH_REFRESH_TTL", str(30 * 24 * 3600)))
OAUTH_MAX_CLIENTS = int(os.environ.get("MCP_OAUTH_MAX_CLIENTS", "100"))
OAUTH_UNUSED_CLIENT_TTL = int(os.environ.get("MCP_OAUTH_UNUSED_CLIENT_TTL", "3600"))
OAUTH_CONSENT_MAX_ATTEMPTS = int(os.environ.get("MCP_OAUTH_CONSENT_MAX_ATTEMPTS", "5"))
OAUTH_CONSENT_FAILURE_WINDOW = int(
    os.environ.get("MCP_OAUTH_CONSENT_FAILURE_WINDOW_SECONDS", "60")
)
OAUTH_CONSENT_MAX_FAILURES = int(
    os.environ.get("MCP_OAUTH_CONSENT_MAX_FAILURES", "10")
)
# Optional single-owner scope override: when set, every approved client gets
# exactly these scopes regardless of what it requested (see LocalOAuthProvider).
OAUTH_OWNER_GRANT_SCOPES = [
    scope
    for scope in os.environ.get("MCP_OAUTH_OWNER_GRANT_SCOPES", "").split()
    if scope in ALL_SCOPES
]

if OAUTH_ENABLED:
    if not OWNER_CODE:
        raise RuntimeError(
            "MCP_OAUTH_OWNER_CODE is required in oauth/dual mode. "
            "Run OAUTH_SETUP.bat (launcher.py --oauth) to configure it."
        )
    _is_local_issuer = PUBLIC_HOST in {"127.0.0.1", "localhost"}
    if not PUBLIC_URL.startswith("https://") and not _is_local_issuer:
        raise RuntimeError(
            "OAuth requires a stable https public URL (or 127.0.0.1 for local "
            f"testing); got: {PUBLIC_URL}"
        )

oauth_provider: LocalOAuthProvider | None = None
_fastmcp_auth_kwargs = {}
if OAUTH_ENABLED:
    _legacy_verifier = LegacyTokenVerifier(TOKEN) if AUTH_MODE == AUTH_MODE_DUAL else None
    oauth_provider = LocalOAuthProvider(
        store=OAuthStore(OAUTH_STATE_DIR / "oauth_state.json"),
        issuer_url=PUBLIC_URL,
        canonical_resource=resource_url_for(PUBLIC_URL),
        legacy_verifier=_legacy_verifier,
        access_ttl=OAUTH_ACCESS_TTL,
        refresh_ttl=OAUTH_REFRESH_TTL,
        max_clients=OAUTH_MAX_CLIENTS,
        unused_client_ttl=OAUTH_UNUSED_CLIENT_TTL,
        owner_grant_scopes=OAUTH_OWNER_GRANT_SCOPES or None,
    )
    _fastmcp_auth_kwargs = {
        "auth": build_auth_settings(PUBLIC_URL, SERVER_NAME),
        "auth_server_provider": oauth_provider,
    }

mcp = FastMCP(
    SERVER_NAME,
    host="127.0.0.1",
    port=PORT,
    stateless_http=True,
    json_response=True,
    # FastMCP's built-in localhost-only Host allowlist causes HTTP 421 behind
    # Serveo, so it is disabled and replaced by the Host check inside
    # SecurityMiddleware (localhost + *.serveousercontent.com).
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    **_fastmcp_auth_kwargs,
)

def _clip(text) -> str:
    if text is None:
        return "(no output)"
    text = str(text)
    if text == "":
        return "(empty result)"
    if len(text) > MAX_OUTPUT_CHARS:
        return (
            text[:MAX_OUTPUT_CHARS]
            + f"\n\n... [output truncated: {len(text):,} chars total, showing first "
            f"{MAX_OUTPUT_CHARS:,}. Use offset/limit or a narrower query to see more.]"
        )
    return text


def _require_scope(scope: str) -> None:
    """Deny-by-default OAuth scope check for the current request.

    In legacy mode the SecurityMiddleware already authenticated the master
    token, which has always granted full access — behaviour is unchanged.
    In oauth/dual mode every request carries an AccessToken (the SDK's
    RequireAuthMiddleware rejects anonymous requests before tools run), and
    the token must include the scope the tool was registered with.
    """
    if AUTH_MODE == AUTH_MODE_LEGACY:
        return
    access = get_access_token()
    if access is None:
        raise PermissionError(
            "Authentication context is missing; the request was not authorized."
        )
    if scope not in access.scopes:
        raise PermissionError(
            f"Access denied: this operation requires OAuth scope '{scope}'. "
            f"Granted scopes: {', '.join(access.scopes) or '(none)'}."
        )


def tool(scope: str):
    """Like @mcp.tool() but enforces an OAuth scope and clips every result."""
    if scope not in ALL_SCOPES:
        raise RuntimeError(f"Tool registered with unknown scope: {scope}")

    def deco(fn):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            _require_scope(scope)
            return _clip(await fn(*args, **kwargs))
        return mcp.tool()(wrapper)
    return deco


def _path(value: str = ".") -> Path:
    return safe_path(BASE_DIR, value)


def _ensure_writable(path: Path) -> None:
    """Reject writes to git-policy trust anchors.

    safe_path only proves a target stays inside the workspace; it does not stop
    a client from forging the repo-context file (which fakes an approved repo
    context) or rewriting git's own metadata under .git/ (e.g. .git/config).
    Both are trust anchors the git policy depends on, so every mutating file
    tool routes its target(s) through here.
    """
    if path.name == REPO_CONTEXT_FILE:
        raise ValueError(
            f"Refusing to modify the repo-context trust anchor '{REPO_CONTEXT_FILE}'. "
            "Use setup_git_context(...) / configure_repo_context(...) instead."
        )
    # Inspect components inside the workspace only (".git" is listed in EXCLUDES).
    try:
        parts = path.relative_to(BASE_DIR).parts
    except ValueError:
        parts = path.parts
    if ".git" in parts:
        raise ValueError("Refusing to modify anything inside a .git directory.")


def _is_binary_bytes(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def _temp_dir() -> Path:
    directory = SERVER_DIR / TEMP_DIRNAME
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _cleanup_temp_files() -> None:
    cutoff = dt.datetime.now().timestamp() - TEMP_FILE_TTL_SECONDS
    directory = _temp_dir()
    for item in directory.glob("*.txt"):
        try:
            if item.stat().st_mtime < cutoff:
                item.unlink()
        except OSError:
            continue


# Monotonic-clock timestamp (seconds) of the last orphan .mcp-tmp sweep.
# Initialized to -inf so the first call always sweeps, even on a freshly booted
# host where time.monotonic() is still below ORPHAN_SWEEP_MIN_INTERVAL_SECONDS.
_last_orphan_sweep: float = float("-inf")


def _cleanup_orphan_mcp_tmp() -> None:
    """Sweep BASE_DIR for orphaned ``.{name}.XXXXXX.mcp-tmp`` temp files.

    `_atomic_write_text` creates these next to the target file and renames
    them into place with `os.replace`. A crash/SIGKILL between `mkstemp` and
    `os.replace` leaves them behind as orphans that the original
    `_cleanup_temp_files` (which only sweeps ``temp/*.txt``) never sees.

    Walks BASE_DIR (respecting EXCLUDES and `core.should_skip`), unlinking any
    ``*.mcp-tmp`` older than TEMP_FILE_TTL_SECONDS. OSError on unlink/stat is
    suppressed so a concurrent writer or permission hiccup can't break callers.

    Throttled by `ORPHAN_SWEEP_MIN_INTERVAL_SECONDS` via a monotonic-clock
    last-sweep timestamp so the walk doesn't fire on every tool call.
    """
    global _last_orphan_sweep
    now_mono = time.monotonic()
    if now_mono - _last_orphan_sweep < ORPHAN_SWEEP_MIN_INTERVAL_SECONDS:
        return
    _last_orphan_sweep = now_mono
    cutoff = dt.datetime.now().timestamp() - TEMP_FILE_TTL_SECONDS
    base_dir = BASE_DIR
    include_hidden = False
    for root, dirs, files in os.walk(base_dir, topdown=True):
        # Prune excluded directories in-place so os.walk doesn't descend.
        dirs[:] = [
            d for d in dirs
            if not should_skip(base_dir / root / d, include_hidden, EXCLUDES)
        ]
        for name in files:
            if not name.endswith(".mcp-tmp"):
                continue
            candidate = Path(root) / name
            try:
                if candidate.stat().st_mtime < cutoff:
                    candidate.unlink()
            except OSError:
                continue


def _temp_virtual_path(path: Path) -> str:
    return f"{TEMP_PATH_PREFIX}{path.name}"


def _resolve_temp_path(path: str) -> Path:
    normalized = path.replace("\\", "/")
    if not normalized.startswith(TEMP_PATH_PREFIX):
        raise ValueError("Not a temp path")
    name = normalized[len(TEMP_PATH_PREFIX):].strip()
    if not name or "/" in name or ".." in name:
        raise ValueError("Invalid temp path")
    return _temp_dir() / name


def _resolve_read_file_path(path: str) -> tuple[Path, bool]:
    normalized = path.replace("\\", "/")
    if normalized.startswith(TEMP_PATH_PREFIX):
        return _resolve_temp_path(normalized), True
    return _path(path), False


def _tool_output_path(prefix: str) -> Path:
    _cleanup_temp_files()
    _cleanup_orphan_mcp_tmp()
    safe_prefix = "".join(
        ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in prefix
    ).strip("-") or "output"
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    return _temp_dir() / f"{safe_prefix}-{stamp}.txt"


def _repo_context_path(cwd: Path | None = None, git_args: list[str] | None = None) -> Path:
    scope_dir = BASE_DIR if cwd is None else cwd
    if cwd is not None:
        detected = _detect_git_repo(cwd, git_args)
        if detected["repo_present"]:
            scope_dir = Path(str(detected["top_level"]))
    return safe_path(scope_dir, REPO_CONTEXT_FILE)


def _normalize_repo_url(value: str) -> str:
    raw = value.strip()
    if not raw:
        return ""
    trimmed = raw.rstrip("/")
    if trimmed.lower().endswith(".git"):
        trimmed = trimmed[:-4]

    if "://" in trimmed:
        parsed = urlsplit(trimmed)
        host = (parsed.hostname or parsed.netloc).lower()
        repo_path = parsed.path.strip("/")
        if repo_path.lower().endswith(".git"):
            repo_path = repo_path[:-4]
        return f"{host}/{repo_path}".lower()

    ssh_match = re.fullmatch(r"(?:[^@]+@)?([^:]+):(.+)", trimmed)
    if ssh_match:
        host = ssh_match.group(1).lower()
        repo_path = ssh_match.group(2).strip("/")
        if repo_path.lower().endswith(".git"):
            repo_path = repo_path[:-4]
        return f"{host}/{repo_path}".lower()

    return trimmed.lower()


def _parse_fork_status(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"fork", "true", "yes"}:
        return True
    if normalized in {"not_fork", "false", "no", "standalone"}:
        return False
    raise ValueError("fork_status must be 'fork' or 'not_fork'")


def _coerce_repo_context(raw: dict[str, object], config_path: Path) -> dict[str, object]:
    status = raw.get("status")
    if status is None:
        status = "configured" if raw.get("repository_url") else "disabled"
    if not isinstance(status, str) or status not in {"configured", "disabled"}:
        raise ValueError("status must be 'configured' or 'disabled'")

    git_enabled = raw.get("git_enabled")
    if not isinstance(git_enabled, bool):
        git_enabled = status == "configured"

    repository_url = raw.get("repository_url", "")
    if repository_url is None:
        repository_url = ""
    if not isinstance(repository_url, str):
        raise ValueError("repository_url must be a string")
    repository_url = repository_url.strip()
    normalized_repository_url = _normalize_repo_url(repository_url) if repository_url else ""

    is_fork = raw.get("is_fork")
    if is_fork is not None and not isinstance(is_fork, bool):
        raise ValueError("is_fork must be true, false, or null")

    upstream_url = raw.get("upstream_url", "")
    if upstream_url is None:
        upstream_url = ""
    if not isinstance(upstream_url, str):
        raise ValueError("upstream_url must be a string")
    upstream_url = upstream_url.strip()
    normalized_upstream_url = _normalize_repo_url(upstream_url) if upstream_url else ""

    default_branch = raw.get("default_branch", "")
    if default_branch is None:
        default_branch = ""
    if not isinstance(default_branch, str):
        raise ValueError("default_branch must be a string")
    default_branch = default_branch.strip()

    branch_mode = raw.get("branch_mode", "default_branch")
    if not isinstance(branch_mode, str) or branch_mode not in {"default_branch", "specified_branch"}:
        raise ValueError("branch_mode must be 'default_branch' or 'specified_branch'")

    commit_branch = raw.get("commit_branch", "")
    if commit_branch is None:
        commit_branch = ""
    if not isinstance(commit_branch, str):
        raise ValueError("commit_branch must be a string")
    commit_branch = commit_branch.strip()

    disabled_reason = raw.get("disabled_reason", "")
    if disabled_reason is None:
        disabled_reason = ""
    if not isinstance(disabled_reason, str):
        raise ValueError("disabled_reason must be a string")

    last_detected_origin = raw.get("last_detected_origin", "")
    if last_detected_origin is None:
        last_detected_origin = ""
    if not isinstance(last_detected_origin, str):
        raise ValueError("last_detected_origin must be a string")

    last_detected_branch = raw.get("last_detected_branch", "")
    if last_detected_branch is None:
        last_detected_branch = ""
    if not isinstance(last_detected_branch, str):
        raise ValueError("last_detected_branch must be a string")

    configured_at = raw.get("configured_at", "")
    if configured_at is None:
        configured_at = ""
    if not isinstance(configured_at, str):
        raise ValueError("configured_at must be a string")

    last_checked_at = raw.get("last_checked_at", "")
    if last_checked_at is None:
        last_checked_at = ""
    if not isinstance(last_checked_at, str):
        raise ValueError("last_checked_at must be a string")

    if status == "configured":
        if not repository_url:
            raise ValueError("repository_url is required when git is configured")
        if not isinstance(is_fork, bool):
            raise ValueError("is_fork must be true or false when git is configured")
        if not git_enabled:
            raise ValueError("git_enabled cannot be false when status is configured")
    elif git_enabled:
        raise ValueError("git_enabled cannot be true when status is disabled")

    return {
        "schema_version": REPO_CONTEXT_SCHEMA_VERSION,
        "status": status,
        "git_enabled": git_enabled,
        "repository_url": repository_url,
        "normalized_repository_url": normalized_repository_url,
        "is_fork": is_fork,
        "upstream_url": upstream_url,
        "normalized_upstream_url": normalized_upstream_url,
        "default_branch": default_branch,
        "branch_mode": branch_mode,
        "commit_branch": commit_branch,
        "disabled_reason": disabled_reason,
        "last_detected_origin": last_detected_origin,
        "last_detected_branch": last_detected_branch,
        "configured_at": configured_at,
        "last_checked_at": last_checked_at,
        "config_path": config_path,
    }


def _load_repo_context(cwd: Path | None = None, git_args: list[str] | None = None) -> dict[str, object] | None:
    config_path = _repo_context_path(cwd, git_args)
    if not config_path.is_file():
        return None

    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid repo context file: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError("repo context must be a JSON object")
    return _coerce_repo_context(raw, config_path)


def _save_repo_context(
    *,
    status: str,
    repository_url: str = "",
    is_fork: bool | None = None,
    upstream_url: str = "",
    default_branch: str = "",
    branch_mode: str = "default_branch",
    commit_branch: str = "",
    git_enabled: bool | None = None,
    disabled_reason: str = "",
    last_detected_origin: str = "",
    last_detected_branch: str = "",
    cwd: Path | None = None,
    git_args: list[str] | None = None,
) -> Path:
    if status not in {"configured", "disabled"}:
        raise ValueError("status must be 'configured' or 'disabled'")
    if branch_mode not in {"default_branch", "specified_branch"}:
        raise ValueError("branch_mode must be 'default_branch' or 'specified_branch'")

    existing: dict[str, object] | None
    try:
        existing = _load_repo_context(cwd, git_args)
    except ValueError:
        existing = None

    if git_enabled is None:
        git_enabled = status == "configured"

    repository_url = repository_url.strip()
    upstream_url = upstream_url.strip()
    default_branch = default_branch.strip()
    commit_branch = commit_branch.strip()
    disabled_reason = disabled_reason.strip()
    normalized_repository_url = _normalize_repo_url(repository_url) if repository_url else ""
    normalized_upstream_url = _normalize_repo_url(upstream_url) if upstream_url else ""
    now = dt.datetime.now().isoformat(timespec="seconds")

    if status == "configured":
        if not repository_url:
            raise ValueError("repository_url is required when configuring git")
        if not isinstance(is_fork, bool):
            raise ValueError("is_fork must be true or false when configuring git")
        if branch_mode == "default_branch" and not default_branch:
            raise ValueError("default_branch is required when branch_mode='default_branch'")
        if branch_mode == "specified_branch" and not commit_branch:
            raise ValueError("commit_branch is required when branch_mode='specified_branch'")
    elif git_enabled:
        raise ValueError("git_enabled cannot be true when status is disabled")

    payload = {
        "schema_version": REPO_CONTEXT_SCHEMA_VERSION,
        "status": status,
        "git_enabled": git_enabled,
        "repository_url": repository_url,
        "normalized_repository_url": normalized_repository_url,
        "is_fork": is_fork,
        "upstream_url": upstream_url,
        "normalized_upstream_url": normalized_upstream_url,
        "default_branch": default_branch,
        "branch_mode": branch_mode,
        "commit_branch": commit_branch,
        "disabled_reason": disabled_reason,
        "last_detected_origin": last_detected_origin.strip(),
        "last_detected_branch": last_detected_branch.strip(),
        "configured_at": existing.get("configured_at", now) if existing else now,
        "last_checked_at": now,
    }

    config_path = _repo_context_path(cwd, git_args)
    _atomic_write_text(config_path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    return config_path


def _target_commit_branch(config: dict[str, object]) -> str:
    if str(config.get("branch_mode", "default_branch")) == "specified_branch":
        return str(config.get("commit_branch", "")).strip()
    return str(config.get("default_branch", "")).strip()


def _git_executable() -> str | None:
    return shutil.which("git")


def _require_git_executable() -> str:
    executable = _git_executable()
    if not executable:
        raise ValueError("Git is not installed or not on PATH.")
    return executable


def _split_git_global_args(git_args: list[str]) -> tuple[list[str], str]:
    options_with_value = {"-c", "-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env"}
    prefix: list[str] = []
    skip_next = False
    subcommand = ""

    for arg in git_args:
        if skip_next:
            prefix.append(arg)
            skip_next = False
            continue
        if arg in options_with_value:
            prefix.append(arg)
            skip_next = True
            continue
        if any(arg.startswith(f"{option}=") for option in options_with_value if option.startswith("--")):
            prefix.append(arg)
            continue
        if arg.startswith("-") and not subcommand:
            prefix.append(arg)
            continue
        if not subcommand:
            subcommand = arg.lower()
            break

    return prefix, subcommand


def _sanitized_env() -> dict[str, str]:
    """Return os.environ minus server secrets, for child processes.

    Child processes (allow-listed commands + git subprocesses) must never
    inherit the server's own credentials. Drop the legacy bearer token and every
    OAuth owner secret (owner code, granted scopes, and any future MCP_OAUTH_*
    key) while keeping the rest of the environment (PATH, HOME, ...) intact.
    """
    secret_keys = {
        "MCP_TOKEN",
        "MCP_OAUTH_OWNER_CODE",
        "MCP_OAUTH_OWNER_GRANT_SCOPES",
    }
    return {
        key: value
        for key, value in os.environ.items()
        if key not in secret_keys and not key.startswith("MCP_OAUTH_")
    }


def _run_git_query(
    cwd: Path,
    *args: str,
    timeout: int = 5,
    git_prefix: list[str] | None = None,
) -> subprocess.CompletedProcess[str] | None:
    executable = _git_executable()
    if not executable:
        return None
    return subprocess.run(
        [executable, *(git_prefix or []), *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        env=_sanitized_env(),
    )


def _run_git_checked(cwd: Path, *args: str, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    executable = _require_git_executable()
    result = subprocess.run(
        [executable, *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        env=_sanitized_env(),
    )
    if result.returncode != 0:
        details = (result.stderr or result.stdout or "unknown error").strip()
        raise ValueError(f"git {' '.join(args)} failed: {details}")
    return result


def _detect_git_repo(cwd: Path, git_args: list[str] | None = None) -> dict[str, object]:
    executable = _git_executable()
    result: dict[str, object] = {
        "git_installed": bool(executable),
        "repo_present": False,
        "top_level": "",
        "branch": "",
        "origin_url": "",
        "normalized_origin_url": "",
        "upstream_url": "",
        "normalized_upstream_url": "",
        "remotes": {},
    }
    if not executable:
        return result

    git_prefix, _ = _split_git_global_args(list(git_args or []))
    top_level = _run_git_query(cwd, "rev-parse", "--show-toplevel", git_prefix=git_prefix)
    if top_level is None or top_level.returncode != 0:
        return result

    root = top_level.stdout.strip()
    branch = _run_git_query(cwd, "branch", "--show-current", git_prefix=git_prefix)
    remotes_query = _run_git_query(cwd, "remote", git_prefix=git_prefix)
    remotes: dict[str, str] = {}
    if remotes_query is not None and remotes_query.returncode == 0:
        for remote_name in [line.strip() for line in remotes_query.stdout.splitlines() if line.strip()]:
            url_query = _run_git_query(cwd, "config", "--get", f"remote.{remote_name}.url", git_prefix=git_prefix)
            if url_query is not None and url_query.returncode == 0:
                remotes[remote_name] = url_query.stdout.strip()

    origin_url = remotes.get("origin", "")
    upstream_url = remotes.get("upstream", "")
    branch_name = branch.stdout.strip() if branch is not None and branch.returncode == 0 else ""

    result.update(
        {
            "repo_present": True,
            "top_level": root,
            "branch": branch_name,
            "origin_url": origin_url,
            "normalized_origin_url": _normalize_repo_url(origin_url) if origin_url else "",
            "upstream_url": upstream_url,
            "normalized_upstream_url": _normalize_repo_url(upstream_url) if upstream_url else "",
            "remotes": remotes,
        }
    )
    return result


def _inspect_git_repository_text(cwd: Path) -> str:
    detected = _detect_git_repo(cwd)
    lines = [f"workspace path: {cwd}"]
    lines.append(f"git installed: {'yes' if detected['git_installed'] else 'no'}")
    if not detected["git_installed"]:
        return "\n".join(lines)
    lines.append(f"repository present: {'yes' if detected['repo_present'] else 'no'}")
    if not detected["repo_present"]:
        return "\n".join(lines)

    lines.append(f"git root: {detected['top_level']}")
    lines.append(f"git branch: {detected['branch'] or '(detached or unknown)'}")
    remotes = detected["remotes"]
    if not remotes:
        lines.append("git remotes: (none)")
    else:
        lines.append("git remotes:")
        for name in sorted(remotes):
            lines.append(f"- {name}: {remotes[name]}")
    return "\n".join(lines)


def _repo_context_state(cwd: Path, git_args: list[str] | None = None) -> tuple[str, dict[str, object] | None, dict[str, object], list[str]]:
    lines: list[str] = []
    config: dict[str, object] | None

    try:
        config = _load_repo_context(cwd, git_args)
    except ValueError as exc:
        config = None
        lines.append(f"repo context status: invalid ({exc})")
        detected = _detect_git_repo(cwd, git_args)
        lines.append("git policy: blocked")
        lines.append("next step: recreate the local repo context with setup_git_context(...) or configure_repo_context(...)")
        return "invalid_context", config, detected, lines

    if config is None:
        lines.append(f"repo context status: missing ({REPO_CONTEXT_FILE})")
    else:
        lines.append(f"repo context status: {config['status']}")
        lines.append(f"git enabled: {'yes' if config['git_enabled'] else 'no'}")
        if config["repository_url"]:
            lines.append(f"repo url: {config['repository_url']}")
        if config["is_fork"] is not None:
            lines.append(f"repo fork: {'yes' if config['is_fork'] else 'no'}")
        if config["upstream_url"]:
            lines.append(f"repo upstream: {config['upstream_url']}")
        if config["default_branch"]:
            lines.append(f"repo default branch: {config['default_branch']}")
        branch_mode = str(config.get("branch_mode", "default_branch"))
        if branch_mode == "specified_branch":
            lines.append(f"commit branch policy: explicit branch ({config['commit_branch'] or 'unset'})")
        else:
            lines.append(f"commit branch policy: default branch ({config['default_branch'] or 'unset'})")
        if config["disabled_reason"]:
            lines.append(f"disabled reason: {config['disabled_reason']}")

    detected = _detect_git_repo(cwd, git_args)
    if not detected["git_installed"]:
        lines.append("git detected: not installed")
        lines.append("git policy: blocked")
        lines.append("next step: install Git or keep trusted developer mode turned off for git work")
        return "git_unavailable", config, detected, lines

    if not detected["repo_present"]:
        lines.append("git detected: no repository in current path")
        if config is None:
            lines.append("git policy: blocked")
            lines.append("next step: ask the user to choose one of: init_new_repo, attach_to_remote, or disable_git")
            lines.append("branch policy choice: the user must also choose whether commits go to the default branch or to a specific branch name")
            return "setup_required_no_repo", config, detected, lines
        if config["status"] == "disabled":
            lines.append("git policy: disabled by user for this workspace")
            lines.append("next step: re-enable with setup_git_context(mode='init_new_repo' or mode='attach_to_remote') if needed")
            return "disabled", config, detected, lines
        lines.append("git policy: blocked")
        lines.append("next step: restore the repository in this folder or run setup_git_context(mode='attach_to_remote', ...) to initialize it here")
        return "repo_missing", config, detected, lines

    lines.append(f"git root: {detected['top_level']}")
    lines.append(f"git branch: {detected['branch'] or '(detached or unknown)'}")
    lines.append(f"git origin: {detected['origin_url'] or '(missing)'}")
    lines.append(f"git upstream: {detected['upstream_url'] or '(missing)'}")

    if config is None:
        lines.append("git policy: blocked")
        lines.append("next step: ask the user to choose one of: bind_existing_repo, attach_to_remote, or disable_git")
        lines.append("branch policy choice: the user must also choose whether commits go to the default branch or to a specific branch name")
        return "setup_required_existing_repo", config, detected, lines

    if config["status"] == "disabled":
        lines.append("git policy: disabled by user for this workspace")
        lines.append("next step: re-enable with setup_git_context(mode='bind_existing_repo', ...) or mode='attach_to_remote' if the target repo changed")
        return "disabled", config, detected, lines

    target_branch = _target_commit_branch(config)
    if not target_branch:
        lines.append("branch policy check: target branch is not configured")
        lines.append("git policy: blocked")
        lines.append("next step: rerun setup_git_context(...) and choose default_branch or commit_branch explicitly")
        return "branch_policy_missing", config, detected, lines

    if not detected["origin_url"]:
        lines.append("repo context check: origin missing")
        lines.append("git policy: blocked")
        lines.append("next step: run setup_git_context(mode='bind_existing_repo', repository_url='...', fork_status='fork|not_fork', branch_mode='default_branch|specified_branch', commit_branch='...') to set origin")
        return "repo_present_no_origin", config, detected, lines

    if detected["normalized_origin_url"] != config["normalized_repository_url"]:
        lines.append("repo context check: mismatch")
        lines.append("git policy: blocked")
        lines.append("next step: run setup_git_context(..., force_origin_update=true) or disable_git for this workspace")
        return "repo_present_bound_mismatch", config, detected, lines

    lines.append(f"commit target branch: {target_branch}")
    lines.append("repo context check: ok")
    lines.append("git policy: allowed")
    return "repo_present_bound_ok", config, detected, lines


def _repo_context_summary(cwd: Path, git_args: list[str] | None = None) -> str:
    _, _, _, lines = _repo_context_state(cwd, git_args)
    return "\n".join(lines)


def _build_repo_context_desired(
    *,
    status: str,
    repository_url: str,
    is_fork: bool | None,
    upstream_url: str,
    default_branch: str,
    branch_mode: str,
    commit_branch: str,
    git_enabled: bool,
    disabled_reason: str,
) -> dict[str, object]:
    repository_url = repository_url.strip()
    upstream_url = upstream_url.strip()
    default_branch = default_branch.strip()
    commit_branch = commit_branch.strip()
    disabled_reason = disabled_reason.strip()
    return {
        "status": status,
        "git_enabled": git_enabled,
        "repository_url": repository_url,
        "normalized_repository_url": _normalize_repo_url(repository_url) if repository_url else "",
        "is_fork": is_fork,
        "upstream_url": upstream_url,
        "normalized_upstream_url": _normalize_repo_url(upstream_url) if upstream_url else "",
        "default_branch": default_branch,
        "branch_mode": branch_mode,
        "commit_branch": commit_branch,
        "disabled_reason": disabled_reason,
    }


def _format_policy_value(value: object) -> str:
    if value is None or value == "":
        return "(empty)"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def _repo_context_change_descriptions(
    existing: dict[str, object], desired: dict[str, object]
) -> list[str]:
    comparisons = [
        ("status", "status"),
        ("git_enabled", "git enabled"),
        ("normalized_repository_url", "repository URL"),
        ("is_fork", "fork setting"),
        ("normalized_upstream_url", "upstream URL"),
        ("default_branch", "default branch"),
        ("branch_mode", "branch mode"),
        ("commit_branch", "commit branch"),
        ("disabled_reason", "disabled reason"),
    ]
    changes: list[str] = []
    for key, label in comparisons:
        if existing.get(key) != desired.get(key):
            changes.append(
                f"{label}: {_format_policy_value(existing.get(key))} -> {_format_policy_value(desired.get(key))}"
            )
    return changes


def _require_repo_context_confirmation(
    existing: dict[str, object] | None,
    desired: dict[str, object],
    confirm_reconfigure: bool,
) -> None:
    if existing is None:
        return
    changes = _repo_context_change_descriptions(existing, desired)
    if changes and not confirm_reconfigure:
        raise ValueError(
            "Repo context already exists for this repository. Any change requires explicit confirmation. "
            "Rerun with confirm_reconfigure=true. Proposed changes:\n- "
            + "\n- ".join(changes)
        )


def _require_explicit_defaults(defaults_used: list[str], confirm_defaults: bool) -> None:
    if defaults_used and not confirm_defaults:
        raise ValueError(
            "Some settings are not explicitly set. Pass explicit values or rerun with "
            "confirm_defaults=true to accept these defaults: "
            + ", ".join(defaults_used)
        )


def _repo_state_label(state: str) -> str:
    return {
        "repo_present_bound_ok": "ok",
        "setup_required_no_repo": "no git repo",
        "setup_required_existing_repo": "missing context",
        "repo_present_bound_mismatch": "origin mismatch",
        "repo_present_no_origin": "origin missing",
        "branch_policy_missing": "branch policy missing",
        "disabled": "disabled",
        "repo_missing": "repo missing",
        "git_unavailable": "git unavailable",
        "invalid_context": "invalid context",
    }.get(state, state.replace("_", " "))


def _discover_workspace_git_roots(base_dir: Path, limit: int = 25) -> list[Path]:
    roots: list[Path] = []
    for current, dirs, files in os.walk(base_dir):
        current_path = Path(current)
        has_git = ".git" in dirs or ".git" in files
        dirs[:] = sorted(
            d
            for d in dirs
            if d != ".git" and d not in EXCLUDES and not d.startswith(".")
        )
        if has_git:
            safe_path(base_dir, current_path)
            roots.append(current_path.resolve())
            if len(roots) >= limit:
                break
    seen: set[Path] = set()
    ordered: list[Path] = []
    for repo_root in sorted(roots, key=lambda p: (len(p.relative_to(base_dir).parts), str(p).lower())):
        if repo_root not in seen:
            seen.add(repo_root)
            ordered.append(repo_root)
    return ordered


def _format_workspace_repo_line(repo_root: Path) -> str:
    state, config, detected, _ = _repo_context_state(repo_root)
    rel = "." if repo_root == BASE_DIR else str(repo_root.relative_to(BASE_DIR))
    current_branch = str(detected.get("branch", "")).strip() or "(detached or unknown)"
    target_branch = _target_commit_branch(config) if config else ""
    parts = [_repo_state_label(state), f"current {current_branch}"]
    if target_branch:
        parts.append(f"target {target_branch}")
    return f"{rel} - " + " | ".join(parts)


def _workspace_repo_overview(base_dir: Path = BASE_DIR, max_nested: int = 10) -> str:
    roots = _discover_workspace_git_roots(base_dir)
    if not roots:
        return "git repos in workspace: none"

    lines = [f"git repos in workspace: {len(roots)}"]
    if base_dir in roots:
        lines.append(f"root repo: {_format_workspace_repo_line(base_dir)}")
    else:
        lines.append("root repo: none")

    nested = [repo_root for repo_root in roots if repo_root != base_dir]
    lines.append(f"nested repos: {len(nested)}")
    for repo_root in nested[:max_nested]:
        lines.append(f"- {_format_workspace_repo_line(repo_root)}")
    if len(nested) > max_nested:
        lines.append(f"... and {len(nested) - max_nested} more nested repos")
    lines.append("Use repo_context_status(cwd='...') for full details on a specific repo.")
    return "\n".join(lines)


def _ensure_remote_url(cwd: Path, remote_name: str, url: str, force_update: bool, confirm_reconfigure: bool = False) -> str:
    current_query = _run_git_query(cwd, "config", "--get", f"remote.{remote_name}.url")
    current_url = current_query.stdout.strip() if current_query is not None and current_query.returncode == 0 else ""
    current_normalized = _normalize_repo_url(current_url) if current_url else ""
    target_normalized = _normalize_repo_url(url)

    if not current_url:
        _run_git_checked(cwd, "remote", "add", remote_name, url)
        return f"added remote {remote_name}"
    if current_normalized == target_normalized:
        return f"kept remote {remote_name}"
    if not force_update:
        raise ValueError(
            f"remote.{remote_name}.url already points to {current_url}. "
            f"Use force_origin_update=true to change it to {url}."
        )
    if not confirm_reconfigure:
        raise ValueError(
            f"remote.{remote_name}.url already points to {current_url}. "
            "Changing an existing git remote requires explicit confirmation. "
            "Rerun with confirm_reconfigure=true as well."
        )
    _run_git_checked(cwd, "remote", "set-url", remote_name, url)
    return f"updated remote {remote_name}"


def _setup_git_context_sync(
    cwd: Path,
    *,
    mode: str,
    repository_url: str = "",
    fork_status: str = "",
    upstream_url: str = "",
    default_branch: str = "",
    branch_mode: str = "default_branch",
    commit_branch: str = "",
    disable_reason: str = "",
    force_origin_update: bool = False,
    set_upstream_remote: bool = False,
    confirm_defaults: bool = False,
    confirm_reconfigure: bool = False,
) -> str:
    mode = mode.strip()
    branch_mode = branch_mode.strip() or "default_branch"
    if mode not in {"bind_existing_repo", "attach_to_remote", "init_new_repo", "disable_git"}:
        raise ValueError("mode must be one of: bind_existing_repo, attach_to_remote, init_new_repo, disable_git")
    if branch_mode not in {"default_branch", "specified_branch"}:
        raise ValueError("branch_mode must be 'default_branch' or 'specified_branch'")

    try:
        existing = _load_repo_context(cwd)
    except ValueError:
        existing = None
    detected_before = _detect_git_repo(cwd)
    if not detected_before["git_installed"]:
        raise ValueError("Git is not installed or not on PATH.")
    if mode == "bind_existing_repo" and not detected_before["repo_present"]:
        raise ValueError(
            "No git repository exists here yet. Ask the user whether to "
            "init_new_repo, attach_to_remote, or disable_git."
        )

    if mode == "disable_git":
        repository_url = (
            str(existing["repository_url"]) if existing and existing["repository_url"] else str(detected_before["origin_url"])
        ).strip()
        is_fork = existing["is_fork"] if existing else None
        upstream_url = str(existing["upstream_url"]) if existing else ""
        default_branch = str(existing["default_branch"]) if existing else ""
        branch_mode = str(existing["branch_mode"]) if existing and existing.get("branch_mode") else "default_branch"
        commit_branch = str(existing["commit_branch"]) if existing else ""
        defaults_used: list[str] = []
        if not disable_reason.strip():
            disable_reason = "user choice"
            defaults_used.append("disable_reason='user choice'")
        _require_explicit_defaults(defaults_used, confirm_defaults)
        desired = _build_repo_context_desired(
            status="disabled",
            repository_url=repository_url,
            is_fork=is_fork if isinstance(is_fork, bool) else None,
            upstream_url=upstream_url,
            default_branch=default_branch,
            branch_mode=branch_mode,
            commit_branch=commit_branch,
            git_enabled=False,
            disabled_reason=disable_reason,
        )
        _require_repo_context_confirmation(existing, desired, confirm_reconfigure)
        config_path = _save_repo_context(
            cwd=cwd,
            status="disabled",
            repository_url=repository_url,
            is_fork=is_fork if isinstance(is_fork, bool) else None,
            upstream_url=upstream_url,
            default_branch=default_branch,
            branch_mode=branch_mode,
            commit_branch=commit_branch,
            git_enabled=False,
            disabled_reason=disable_reason,
            last_detected_origin=str(detected_before["origin_url"]),
            last_detected_branch=str(detected_before["branch"]),
        )
        summary = _repo_context_summary(cwd)
        return f"Saved disabled git policy to {config_path.relative_to(BASE_DIR)}\n\n{summary}"

    repository_url = repository_url.strip()
    if not repository_url:
        raise ValueError("repository_url is required for this setup mode")
    if not fork_status.strip():
        raise ValueError("fork_status must be explicitly set to 'fork' or 'not_fork'")
    is_fork = _parse_fork_status(fork_status)
    upstream_url = upstream_url.strip()
    default_branch = default_branch.strip()
    commit_branch = commit_branch.strip()
    defaults_used: list[str] = []

    if branch_mode == "specified_branch" and not commit_branch:
        raise ValueError("commit_branch is required when branch_mode='specified_branch'")

    if branch_mode == "default_branch" and not default_branch:
        if mode == "init_new_repo" or (mode == "attach_to_remote" and not detected_before["repo_present"]):
            default_branch = "main"
            defaults_used.append("default_branch='main'")
        elif existing and existing.get("default_branch"):
            default_branch = str(existing["default_branch"]).strip()
        elif detected_before["branch"]:
            default_branch = str(detected_before["branch"]).strip()
            defaults_used.append(f"default_branch='{default_branch}'")
        else:
            raise ValueError(
                "default_branch is not set. Pass it explicitly, or rerun with confirm_defaults=true "
                "only when a safe default is available."
            )
    _require_explicit_defaults(defaults_used, confirm_defaults)

    desired = _build_repo_context_desired(
        status="configured",
        repository_url=repository_url,
        is_fork=is_fork,
        upstream_url=upstream_url,
        default_branch=default_branch,
        branch_mode=branch_mode,
        commit_branch=commit_branch,
        git_enabled=True,
        disabled_reason="",
    )
    _require_repo_context_confirmation(existing, desired, confirm_reconfigure)

    actions: list[str] = []
    work_root = cwd

    if mode == "init_new_repo":
        if detected_before["repo_present"]:
            raise ValueError("A git repository already exists here. Use bind_existing_repo or attach_to_remote instead.")
        _run_git_checked(cwd, "init")
        actions.append("initialized git repository")
        work_root = cwd
        if default_branch:
            _run_git_checked(cwd, "branch", "-M", default_branch)
            actions.append(f"set default branch to {default_branch}")
    elif mode == "attach_to_remote":
        if not detected_before["repo_present"]:
            _run_git_checked(cwd, "init")
            actions.append("initialized git repository")
            if default_branch:
                _run_git_checked(cwd, "branch", "-M", default_branch)
                actions.append(f"set default branch to {default_branch}")
            work_root = cwd
        else:
            work_root = Path(str(detected_before["top_level"]))
    elif mode == "bind_existing_repo":
        if not detected_before["repo_present"]:
            raise ValueError("No git repository exists here yet. Ask the user whether to init_new_repo, attach_to_remote, or disable_git.")
        work_root = Path(str(detected_before["top_level"]))

    actions.append(_ensure_remote_url(work_root, "origin", repository_url, force_origin_update, confirm_reconfigure))
    if upstream_url and set_upstream_remote:
        actions.append(_ensure_remote_url(work_root, "upstream", upstream_url, True, confirm_reconfigure))

    detected_after = _detect_git_repo(work_root)
    final_branch = str(detected_after["branch"] or default_branch).strip()
    stored_default_branch = default_branch or final_branch
    if branch_mode == "default_branch" and not stored_default_branch:
        raise ValueError("default_branch is required when branch_mode='default_branch'")

    config_path = _save_repo_context(
        cwd=work_root,
        status="configured",
        repository_url=repository_url,
        is_fork=is_fork,
        upstream_url=upstream_url,
        default_branch=stored_default_branch,
        branch_mode=branch_mode,
        commit_branch=commit_branch,
        git_enabled=True,
        disabled_reason="",
        last_detected_origin=str(detected_after["origin_url"]),
        last_detected_branch=str(final_branch),
    )
    summary = _repo_context_summary(work_root)
    return (
        f"Saved repo context to {config_path.relative_to(BASE_DIR)}\n"
        f"mode: {mode}\n"
        f"branch policy: {branch_mode}\n"
        f"actions: {', '.join(actions)}\n\n"
        f"{summary}"
    )


def _split_git_command(git_args: list[str]) -> tuple[list[str], str, list[str]]:
    options_with_value = {"-c", "-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env"}
    prefix: list[str] = []
    index = 0
    while index < len(git_args):
        arg = git_args[index]
        if arg in options_with_value:
            prefix.append(arg)
            if index + 1 < len(git_args):
                prefix.append(git_args[index + 1])
            index += 2
            continue
        if any(arg.startswith(f"{option}=") for option in options_with_value if option.startswith("--")):
            prefix.append(arg)
            index += 1
            continue
        if arg.startswith("-"):
            prefix.append(arg)
            index += 1
            continue
        return prefix, arg.lower(), git_args[index + 1:]
    return prefix, "", []


# Global git prefix options that either run an arbitrary program (-c/--config-env
# can set core.editor / core.sshCommand / credential.helper, --exec-path relocates
# the git binary directory) or retarget git outside the validated workspace
# (-C, --git-dir, --work-tree, --namespace). None may originate from a client.
_UNSAFE_GIT_GLOBAL_OPTIONS = {
    "-c",
    "--config-env",
    "-C",
    "--git-dir",
    "--work-tree",
    "--exec-path",
    "--namespace",
}


def _reject_unsafe_git_global_options(prefix: list[str]) -> None:
    for arg in prefix:
        # `--opt=value` and bare `--opt` share the same policy decision.
        base = arg.split("=", 1)[0]
        if base in _UNSAFE_GIT_GLOBAL_OPTIONS:
            raise ValueError(
                "Git is blocked because the global option "
                f"'{base}' can run arbitrary programs or retarget git outside "
                "the validated workspace."
            )


def _command_positionals(args: list[str], options_with_value: set[str] | None = None) -> list[str]:
    options_with_value = options_with_value or set()
    positionals: list[str] = []
    skip_next = False
    passthrough = False
    for arg in args:
        if passthrough:
            positionals.append(arg)
            continue
        if skip_next:
            skip_next = False
            continue
        if arg == "--":
            passthrough = True
            continue
        if arg in options_with_value:
            skip_next = True
            continue
        if any(arg.startswith(f"{option}=") for option in options_with_value if option.startswith("--")):
            continue
        if arg.startswith("-"):
            continue
        positionals.append(arg)
    return positionals


def _allowed_remote_urls(config: dict[str, object]) -> set[str]:
    urls = {
        str(config.get("normalized_repository_url", "")).strip(),
        str(config.get("normalized_upstream_url", "")).strip(),
    }
    return {url for url in urls if url}


def _normalize_remote_candidate(remote_ref: str, detected: dict[str, object]) -> str:
    remotes = detected.get("remotes", {})
    if isinstance(remotes, dict) and remote_ref in remotes:
        return _normalize_repo_url(str(remotes[remote_ref]))
    if "://" in remote_ref or re.fullmatch(r"(?:[^@]+@)?[^:]+:.+", remote_ref):
        return _normalize_repo_url(remote_ref)
    return ""


def _ensure_remote_reference_allowed(
    remote_ref: str,
    config: dict[str, object],
    detected: dict[str, object],
    *,
    context: str,
) -> None:
    if not remote_ref:
        return
    normalized = _normalize_remote_candidate(remote_ref, detected)
    if not normalized:
        raise ValueError(
            f"Git is blocked because {context} must use a configured remote, but got {remote_ref}."
        )
    if normalized not in _allowed_remote_urls(config):
        raise ValueError(
            f"Git is blocked because {context} points to a remote outside the approved repo context: {remote_ref}."
        )


def _require_current_branch_matches(current_branch: str, target_branch: str) -> None:
    if not current_branch:
        raise ValueError(
            f"Git is blocked because changes for this workspace must happen on {target_branch}, "
            "but the repository is currently detached or the branch is unknown."
        )
    if current_branch != target_branch:
        raise ValueError(
            f"Git is blocked because this workspace is configured to work on {target_branch}, "
            f"but the current branch is {current_branch}. Switch branches first or update the repo context."
        )


def _is_git_config_read_only(args: list[str]) -> bool:
    # `--edit`/`-e` opens the config in $EDITOR, which is attacker-controllable
    # and executes an arbitrary program, so it must never count as read-only.
    mutating_flags = {
        "--add", "--replace-all", "--unset", "--unset-all",
        "--remove-section", "--rename-section", "--edit", "-e",
    }
    if any(flag in args for flag in mutating_flags):
        return False
    positionals = _command_positionals(args, {"-f", "--file", "--type", "--default", "--blob", "--fixed-value", "--url"})
    return len(positionals) <= 1


def _is_git_remote_read_only(args: list[str]) -> bool:
    if not args:
        return True
    if args[0] in {"-v", "--verbose"}:
        return True
    return args[0] in {"show", "get-url"}


def _remote_read_only_target(args: list[str]) -> str:
    if not args or args[0] in {"-v", "--verbose"}:
        return ""
    if args[0] in {"show", "get-url"}:
        positionals = _command_positionals(args[1:])
        return positionals[0] if positionals else ""
    return ""


def _is_git_branch_read_only(args: list[str]) -> bool:
    if not args:
        return True
    mutating_flags = {"-d", "-D", "-m", "-M", "-c", "-C", "--move", "--copy", "--delete", "--set-upstream-to", "--unset-upstream", "--edit-description"}
    if any(flag in args for flag in mutating_flags):
        return False
    positionals = _command_positionals(args, {"--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--format", "--sort", "--column"})
    return len(positionals) == 0


def _is_git_tag_read_only(args: list[str]) -> bool:
    if not args:
        return True
    if any(flag in args for flag in {"-d", "--delete", "-f", "--force", "-a", "-s", "-u", "-m", "-F", "--cleanup", "--trailer"}):
        return False
    positionals = _command_positionals(args, {"-m", "-F", "-u", "--cleanup", "--trailer"})
    return len(positionals) == 0 or any(flag in args for flag in {"-l", "--list"})


def _checkout_target_branch(args: list[str]) -> str:
    scan = args[: args.index("--")] if "--" in args else args
    index = 0
    while index < len(scan):
        arg = scan[index]
        if arg in {"-b", "-B", "--orphan"}:
            return scan[index + 1] if index + 1 < len(scan) else ""
        if arg.startswith("-"):
            index += 1
            continue
        return arg
    return ""


def _switch_target_branch(args: list[str]) -> str:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in {"-c", "-C", "--orphan"}:
            return args[index + 1] if index + 1 < len(args) else ""
        if arg.startswith("-"):
            index += 1
            continue
        return arg
    return ""


def _branch_target(args: list[str]) -> str:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in {"-d", "-D", "-m", "-M", "-c", "-C", "--move", "--copy", "--delete", "--set-upstream-to"}:
            return args[index + 1] if index + 1 < len(args) else ""
        if arg.startswith("--set-upstream-to="):
            return arg.split("=", 1)[1]
        if arg.startswith("-"):
            index += 1
            continue
        return arg
    return ""


def _push_remote_and_refspecs(args: list[str]) -> tuple[str, list[str]]:
    positionals = _command_positionals(args, {"-u", "--set-upstream", "--repo", "--receive-pack", "--exec", "-o", "--push-option"})
    if not positionals:
        return "", []
    return positionals[0], positionals[1:]


def _git_config_value(
    cwd: Path, key: str, *, git_prefix: list[str] | None = None
) -> str:
    query = _run_git_query(cwd, "config", "--get", key, git_prefix=git_prefix)
    if query is None or query.returncode != 0:
        return ""
    return query.stdout.strip()


def _effective_push_remote(
    cwd: Path, current_branch: str, detected: dict[str, object], git_args: list[str]
) -> str:
    git_prefix, _ = _split_git_global_args(git_args)
    keys = []
    if current_branch:
        keys.append(f"branch.{current_branch}.pushRemote")
    keys.append("remote.pushDefault")
    if current_branch:
        keys.append(f"branch.{current_branch}.remote")
    for key in keys:
        value = _git_config_value(cwd, key, git_prefix=git_prefix)
        if value and value != ".":
            return value
    remotes = detected.get("remotes", {})
    return "origin" if isinstance(remotes, dict) and "origin" in remotes else ""


def _blocked_push_mode(args: list[str]) -> str:
    # Force flags (-f/--force/--force-with-lease) can overwrite remote history;
    # the multi-ref modes update/delete refs outside the branch policy. Match on
    # the option base so `--force-with-lease=<ref>` is caught too.
    blocked = {
        "--all", "--mirror", "--tags", "--delete", "-d", "--prune",
        "-f", "--force", "--force-with-lease",
    }
    for arg in args:
        base = arg.split("=", 1)[0]
        if base in blocked:
            return base
    return ""


def _pull_remote_and_branch(args: list[str]) -> tuple[str, str]:
    positionals = _command_positionals(args, {"--rebase-merges", "--strategy", "--strategy-option"})
    remote = positionals[0] if positionals else ""
    branch = positionals[1] if len(positionals) > 1 else ""
    return remote, branch


_FETCH_OPTIONS_WITH_VALUE = {
    "--depth", "--deepen", "--shallow-since", "--shallow-exclude",
    "--refmap", "--filter", "-o", "--server-option", "--upload-pack",
}


def _fetch_remote(args: list[str]) -> str:
    if "--all" in args:
        return "__ALL__"
    positionals = _command_positionals(args, _FETCH_OPTIONS_WITH_VALUE)
    return positionals[0] if positionals else ""


def _fetch_refspecs(args: list[str]) -> list[str]:
    # Everything after the remote is a refspec (src[:dst]).
    positionals = _command_positionals(args, _FETCH_OPTIONS_WITH_VALUE)
    return positionals[1:]


def _local_ref_branch(ref: str) -> str:
    return ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref


def _refspec_target_branch(refspec: str, current_branch: str) -> str:
    # A leading '+' forces a non-fast-forward update and can clobber history.
    if refspec.startswith("+"):
        raise ValueError(
            "Git is blocked because a forced-update refspec ('+...') can "
            "overwrite refs outside the configured branch policy."
        )
    source = target = refspec
    if ":" in refspec:
        source, target = refspec.split(":", 1)
        # An empty source (':branch') is delete-branch syntax.
        if source == "":
            raise ValueError(
                "Git is blocked because an empty-source refspec (':branch') "
                "deletes a remote branch, which the branch policy forbids."
            )
    if target in {"", "HEAD"}:
        return current_branch
    return _local_ref_branch(target)


def _ensure_transport_refspec_allowed(
    refspec: str, target_branch: str, *, context: str
) -> None:
    """Validate a fetch/pull refspec's local-ref destination.

    A refspec 'src:dst' on fetch/pull writes the local ref 'dst'. Reject forced
    updates ('+...') and any refspec whose local destination is a ref other than
    the configured target branch, so a client cannot forge arbitrary local refs.
    """
    if refspec.startswith("+"):
        raise ValueError(
            f"Git is blocked because {context} with a forced-update refspec "
            "('+...') can overwrite local refs."
        )
    if ":" not in refspec:
        return
    _, dst = refspec.split(":", 1)
    if _local_ref_branch(dst) != target_branch:
        raise ValueError(
            f"Git is blocked because {context} may only update the "
            f"{target_branch} local branch, but the refspec targets {dst}."
        )


def _ensure_git_context_for_command(cwd: Path, git_args: list[str] | None = None) -> None:
    git_args = list(git_args or [])
    state, config, detected, lines = _repo_context_state(cwd, git_args)
    if state != "repo_present_bound_ok":
        raise ValueError("Git is blocked for this workspace.\n\n" + "\n".join(lines))
    if config is None:
        raise ValueError("Git is blocked because repo context data is unavailable.")

    git_prefix, subcommand, tail = _split_git_command(git_args)
    # Reject dangerous global prefix options before any subcommand-specific
    # policy runs: they can execute arbitrary programs or move git's cwd.
    _reject_unsafe_git_global_options(git_prefix)
    if not subcommand:
        raise ValueError("Git is blocked because the command could not be classified safely.")

    target_branch = _target_commit_branch(config)
    if not target_branch:
        raise ValueError(
            "Git is blocked because commit branch policy is not fully configured. "
            "Run setup_git_context(...) and choose default_branch or commit_branch explicitly."
        )
    current_branch = str(detected.get("branch", "")).strip()

    simple_read_only = {
        "status",
        "log",
        "show",
        "diff",
        "rev-parse",
        "describe",
        "ls-files",
        "ls-tree",
        "cat-file",
        "blame",
        "grep",
        "symbolic-ref",
    }
    if subcommand in simple_read_only:
        return

    if subcommand == "config":
        if _is_git_config_read_only(tail):
            return
        raise ValueError(
            "Git is blocked because mutating git config is not allowed through ordinary git commands. "
            "Use setup_git_context(...) or configure_repo_context(...) only with explicit user confirmation."
        )

    if subcommand == "remote":
        if _is_git_remote_read_only(tail):
            remote_target = _remote_read_only_target(tail)
            _ensure_remote_reference_allowed(remote_target, config, detected, context="this remote lookup")
            return
        raise ValueError(
            "Git is blocked because remote changes are not allowed through ordinary git commands. "
            "Use setup_git_context(...) with explicit confirmation instead."
        )

    if subcommand == "branch":
        if _is_git_branch_read_only(tail):
            return
        branch_target = _branch_target(tail)
        if branch_target and branch_target != target_branch:
            raise ValueError(
                f"Git is blocked because branch operations for this workspace must stay on {target_branch}, "
                f"but the command targets {branch_target}."
            )
        _require_current_branch_matches(current_branch, target_branch)
        return

    if subcommand == "checkout":
        branch_target = _checkout_target_branch(tail)
        if branch_target:
            if branch_target != target_branch:
                raise ValueError(
                    f"Git is blocked because checkout for this workspace must stay on {target_branch}, "
                    f"but the command targets {branch_target}."
                )
            return
        _require_current_branch_matches(current_branch, target_branch)
        return

    if subcommand == "switch":
        branch_target = _switch_target_branch(tail)
        if branch_target:
            if branch_target != target_branch:
                raise ValueError(
                    f"Git is blocked because switch for this workspace must stay on {target_branch}, "
                    f"but the command targets {branch_target}."
                )
            return
        _require_current_branch_matches(current_branch, target_branch)
        return

    if subcommand == "fetch":
        remote_target = _fetch_remote(tail)
        if remote_target == "__ALL__":
            for remote_name in sorted(detected.get("remotes", {})):
                _ensure_remote_reference_allowed(remote_name, config, detected, context="git fetch --all")
            return
        _ensure_remote_reference_allowed(remote_target, config, detected, context="git fetch")
        for refspec in _fetch_refspecs(tail):
            _ensure_transport_refspec_allowed(refspec, target_branch, context="git fetch")
        return

    if subcommand == "pull":
        _require_current_branch_matches(current_branch, target_branch)
        remote_target, branch_target = _pull_remote_and_branch(tail)
        _ensure_remote_reference_allowed(remote_target, config, detected, context="git pull")
        if branch_target:
            _ensure_transport_refspec_allowed(branch_target, target_branch, context="git pull")
            # A bare remote branch (no ':') must still be the configured target.
            if ":" not in branch_target and _local_ref_branch(branch_target) != target_branch:
                raise ValueError(
                    f"Git is blocked because pull for this workspace must stay on {target_branch}, "
                    f"but the command targets {branch_target}."
                )
        return

    if subcommand == "push":
        _require_current_branch_matches(current_branch, target_branch)
        blocked_mode = _blocked_push_mode(tail)
        if blocked_mode:
            raise ValueError(
                f"Git is blocked because git push {blocked_mode} can update or delete "
                "multiple refs outside the configured branch policy."
            )
        remote_target, refspecs = _push_remote_and_refspecs(tail)
        if not remote_target:
            remote_target = _effective_push_remote(
                cwd, current_branch, detected, git_args
            )
        if not remote_target:
            raise ValueError(
                "Git is blocked because the effective push remote could not be determined safely."
            )
        _ensure_remote_reference_allowed(remote_target, config, detected, context="git push")
        for refspec in refspecs:
            ref_target = _refspec_target_branch(refspec, current_branch)
            if ref_target != target_branch:
                raise ValueError(
                    f"Git is blocked because push for this workspace must stay on {target_branch}, "
                    f"but the command targets {ref_target}."
                )
        return

    if subcommand == "tag":
        if _is_git_tag_read_only(tail):
            return
        _require_current_branch_matches(current_branch, target_branch)
        return

    branch_bound_commands = {
        "add",
        "rm",
        "mv",
        "restore",
        "reset",
        "clean",
        "stash",
        "commit",
        "merge",
        "rebase",
        "cherry-pick",
        "revert",
        "am",
    }
    if subcommand in branch_bound_commands:
        _require_current_branch_matches(current_branch, target_branch)
        return

    raise ValueError(
        f"Git is blocked because the command '{subcommand}' is not yet explicitly classified by the repo policy."
    )


def _read_text_with_replace(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _slice_chunk(
    text: str,
    offset: int = 0,
    limit: int = 0,
    char_limit: int = CHUNK_CHAR_LIMIT,
    char_offset: int = 0,
) -> dict[str, object]:
    lines = text.splitlines(keepends=True)
    start = max(0, offset)
    start_char_offset = max(0, char_offset if start < len(lines) else 0)
    line_limit = max(1, min(limit or DEFAULT_READ_LINES, 2000))
    total = len(lines)

    if start >= total:
        return {
            "start": start,
            "end": start,
            "next_offset": start,
            "next_char_offset": 0,
            "total": total,
            "body": "(end of content)",
            "reason": None,
            "is_complete": True,
            "char_limit": char_limit,
            "line_fragment": False,
        }

    selected: list[str] = []
    selected_chars = 0
    stop_reason: str | None = None
    next_offset = start
    next_char_offset = start_char_offset
    line_fragment = False
    consumed_lines = 0

    for index in range(start, total):
        line = lines[index]
        current_char_offset = next_char_offset if index == start else 0
        remaining_line = line[current_char_offset:]

        if consumed_lines >= line_limit:
            stop_reason = "line limit"
            next_offset = index
            next_char_offset = 0
            break

        if selected_chars + len(remaining_line) > char_limit:
            stop_reason = "character limit"
            available = char_limit - selected_chars
            if available > 0:
                selected.append(remaining_line[:available])
                selected_chars += available
                next_offset = index
                next_char_offset = current_char_offset + available
                line_fragment = next_char_offset < len(line)
            else:
                next_offset = index
                next_char_offset = current_char_offset
            break

        selected.append(remaining_line)
        selected_chars += len(remaining_line)
        consumed_lines += 1
        next_offset = index + 1
        next_char_offset = 0
    else:
        next_offset = total
        next_char_offset = 0

    is_complete = next_offset >= total and next_char_offset == 0
    body = "".join(selected) or "(empty result)"

    return {
        "start": start,
        "end": start + consumed_lines,
        "next_offset": next_offset,
        "next_char_offset": next_char_offset,
        "total": total,
        "body": body,
        "reason": stop_reason,
        "is_complete": is_complete,
        "char_limit": char_limit,
        "line_fragment": line_fragment,
    }


def _render_chunk_text(chunk: dict[str, object], source_label: str) -> tuple[str, bool]:
    start = int(chunk["start"])
    end = int(chunk["end"])
    next_offset = int(chunk["next_offset"])
    next_char_offset = int(chunk["next_char_offset"])
    total = int(chunk["total"])
    body = str(chunk["body"])
    reason = chunk["reason"]
    is_complete = bool(chunk["is_complete"])

    char_suffix = f" | next char offset {next_char_offset}" if next_char_offset else ""
    header = f"[lines {start}–{end} of {total} | next offset {next_offset}{char_suffix}]"
    if next_offset < total or next_char_offset:
        continue_args = f"path={source_label!r}, offset={next_offset}"
        if next_char_offset:
            continue_args += f", char_offset={next_char_offset}"
        footer = (
            f"\n\n... [more content hidden. Stopped by {reason or 'character limit'}. "
            f"Call read_file({continue_args}) to continue.]"
        )
    else:
        footer = ""
    return header + "\n" + body + footer, is_complete


def _format_chunk_text(
    text: str,
    source_label: str,
    offset: int = 0,
    limit: int = 0,
    char_offset: int = 0,
) -> tuple[str, bool]:
    working_char_limit = CHUNK_CHAR_LIMIT

    while True:
        chunk = _slice_chunk(
            text,
            offset=offset,
            limit=limit,
            char_limit=working_char_limit,
            char_offset=char_offset,
        )
        rendered, is_complete = _render_chunk_text(chunk, source_label)
        overflow = len(rendered) - MAX_OUTPUT_CHARS
        if overflow <= 0:
            return rendered, is_complete
        reduced = max(1, working_char_limit - overflow)
        if reduced >= working_char_limit:
            return rendered, is_complete
        working_char_limit = reduced


def _save_long_output(prefix: str, text: str) -> str:
    output_path = _tool_output_path(prefix)
    _atomic_write_text(output_path, text)
    virtual_path = _temp_virtual_path(output_path)
    preview, _ = _format_chunk_text(text, virtual_path)
    return f"Full output saved to {virtual_path}\n\n{preview}"


def _direct_or_saved_output(prefix: str, text: str) -> str:
    if text is None:
        text = "(no output)"
    text = str(text)
    if text == "":
        text = "(empty result)"
    if len(text) > CHUNK_CHAR_LIMIT:
        return _save_long_output(prefix, text)
    return text


def _text_file(path: Path) -> None:
    if not path.exists():
        raise ValueError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Not a file: {path}")
    size = path.stat().st_size
    if size > MAX_TEXT_FILE:
        raise ValueError(f"File is too large ({size:,} bytes; limit {MAX_TEXT_FILE:,})")


def _atomic_write_text(path: Path, content: str) -> None:
    """Write via unique temp file + replace: crash-safe and safe for parallel calls."""
    fd, temp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=path.name + ".", suffix=".mcp-tmp"
    )
    try:
        # newline="" disables newline translation on write: existing line
        # endings in `content` are written byte-for-byte. Without it, Windows
        # text mode rewrites every LF to CRLF, turning an existing CRLF (read
        # verbatim by edit_file) into CR+CRLF and accumulating a stray CR on
        # every subsequent edit_file call on the same file.
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise


async def _kill_tree(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    if os.name == "nt":
        killer = await asyncio.create_subprocess_exec(
            "taskkill",
            "/T",
            "/F",
            "/PID",
            str(proc.pid),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await killer.wait()
    else:
        proc.kill()
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(proc.wait(), timeout=5)


@tool(scope=SCOPE_FILES_READ)
async def workspace_info() -> str:
    """Show the allowed workspace, active mode, and git repo-context status."""
    commands = ", ".join(sorted(ALLOWED_COMMANDS)) if ALLOW_COMMANDS else "disabled"
    mode = "trusted developer mode" if ALLOW_COMMANDS else "file-only mode"
    repo_overview = await asyncio.to_thread(_workspace_repo_overview, BASE_DIR)
    return (
        f"workspace: {BASE_DIR}\nmode: {mode}\ncommands: {commands}\n"
        f"max text file: {MAX_TEXT_FILE:,} bytes\n"
        f"repo context file: {REPO_CONTEXT_FILE}\n"
        f"{repo_overview}"
    )


@tool(scope=SCOPE_GIT)
async def repo_context_status(cwd: str = ".") -> str:
    """Show the current repo-context configuration, git detection, and next setup step."""
    workdir = _path(cwd)
    if not workdir.is_dir():
        raise ValueError(f"cwd is not a directory: {cwd}")
    return await asyncio.to_thread(_repo_context_summary, workdir)


@tool(scope=SCOPE_GIT)
async def inspect_git_repository(cwd: str = ".") -> str:
    """Inspect the git repository in this workspace without running any mutating git command."""
    workdir = _path(cwd)
    if not workdir.is_dir():
        raise ValueError(f"cwd is not a directory: {cwd}")
    return await asyncio.to_thread(_inspect_git_repository_text, workdir)


@tool(scope=SCOPE_GIT)
async def configure_repo_context(
    repository_url: str,
    is_fork: bool,
    upstream_url: str = "",
    default_branch: str = "",
    branch_mode: str = "default_branch",
    commit_branch: str = "",
    cwd: str = ".",
    confirm_defaults: bool = False,
    confirm_reconfigure: bool = False,
) -> str:
    """Low-level manual override for the local repo-context file. Prefer setup_git_context() for normal use."""
    workdir = _path(cwd)
    if not workdir.is_dir():
        raise ValueError(f"cwd is not a directory: {cwd}")
    try:
        existing = await asyncio.to_thread(_load_repo_context, workdir)
    except ValueError:
        existing = None
    detected = await asyncio.to_thread(_detect_git_repo, workdir)
    branch_mode = branch_mode.strip() or "default_branch"
    default_branch = default_branch.strip()
    defaults_used: list[str] = []
    if branch_mode == "specified_branch" and not commit_branch.strip():
        raise ValueError("commit_branch is required when branch_mode='specified_branch'")
    if branch_mode == "default_branch" and not default_branch:
        inferred_default_branch = str(detected["branch"] or "").strip()
        if not inferred_default_branch:
            raise ValueError("default_branch must be explicitly set when it cannot be inferred safely")
        default_branch = inferred_default_branch
        defaults_used.append(f"default_branch='{default_branch}'")
    _require_explicit_defaults(defaults_used, confirm_defaults)
    desired = _build_repo_context_desired(
        status="configured",
        repository_url=repository_url,
        is_fork=is_fork,
        upstream_url=upstream_url,
        default_branch=default_branch,
        branch_mode=branch_mode,
        commit_branch=commit_branch,
        git_enabled=True,
        disabled_reason="",
    )
    _require_repo_context_confirmation(existing, desired, confirm_reconfigure)
    config_path = await asyncio.to_thread(
        _save_repo_context,
        cwd=workdir,
        status="configured",
        repository_url=repository_url,
        is_fork=is_fork,
        upstream_url=upstream_url,
        default_branch=default_branch,
        branch_mode=branch_mode,
        commit_branch=commit_branch,
        git_enabled=True,
        disabled_reason="",
        last_detected_origin=str(detected["origin_url"]),
        last_detected_branch=str(detected["branch"] or default_branch),
    )
    summary = await asyncio.to_thread(_repo_context_summary, workdir)
    return f"Saved repo context to {config_path.relative_to(BASE_DIR)}\n\n{summary}"


@tool(scope=SCOPE_GIT)
async def setup_git_context(
    mode: str,
    repository_url: str = "",
    fork_status: str = "",
    upstream_url: str = "",
    cwd: str = ".",
    default_branch: str = "",
    branch_mode: str = "default_branch",
    commit_branch: str = "",
    disable_reason: str = "",
    force_origin_update: bool = False,
    set_upstream_remote: bool = False,
    confirm_defaults: bool = False,
    confirm_reconfigure: bool = False,
) -> str:
    """Safely initialize, bind, rebind, or disable git for this workspace before ordinary git commands are allowed."""
    workdir = _path(cwd)
    if not workdir.is_dir():
        raise ValueError(f"cwd is not a directory: {cwd}")
    return await asyncio.to_thread(
        _setup_git_context_sync,
        workdir,
        mode=mode,
        repository_url=repository_url,
        fork_status=fork_status,
        upstream_url=upstream_url,
        default_branch=default_branch,
        branch_mode=branch_mode,
        commit_branch=commit_branch,
        disable_reason=disable_reason,
        force_origin_update=force_origin_update,
        set_upstream_remote=set_upstream_remote,
        confirm_defaults=confirm_defaults,
        confirm_reconfigure=confirm_reconfigure,
    )


@tool(scope=SCOPE_FILES_READ)
async def list_dir(
    path: str = ".",
    recursive: bool = False,
    include_hidden: bool = False,
    max_results: int = 300,
) -> str:
    """List files inside the workspace. Large dependency/cache folders are skipped."""
    root = _path(path)
    limit = max(1, min(max_results, MAX_RESULTS))

    # Recursive os.walk + per-entry stat() is blocking I/O; run it off the event
    # loop so slow/large trees cannot stall every other in-flight request.
    def _list() -> str:
        if not root.is_dir():
            raise ValueError(f"Not a directory: {root}")
        rows: list[str] = []
        if not recursive:
            for item in sorted(root.iterdir(), key=lambda p: p.name.lower()):
                if should_skip(item, include_hidden, EXCLUDES):
                    continue
                kind = "DIR" if item.is_dir() else f"{item.stat().st_size:,} B"
                rows.append(f"{kind:>12}  {item.name}")
                if len(rows) >= limit:
                    break
        else:
            for current, dirs, files in os.walk(root):
                current_path = Path(current)
                dirs[:] = sorted(
                    d
                    for d in dirs
                    if not should_skip(current_path / d, include_hidden, EXCLUDES)
                )
                for name in sorted(files):
                    item = current_path / name
                    if should_skip(item, include_hidden, EXCLUDES):
                        continue
                    rows.append(str(item.relative_to(root)))
                    if len(rows) >= limit:
                        break
                if len(rows) >= limit:
                    break

        if not rows:
            return "Directory is empty."
        suffix = f"\n... limited to {limit} results" if len(rows) >= limit else ""
        return _direct_or_saved_output("list-dir", "\n".join(rows) + suffix)

    return await asyncio.to_thread(_list)


@tool(scope=SCOPE_FILES_READ)
async def file_info(path: str) -> str:
    """Show file or directory metadata."""
    item = _path(path)

    # exists()/stat() are blocking syscalls; keep them off the event loop.
    def _info() -> str:
        if not item.exists():
            return f"Not found: {path}"
        stat = item.stat()
        kind = "directory" if item.is_dir() else "file"
        modified = dt.datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds")
        return (
            f"path: {item.relative_to(BASE_DIR)}\ntype: {kind}\n"
            f"size: {stat.st_size:,}\nmodified: {modified}"
        )

    return await asyncio.to_thread(_info)


@tool(scope=SCOPE_FILES_READ)
async def read_file(path: str, offset: int = 0, limit: int = 0, char_offset: int = 0) -> str:
    """Read a text file in chunks with a character budget that takes priority over line count."""
    item, is_temp_file = _resolve_read_file_path(path)
    if not item.exists():
        raise ValueError(f"File not found: {item}")
    if not item.is_file():
        raise ValueError(f"Not a file: {item}")

    def _read() -> str:
        _text_file(item)
        with item.open("rb") as handle:
            if _is_binary_bytes(handle.read(8192)):
                label = path if is_temp_file else str(item.relative_to(BASE_DIR))
                return f"(binary file, not shown as text): {label} — {item.stat().st_size:,} bytes"
        text_content = _read_text_with_replace(item)
        rendered, is_complete = _format_chunk_text(
            text_content,
            path,
            offset=offset,
            limit=limit,
            char_offset=char_offset,
        )
        if is_temp_file and is_complete:
            with contextlib.suppress(OSError):
                item.unlink()
        return rendered

    return await asyncio.to_thread(_read)



@tool(scope=SCOPE_FILES_WRITE)
async def write_file(path: str, content: str, overwrite: bool = True) -> str:
    """Write a UTF-8 text file inside the workspace."""
    encoded_size = len(content.encode("utf-8"))
    if encoded_size > MAX_WRITE:
        raise ValueError(f"Content exceeds {MAX_WRITE:,} bytes")
    item = _path(path)
    _ensure_writable(item)
    if item.exists() and not overwrite:
        raise ValueError(f"File already exists: {path}")

    def _write() -> None:
        item.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_text(item, content)

    await asyncio.to_thread(_write)
    return f"Wrote {len(content):,} characters to {item.relative_to(BASE_DIR)}"


@tool(scope=SCOPE_FILES_WRITE)
async def append_file(path: str, content: str) -> str:
    """Append UTF-8 text while keeping the resulting file under the size limit."""
    encoded_size = len(content.encode("utf-8"))
    if encoded_size > MAX_WRITE:
        raise ValueError(f"Content exceeds {MAX_WRITE:,} bytes")
    item = _path(path)
    _ensure_writable(item)
    current_size = item.stat().st_size if item.exists() else 0
    if current_size + encoded_size > MAX_TEXT_FILE:
        raise ValueError(f"Resulting file would exceed {MAX_TEXT_FILE:,} bytes")

    def _append() -> None:
        item.parent.mkdir(parents=True, exist_ok=True)
        with item.open("a", encoding="utf-8", newline="") as handle:
            handle.write(content)

    await asyncio.to_thread(_append)
    return f"Appended {len(content):,} characters to {item.relative_to(BASE_DIR)}"


@tool(scope=SCOPE_FILES_WRITE)
async def edit_file(
    path: str,
    old_string: str,
    new_string: str,
    replace_all: bool = False,
) -> str:
    """Replace exact text in a UTF-8 file. Read the file first."""
    item = _path(path)
    _ensure_writable(item)
    _text_file(item)

    def _edit() -> int:
        data = item.read_bytes()
        if _is_binary_bytes(data):
            raise ValueError(f"Refusing to edit binary file: {item.relative_to(BASE_DIR)}")
        text_content = data.decode("utf-8", errors="replace")
        found = text_content.count(old_string)
        if found == 0:
            raise ValueError("old_string was not found")
        if not replace_all and found > 1:
            raise ValueError(
                f"old_string occurs {found} times; use a larger match or replace_all"
            )
        count = found if replace_all else 1
        updated = (
            text_content.replace(old_string, new_string)
            if replace_all
            else text_content.replace(old_string, new_string, 1)
        )
        if len(updated.encode("utf-8")) > MAX_TEXT_FILE:
            raise ValueError("Updated file would exceed the size limit")
        _atomic_write_text(item, updated)
        return count

    count = await asyncio.to_thread(_edit)
    return f"Replaced {count} occurrence(s) in {item.relative_to(BASE_DIR)}"


@tool(scope=SCOPE_FILES_WRITE)
async def create_dir(path: str) -> str:
    """Create a directory and missing parents. Existing directories are accepted."""
    item = _path(path)
    _ensure_writable(item)
    await asyncio.to_thread(item.mkdir, parents=True, exist_ok=True)
    return f"Directory ready: {item.relative_to(BASE_DIR)}"


@tool(scope=SCOPE_FILES_WRITE)
async def delete_file(path: str) -> str:
    """Delete one file or one empty directory. Recursive deletion is unavailable."""
    item = _path(path)
    _ensure_writable(item)
    if not item.exists():
        return f"Not found: {path}"
    if item.is_dir():
        await asyncio.to_thread(item.rmdir)
    else:
        await asyncio.to_thread(item.unlink)
    return f"Deleted: {item.relative_to(BASE_DIR)}"


def _ensure_copy_move_size(source: Path) -> None:
    """Reject a copy/move whose source exceeds MAX_COPY_MOVE_BYTES.

    A client holding mcp:files:write could otherwise exhaust disk by
    duplicating a multi-GB artifact. Runs AFTER the _ensure_writable
    trust-anchor guard, never instead of it. Override the cap with the
    MCP_MAX_COPY_MOVE_BYTES environment variable.
    """
    size = source.stat().st_size
    if size > MAX_COPY_MOVE_BYTES:
        raise ValueError(
            f"Source exceeds the copy/move size limit: {size} bytes > "
            f"{MAX_COPY_MOVE_BYTES} bytes "
            "(raise MCP_MAX_COPY_MOVE_BYTES to allow larger files)."
        )


@tool(scope=SCOPE_FILES_WRITE)
async def copy_file(src: str, dst: str, overwrite: bool = False) -> str:
    """Copy one file inside the workspace."""
    source, target = _path(src), _path(dst)
    _ensure_writable(target)
    if not source.is_file():
        raise ValueError(f"Source is not a file: {src}")
    _ensure_copy_move_size(source)
    if target.exists() and not overwrite:
        raise ValueError(f"Destination exists: {dst}")
    target.parent.mkdir(parents=True, exist_ok=True)
    await asyncio.to_thread(shutil.copy2, source, target)
    return f"Copied {source.relative_to(BASE_DIR)} -> {target.relative_to(BASE_DIR)}"


@tool(scope=SCOPE_FILES_WRITE)
async def move_file(src: str, dst: str, overwrite: bool = False) -> str:
    """Move or rename one file inside the workspace."""
    source, target = _path(src), _path(dst)
    # Guard both ends: moving the anchor away removes it; moving onto it forges it.
    _ensure_writable(source)
    _ensure_writable(target)
    if not source.is_file():
        raise ValueError(f"Source is not a file: {src}")
    _ensure_copy_move_size(source)
    if target.exists() and not overwrite:
        raise ValueError(f"Destination exists: {dst}")
    target.parent.mkdir(parents=True, exist_ok=True)
    await asyncio.to_thread(shutil.move, str(source), str(target))
    return f"Moved {source.relative_to(BASE_DIR)} -> {target.relative_to(BASE_DIR)}"


@tool(scope=SCOPE_FILES_READ)
async def glob_files(pattern: str, path: str = ".", max_results: int = 300) -> str:
    """Find workspace files using a glob such as **/*.py."""
    root = _path(path)
    limit = max(1, min(max_results, MAX_RESULTS))

    # Glob expansion walks the filesystem and stat()s each match; run it in a
    # worker thread so it does not block the event loop like grep_files does.
    def _glob() -> str:
        rows: list[str] = []
        for item in root.glob(pattern):
            if not item.is_file() or any(part in EXCLUDES for part in item.parts):
                continue
            safe_path(BASE_DIR, item)
            rows.append(str(item.relative_to(root)))
            if len(rows) >= limit:
                break
        return "\n".join(sorted(rows)) if rows else "No files matched."

    return await asyncio.to_thread(_glob)


@tool(scope=SCOPE_FILES_READ)
async def grep_files(
    pattern: str,
    path: str = ".",
    file_glob: str = "*",
    regex: bool = False,
    max_results: int = 100,
) -> str:
    """Search text files with bounded output. Regex mode is disabled for safety."""
    if regex:
        raise ValueError("Regex mode is disabled to prevent pathological expressions")
    root = _path(path)
    limit = max(1, min(max_results, 500))

    def _grep() -> str:
        rows: list[str] = []
        for current, dirs, files in os.walk(root):
            current_path = Path(current)
            dirs[:] = [d for d in dirs if d not in EXCLUDES and not d.startswith(".")]
            for name in files:
                if not fnmatch.fnmatch(name, file_glob):
                    continue
                item = current_path / name
                try:
                    if item.stat().st_size > MAX_TEXT_FILE:
                        continue
                    for number, line in enumerate(
                        item.read_text(encoding="utf-8", errors="ignore").splitlines(), 1
                    ):
                        if pattern.lower() in line.lower():
                            rows.append(
                                f"{item.relative_to(root)}:{number}: {line.rstrip()}"
                            )
                            if len(rows) >= limit:
                                rows.append(f"... limited to {limit} results")
                                return _direct_or_saved_output("grep-files", "\n".join(rows))
                except (OSError, UnicodeError):
                    continue
        result = "\n".join(rows) if rows else "No matches found."
        return _direct_or_saved_output("grep-files", result)

    return await asyncio.to_thread(_grep)


async def _capture_process_to_files(
    proc: asyncio.subprocess.Process,
    stdout_path: Path,
    stderr_path: Path,
    timeout: int,
) -> tuple[bool, bool]:
    total = 0
    limit_reached = asyncio.Event()

    async def consume(stream: asyncio.StreamReader, target_path: Path) -> None:
        nonlocal total
        with target_path.open("wb") as handle:
            while True:
                chunk = await stream.read(8192)
                if not chunk:
                    handle.flush()
                    os.fsync(handle.fileno())
                    return
                remaining = MAX_COMMAND_OUTPUT - total
                if remaining <= 0:
                    limit_reached.set()
                    continue
                accepted = chunk[:remaining]
                handle.write(accepted)
                total += len(accepted)
                if len(accepted) < len(chunk):
                    limit_reached.set()

    async def finish() -> None:
        assert proc.stdout is not None and proc.stderr is not None
        await asyncio.gather(
            consume(proc.stdout, stdout_path),
            consume(proc.stderr, stderr_path),
            proc.wait(),
        )

    run_task = asyncio.create_task(finish())
    limit_task = asyncio.create_task(limit_reached.wait())
    done, _ = await asyncio.wait(
        {run_task, limit_task}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED
    )

    timed_out = False
    truncated = False
    if run_task in done:
        await run_task
        truncated = limit_task in done and limit_reached.is_set()
    elif limit_task in done:
        truncated = True
        await _kill_tree(proc)
        await run_task
    else:
        timed_out = True
        await _kill_tree(proc)
        await run_task

    limit_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await limit_task
    return timed_out, truncated


async def _prepare_command(
    program: str, args: list[str] | None, cwd: str
) -> tuple[str, Path]:
    """Shared validation for run_command / start_command: enforce trusted mode,
    resolve the program against the allowlist, validate cwd, and apply the git
    context guard. Both the synchronous and background command paths MUST go
    through this so their security posture can never drift apart."""
    if not ALLOW_COMMANDS:
        raise ValueError(
            "Command execution is disabled. Re-run SETUP.bat to enable trusted developer mode."
        )
    executable = resolve_program(BASE_DIR, program, ALLOWED_COMMANDS)
    workdir = _path(cwd)
    if not workdir.is_dir():
        raise ValueError(f"cwd is not a directory: {cwd}")
    if normalized_program_name(program) == "git":
        await asyncio.to_thread(_ensure_git_context_for_command, workdir, list(args or []))
    return executable, workdir


async def _spawn_process(
    executable: str, args: list[str] | None, workdir: Path
) -> asyncio.subprocess.Process:
    flags = 0x00000200 if os.name == "nt" else 0
    return await asyncio.create_subprocess_exec(
        executable,
        *(args or []),
        cwd=str(workdir),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        creationflags=flags,
        env=_sanitized_env(),
    )


def _format_command_result(
    returncode: int | None,
    stdout_text: str,
    stderr_text: str,
    timed_out: bool,
    truncated: bool,
    seconds: int,
) -> str:
    stdout_text = stdout_text if stdout_text != "" else "(empty result)"
    stderr_text = stderr_text if stderr_text != "" else "(empty result)"
    prefix_parts: list[str] = []
    if timed_out:
        prefix_parts.append(f"Timed out after {seconds}s (process tree stopped).")
    if truncated:
        prefix_parts.append(
            f"Output truncated after reaching the safe combined limit of {MAX_COMMAND_OUTPUT:,} bytes."
        )
    prefix = "\n".join(prefix_parts)
    if prefix:
        prefix += "\n"
    return (
        prefix
        + f"exit code: {returncode}\n"
        + f"--- stdout ---\n{stdout_text}\n"
        + f"--- stderr ---\n{stderr_text}"
    )


@tool(scope=SCOPE_COMMANDS_RUN)
async def run_command(
    program: str,
    args: list[str] | None = None,
    cwd: str = ".",
    timeout: int = 60,
) -> str:
    """Trusted developer mode: run an allow-listed program without a shell.

    Short output is returned directly. Long output is saved to a file and returned
    through the same chunked reading model as read_file().
    """
    executable, workdir = await _prepare_command(program, args, cwd)

    seconds = max(1, min(timeout, 300))

    stdout_capture = _tool_output_path("run-command-stdout")
    stderr_capture = _tool_output_path("run-command-stderr")

    try:
        proc = await _spawn_process(executable, args, workdir)
        timed_out, truncated = await _capture_process_to_files(
            proc,
            stdout_capture,
            stderr_capture,
            seconds,
        )

        stdout_text = await asyncio.to_thread(_read_text_with_replace, stdout_capture)
        stderr_text = await asyncio.to_thread(_read_text_with_replace, stderr_capture)

        result = _format_command_result(
            proc.returncode, stdout_text, stderr_text, timed_out, truncated, seconds
        )
        return _direct_or_saved_output("run-command", result)
    finally:
        with contextlib.suppress(OSError):
            stdout_capture.unlink()
        with contextlib.suppress(OSError):
            stderr_capture.unlink()


# --------------------------------------------------------------------------
# Background command jobs (v2.2)
#
# start_command runs an allow-listed program in the background and returns a
# job_id immediately, so a client can poll get_command_status instead of
# holding one long HTTP request open (the free Serveo tunnel caps a single
# request at ~20-30s) and can run several commands truly in parallel. All the
# heavy lifting -- streamed capture with the MAX_COMMAND_OUTPUT limit, the
# timeout-vs-limit race, and the process-tree kill -- is reused from
# run_command's primitives; this layer is only bookkeeping (registry, limits,
# pruning, shutdown cleanup).
# --------------------------------------------------------------------------

MAX_CONCURRENT_JOBS = max(1, int(os.environ.get("MCP_MAX_COMMAND_JOBS", "4") or "4"))
MAX_TRACKED_JOBS = 50
JOB_RETENTION_SECONDS = 600

_TERMINAL_JOB_STATES = {"done", "timeout", "cancelled", "error"}


@dataclass
class CommandJob:
    job_id: str
    program: str
    args: list[str]
    cwd: str
    executable: str
    workdir: str
    seconds: int
    stdout_path: Path
    stderr_path: Path
    created_at: float
    finished_at: float | None = None
    status: Literal["running", "done", "timeout", "cancelled", "error"] = "running"
    exit_code: int | None = None
    timed_out: bool = False
    truncated: bool = False
    error: str | None = None
    proc: asyncio.subprocess.Process | None = None
    task: asyncio.Task | None = None


_JOBS: dict[str, CommandJob] = {}


def _now() -> float:
    return dt.datetime.now().timestamp()


def _job_elapsed(job: CommandJob) -> float:
    end = job.finished_at if job.finished_at is not None else _now()
    return max(0.0, end - job.created_at)


def _delete_job_files(job: CommandJob) -> None:
    for path in (job.stdout_path, job.stderr_path):
        with contextlib.suppress(OSError):
            path.unlink()


def _prune_jobs() -> None:
    """Opportunistic pruning (mirrors _cleanup_temp_files): drop finished jobs
    past their retention window, then enforce a hard cap on the number of
    tracked finished jobs (oldest first) so a burst cannot grow the registry
    without bound even before TTL expiry."""
    cutoff = _now() - JOB_RETENTION_SECONDS
    expired = [
        job_id
        for job_id, job in _JOBS.items()
        if job.status in _TERMINAL_JOB_STATES
        and job.finished_at is not None
        and job.finished_at < cutoff
    ]
    for job_id in expired:
        _delete_job_files(_JOBS.pop(job_id))

    finished = [job for job in _JOBS.values() if job.status in _TERMINAL_JOB_STATES]
    if len(finished) > MAX_TRACKED_JOBS:
        finished.sort(key=lambda job: job.finished_at or 0.0)
        for job in finished[: len(finished) - MAX_TRACKED_JOBS]:
            popped = _JOBS.pop(job.job_id, None)
            if popped is not None:
                _delete_job_files(popped)


def _running_job_count() -> int:
    return sum(1 for job in _JOBS.values() if job.status == "running")


async def _run_job(job: CommandJob) -> None:
    """Background driver: reuses _capture_process_to_files exactly as run_command
    does, then records the terminal state. Capture files are kept for later
    retrieval and cleaned up by _prune_jobs, not here."""
    try:
        proc = await _spawn_process(job.executable, job.args, Path(job.workdir))
        job.proc = proc
        timed_out, truncated = await _capture_process_to_files(
            proc, job.stdout_path, job.stderr_path, job.seconds
        )
        job.timed_out = timed_out
        job.truncated = truncated
        job.exit_code = proc.returncode
        if job.status == "cancelled":
            pass
        elif timed_out:
            job.status = "timeout"
        else:
            job.status = "done"
    except asyncio.CancelledError:
        job.status = "cancelled"
        raise
    except Exception as exc:
        job.status = "error"
        job.error = f"{type(exc).__name__}: {exc}"
    finally:
        if job.finished_at is None:
            job.finished_at = _now()


@tool(scope=SCOPE_COMMANDS_RUN)
async def start_command(
    program: str,
    args: list[str] | None = None,
    cwd: str = ".",
    timeout: int = 300,
) -> str:
    """Start an allow-listed program in the background and return a job id.

    Same trusted-developer restrictions as run_command (allowlist, cwd check,
    git-context guard). Use this for commands that may outlive a single tunnel
    request, or to run several commands in parallel, then poll
    get_command_status(job_id=...) to collect the result.
    """
    executable, workdir = await _prepare_command(program, args, cwd)
    _prune_jobs()
    running = _running_job_count()
    if running >= MAX_CONCURRENT_JOBS:
        raise ValueError(
            f"Too many background commands running ({running}/{MAX_CONCURRENT_JOBS}). "
            "Wait for one to finish or raise MCP_MAX_COMMAND_JOBS."
        )
    seconds = max(1, min(timeout, 300))
    job_id = secrets.token_urlsafe(9)
    job = CommandJob(
        job_id=job_id,
        program=program,
        args=list(args or []),
        cwd=cwd,
        executable=executable,
        workdir=str(workdir),
        seconds=seconds,
        stdout_path=_tool_output_path(f"job-{job_id}-stdout"),
        stderr_path=_tool_output_path(f"job-{job_id}-stderr"),
        created_at=_now(),
    )
    _JOBS[job_id] = job
    job.task = asyncio.create_task(_run_job(job))
    command = f"{program} {' '.join(job.args)}".rstrip()
    return (
        f"Started job {job_id}: {command}\n"
        f'Poll get_command_status(job_id="{job_id}") for progress and the result.'
    )


@tool(scope=SCOPE_COMMANDS_RUN)
async def get_command_status(job_id: str) -> str:
    """Return the status, and the final output once finished, of a background job."""
    _prune_jobs()
    job = _JOBS.get(job_id)
    if job is None:
        raise ValueError(
            f"No background job {job_id!r} (unknown, or expired after "
            f"{JOB_RETENTION_SECONDS}s). Use list_commands to see tracked jobs."
        )
    command = f"{job.program} {' '.join(job.args)}".rstrip()
    if job.status == "running":
        stdout_preview = await asyncio.to_thread(_read_text_with_replace, job.stdout_path)
        stderr_preview = await asyncio.to_thread(_read_text_with_replace, job.stderr_path)
        note = "(partial; output is buffered and may lag until the command finishes)"
        body = (
            f"job {job.job_id}: running ({_job_elapsed(job):.1f}s elapsed, "
            f"timeout {job.seconds}s)\n"
            f"command: {command}\n"
            f"--- stdout so far {note} ---\n"
            f"{stdout_preview if stdout_preview else '(empty result)'}\n"
            f"--- stderr so far {note} ---\n"
            f"{stderr_preview if stderr_preview else '(empty result)'}"
        )
        return _direct_or_saved_output("get-command-status", body)
    if job.status == "cancelled":
        return f"job {job.job_id}: cancelled after {_job_elapsed(job):.1f}s ({command})."
    if job.status == "error":
        return (
            f"job {job.job_id}: error after {_job_elapsed(job):.1f}s ({command})\n"
            f"{job.error or 'unknown error'}"
        )
    stdout_text = await asyncio.to_thread(_read_text_with_replace, job.stdout_path)
    stderr_text = await asyncio.to_thread(_read_text_with_replace, job.stderr_path)
    result = _format_command_result(
        job.exit_code, stdout_text, stderr_text, job.timed_out, job.truncated, job.seconds
    )
    header = f"job {job.job_id}: {job.status} ({_job_elapsed(job):.1f}s)\n"
    return _direct_or_saved_output("get-command-status", header + result)


@tool(scope=SCOPE_COMMANDS_RUN)
async def cancel_command(job_id: str) -> str:
    """Kill a running background job's process tree and mark it cancelled."""
    _prune_jobs()
    job = _JOBS.get(job_id)
    if job is None:
        raise ValueError(f"No background job {job_id!r}.")
    if job.status != "running":
        return f"job {job.job_id}: already {job.status}; nothing to cancel."
    job.status = "cancelled"
    if job.finished_at is None:
        job.finished_at = _now()
    if job.proc is not None:
        with contextlib.suppress(Exception):
            await _kill_tree(job.proc)
    return f"job {job.job_id}: cancelled."


@tool(scope=SCOPE_COMMANDS_RUN)
async def list_commands() -> str:
    """List tracked background command jobs (id, status, elapsed, command)."""
    _prune_jobs()
    if not _JOBS:
        return "No background command jobs."
    lines = [f"{'JOB_ID':<14} {'STATUS':<10} {'ELAPSED':>9}  COMMAND"]
    for job in sorted(_JOBS.values(), key=lambda item: item.created_at):
        command = f"{job.program} {' '.join(job.args)}".rstrip()
        lines.append(
            f"{job.job_id:<14} {job.status:<10} {_job_elapsed(job):>8.1f}s  {command}"
        )
    return _direct_or_saved_output("list-commands", "\n".join(lines))


def _install_shutdown_hook(app) -> None:
    """Cancel background jobs on graceful shutdown by composing our cleanup
    around the app's existing lifespan. Starlette 1.x removed add_event_handler
    and on_event, and FastMCP's streamable_http_app already installs its own
    lifespan, so we wrap that instead of replacing it."""
    base_lifespan = app.router.lifespan_context

    @contextlib.asynccontextmanager
    async def _lifespan(scope_app):
        async with base_lifespan(scope_app) as maybe_state:
            try:
                yield maybe_state
            finally:
                await _shutdown_running_jobs()

    app.router.lifespan_context = _lifespan


async def _shutdown_running_jobs() -> None:
    """On graceful shutdown, kill any still-running background jobs so their child
    process trees do not outlive the server. On Windows a child process is not
    terminated automatically when its parent exits, so without this a long job
    could be orphaned when the server is stopped."""
    for job in list(_JOBS.values()):
        if job.status == "running":
            job.status = "cancelled"
            if job.finished_at is None:
                job.finished_at = _now()
            if job.proc is not None:
                with contextlib.suppress(Exception):
                    await _kill_tree(job.proc)


def _extract_token(request) -> str:
    auth = request.headers.get("authorization", "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.headers.get("x-api-key", "").strip()


def _host_allowed(host_header: str) -> bool:
    host = host_header.split(":", 1)[0].strip().lower()
    if host in {"127.0.0.1", "localhost"}:
        return True
    # A configured public host (Serveo reserved, a custom reverse proxy, or a
    # self-hosted sish domain) is always allowed so Bearer/legacy clients work
    # behind it too, not only OAuth clients.
    if PUBLIC_HOST and host == PUBLIC_HOST:
        return True
    if STABLE_HOSTNAME:
        return host == f"{STABLE_HOSTNAME}{SERVEO_SUFFIX}"
    return host.endswith(SERVEO_SUFFIX)


class SecurityMiddleware(BaseHTTPMiddleware):
    """Legacy-mode gate: host allowlist + static master token on every route."""

    async def dispatch(self, request, call_next):
        if not _host_allowed(request.headers.get("host", "")):
            return JSONResponse({"error": "forbidden host"}, status_code=403)
        incoming = _extract_token(request)
        if not incoming or not _consteq(incoming, TOKEN):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if request.url.path == "/health":
            return JSONResponse({"status": "ok"})
        return await call_next(request)


class HostCheckMiddleware(BaseHTTPMiddleware):
    """OAuth-mode gate: host allowlist only; auth is enforced per route.

    The SDK's RequireAuthMiddleware protects /mcp, the OAuth endpoints are
    public by design, and /health validates the operator token itself.
    """

    async def dispatch(self, request, call_next):
        if not _host_allowed(request.headers.get("host", "")):
            return JSONResponse({"error": "forbidden host"}, status_code=403)
        return await call_next(request)


class XApiKeyCompatMiddleware:
    """dual mode: let legacy clients send the master token via X-API-Key.

    The SDK BearerAuthBackend reads only the Authorization header, so the
    X-API-Key value is mirrored into it when Authorization is absent.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = list(scope.get("headers", []))
            has_auth = any(name == b"authorization" for name, _ in headers)
            api_key = next(
                (value for name, value in headers if name == b"x-api-key"), b""
            )
            if not has_auth and api_key:
                headers.append((b"authorization", b"Bearer " + api_key))
                scope = dict(scope)
                scope["headers"] = headers
        await self.app(scope, receive, send)


_AUTHORIZE_HINT_STYLE = """
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
         max-width: 34rem; margin: 8vh auto; padding: 0 1.25rem; line-height: 1.5; }
  h1 { font-size: 1.25rem; }
  .card { border: 1px solid rgba(128,128,128,.35); border-radius: 10px;
          padding: 1.25rem 1.5rem; }
  ol { padding-left: 1.2rem; }
  li { margin: .35rem 0; }
  code { background: rgba(128,128,128,.15); padding: .1rem .3rem; border-radius: 4px; }
  .muted { opacity: .65; font-size: .85rem; }
"""


def _authorize_hint_html() -> str:
    """HTML shown when GET /authorize arrives without the required OAuth query
    parameters. The usual cause is the Serveo free-tier interstitial ("you are
    about to visit...") swallowing the query string on the very first hit of a
    browser session; the SDK would otherwise answer with a raw JSON 400
    (client_id / response_type / code_challenge: Field required) that reads like
    a broken server mid-Connect."""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Finish connecting &mdash; {SERVER_NAME}</title>
<style>{_AUTHORIZE_HINT_STYLE}</style></head>
<body><div class="card">
<h1>Almost there &mdash; one more step</h1>
<p>This authorization link opened <strong>without its parameters</strong>, so
sign-in can't continue yet. This is expected on the <strong>first</strong>
visit through a free Serveo tunnel: Serveo shows a one-time
&ldquo;you are about to visit&rdquo; page and drops the query string from the
link.</p>
<p><strong>How to finish:</strong></p>
<ol>
  <li>Press your browser&rsquo;s <strong>Back</strong> button, then open the
  authorization link again &mdash; the Serveo page is now cleared for this
  browser session and the real consent screen will load.</li>
  <li>Or simply start <em>Connect</em> again from your MCP client.</li>
</ol>
<p class="muted">To avoid this step entirely, run the server behind your own
domain / reverse proxy (set a custom public URL via OAUTH_SETUP.bat) or use a
paid Serveo account with a reserved hostname &mdash; neither shows the
interstitial. This page appears only when the authorization request is missing
required parameters; a normal request is never interrupted.</p>
</div></body></html>"""


class AuthorizeHintMiddleware(BaseHTTPMiddleware):
    """Turn the SDK's raw JSON 400 on a parameter-less /authorize into a
    friendly HTML page.

    Serveo's free-tier interstitial can strip the query string on the first
    GET /authorize of a browser session, so the SDK sees no OAuth parameters
    and replies with ``{"error":"invalid_request", ... Field required}``. That
    reads like a broken server in the middle of Connect. When any required
    OAuth parameter is absent we return an explanatory HTML page instead. The
    match is deliberately narrow -- method GET, path exactly ``/authorize``,
    and at least one required parameter missing -- so a well-formed
    authorization request (which always carries all three) is passed straight
    through to the SDK handler untouched."""

    _REQUIRED_PARAMS = ("client_id", "response_type", "code_challenge")

    async def dispatch(self, request, call_next):
        if request.method == "GET" and request.url.path == "/authorize":
            if any(
                not request.query_params.get(name) for name in self._REQUIRED_PARAMS
            ):
                response = HTMLResponse(_authorize_hint_html(), status_code=400)
                response.headers["Cache-Control"] = "no-store"
                response.headers["X-Content-Type-Options"] = "nosniff"
                response.headers["X-Frame-Options"] = "DENY"
                return response
        return await call_next(request)


def _presented_client_secret(request, form, client_id: str, auth_method: str) -> str | None:
    """Extract the client_secret a /token request presents, mirroring exactly how
    the SDK's ClientAuthenticator reads it for each registered auth method
    (RFC 6749 2.3.1 Basic header, or the client_secret_post form field)."""
    if auth_method == "client_secret_basic":
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Basic "):
            return None
        try:
            decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
        except (ValueError, UnicodeDecodeError, binascii.Error):
            return None
        if ":" not in decoded:
            return None
        basic_client_id, secret = decoded.split(":", 1)
        # URL-decode both parts per RFC 6749 Section 2.3.1.
        if unquote(basic_client_id) != client_id:
            return None
        return unquote(secret)
    if auth_method == "client_secret_post":
        raw = form.get("client_secret")
        return raw if isinstance(raw, str) else None
    return None


class ClientSecretAuthMiddleware(BaseHTTPMiddleware):
    """Enforce confidential-client secret authentication on POST /token.

    Client secrets are persisted only as SHA-256 hashes (auth/oauth.py), so the
    SDK's own ClientAuthenticator — which compares the presented secret against
    whatever get_client() returns — can no longer verify them; get_client
    deliberately returns client_secret=None so that comparison is always
    skipped. This middleware is therefore the sole real enforcer: it looks up
    the client's stored secret hash, hashes the presented secret the same way,
    and compares them in constant time.

    A public client (no stored secret) is passed straight through untouched, so
    the SDK's own none/secret_post/basic logic runs unmodified for it. A
    confidential client presenting a wrong or missing secret is rejected here
    with an invalid_client error and never reaches the SDK handler (so the
    authorization code / refresh token it targeted is left unconsumed)."""

    async def dispatch(self, request, call_next):
        if request.method != "POST" or request.url.path != TOKEN_PATH:
            return await call_next(request)
        assert oauth_provider is not None
        try:
            # Buffer the raw body first so Starlette caches it on the request;
            # otherwise reading the urlencoded form here consumes the ASGI
            # receive stream and the downstream SDK TokenHandler would see an
            # empty body ("Missing client_id"). With _body cached, the
            # BaseHTTPMiddleware replays the full body to the SDK handler.
            await request.body()
            form = await request.form()
        except Exception:
            # Malformed body: let the SDK produce its own error response.
            return await call_next(request)
        client_id = form.get("client_id")
        if not isinstance(client_id, str) or not client_id:
            return await call_next(request)
        stored = oauth_provider.store.clients.get(client_id)
        secret_hash = stored.get("client_secret") if isinstance(stored, dict) else None
        if not secret_hash:
            # Public/unknown client: nothing to enforce here.
            return await call_next(request)
        auth_method = str(stored.get("token_endpoint_auth_method") or "")
        presented = _presented_client_secret(request, form, client_id, auth_method)
        if not presented or not _consteq(hash_client_secret(presented), secret_hash):
            return JSONResponse(
                {
                    "error": "invalid_client",
                    "error_description": "client authentication failed",
                },
                status_code=401,
            )
        return await call_next(request)


if OAUTH_ENABLED:
    assert oauth_provider is not None
    _consent_handler = ConsentHandler(
        provider=oauth_provider,
        owner_code=OWNER_CODE,
        server_name=SERVER_NAME,
        server_version=SERVER_VERSION,
        max_attempts_per_txn=OAUTH_CONSENT_MAX_ATTEMPTS,
        failure_window_seconds=OAUTH_CONSENT_FAILURE_WINDOW,
        max_failures_per_window=OAUTH_CONSENT_MAX_FAILURES,
    )

    @mcp.custom_route("/consent", methods=["GET", "POST"])
    async def consent_route(request):
        return await _consent_handler.handle(request)

    @mcp.custom_route("/health", methods=["GET"])
    async def health_route(request):
        # Operator endpoint for the launcher: accepts the master token in
        # every mode, even when /mcp itself is OAuth-only.
        incoming = _extract_token(request)
        if not incoming or not _consteq(incoming, TOKEN):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return JSONResponse({"status": "ok"})

    @mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET", "OPTIONS"])
    async def protected_resource_alias(request):
        # Path-aware metadata (RFC 9728) is served by the SDK at
        # /.well-known/oauth-protected-resource/mcp; this root alias keeps
        # clients that still probe the older location working.
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "mcp-protocol-version",
        }
        if request.method == "OPTIONS":
            return JSONResponse(None, status_code=204, headers=headers)
        return JSONResponse(protected_resource_document(PUBLIC_URL), headers=headers)


def _configure_logging() -> None:
    """Quiet per-request streamable-HTTP session chatter.

    Each MCP call logs an INFO line from this logger; at steady state it floods
    server.log with no diagnostic value. uvicorn.access is deliberately left
    alone -- its GET /mcp 200 OK lines are how we spot transport drops.
    """
    logging.getLogger("mcp.server.streamable_http").setLevel(logging.WARNING)


if __name__ == "__main__":
    import uvicorn

    _cleanup_temp_files()
    _cleanup_orphan_mcp_tmp()
    app = mcp.streamable_http_app()
    _install_shutdown_hook(app)
    if AUTH_MODE == AUTH_MODE_LEGACY:
        app.add_middleware(SecurityMiddleware)
    else:
        if AUTH_MODE == AUTH_MODE_DUAL:
            app.add_middleware(XApiKeyCompatMiddleware)
        # Added before HostCheckMiddleware so host validation stays outermost;
        # this only rewrites the SDK's raw 400 on a parameter-less /authorize.
        app.add_middleware(AuthorizeHintMiddleware)
        # Enforce confidential-client secrets on /token, since secrets are stored
        # only as hashes and the SDK's own comparison can no longer verify them.
        # Applies in oauth and dual modes (both expose the SDK's /token route).
        app.add_middleware(ClientSecretAuthMiddleware)
        app.add_middleware(HostCheckMiddleware)
    print(f"{SERVER_NAME} {SERVER_VERSION}: http://127.0.0.1:{PORT}/mcp")
    print(f"Workspace: {BASE_DIR}")
    print(f"Commands: {'trusted developer mode' if ALLOW_COMMANDS else 'file-only mode'}")
    print(f"Auth mode: {AUTH_MODE}")
    if OAUTH_ENABLED:
        print(f"OAuth issuer: {PUBLIC_URL}")
        print(f"OAuth resource: {resource_url_for(PUBLIC_URL)}")
        print(
            "OAuth discovery: "
            f"{PUBLIC_URL}/.well-known/oauth-authorization-server | "
            f"{PUBLIC_URL}/.well-known/oauth-protected-resource/mcp"
        )
    _configure_logging()
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="info")
