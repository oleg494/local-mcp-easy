from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import fnmatch
import functools
import hmac
import json
import os
import re
import shutil
import subprocess
import tempfile
from itertools import islice
from pathlib import Path
from urllib.parse import urlsplit

from core import (
    DEFAULT_ALLOWED_COMMANDS,
    DEFAULT_EXCLUDES,
    normalized_program_name,
    resolve_program,
    safe_path,
    should_skip,
)
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

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
MAX_COMMAND_OUTPUT = 200_000
MAX_RESULTS = 1000
MAX_OUTPUT_CHARS = 10_000
DEFAULT_READ_LINES = 400
CHUNK_CHAR_LIMIT = 9_500
TEMP_DIRNAME = "temp"
TEMP_PATH_PREFIX = "@temp/"
TEMP_FILE_TTL_SECONDS = 24 * 60 * 60
REPO_CONTEXT_FILE = "agent-repo-config.local.json"
REPO_CONTEXT_SCHEMA_VERSION = 3

if not TOKEN:
    raise RuntimeError("MCP_TOKEN is required")
if not BASE_DIR.is_dir():
    raise RuntimeError(f"MCP_BASE_DIR does not exist: {BASE_DIR}")

mcp = FastMCP(
    "Notion Local MCP Easy",
    host="127.0.0.1",
    port=PORT,
    stateless_http=True,
    json_response=True,
    # FastMCP's built-in localhost-only Host allowlist causes HTTP 421 behind
    # Serveo, so it is disabled and replaced by the Host check inside
    # SecurityMiddleware (localhost + *.serveousercontent.com).
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
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


def tool():
    """Like @tool() but clips every result through _clip()."""
    def deco(fn):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            return _clip(await fn(*args, **kwargs))
        return mcp.tool()(wrapper)
    return deco


def _path(value: str = ".") -> Path:
    return safe_path(BASE_DIR, value)


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
    safe_prefix = "".join(
        ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in prefix
    ).strip("-") or "output"
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    return _temp_dir() / f"{safe_prefix}-{stamp}.txt"


def _repo_context_path() -> Path:
    return _path(REPO_CONTEXT_FILE)


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


def _load_repo_context() -> dict[str, object] | None:
    config_path = _repo_context_path()
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
) -> Path:
    if status not in {"configured", "disabled"}:
        raise ValueError("status must be 'configured' or 'disabled'")
    if branch_mode not in {"default_branch", "specified_branch"}:
        raise ValueError("branch_mode must be 'default_branch' or 'specified_branch'")

    existing: dict[str, object] | None
    try:
        existing = _load_repo_context()
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

    config_path = _repo_context_path()
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


def _run_git_query(cwd: Path, *args: str, timeout: int = 5) -> subprocess.CompletedProcess[str] | None:
    executable = _git_executable()
    if not executable:
        return None
    return subprocess.run(
        [executable, *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
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
    )
    if result.returncode != 0:
        details = (result.stderr or result.stdout or "unknown error").strip()
        raise ValueError(f"git {' '.join(args)} failed: {details}")
    return result


def _detect_git_repo(cwd: Path) -> dict[str, object]:
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

    top_level = _run_git_query(cwd, "rev-parse", "--show-toplevel")
    if top_level is None or top_level.returncode != 0:
        return result

    root = top_level.stdout.strip()
    branch = _run_git_query(cwd, "branch", "--show-current")
    remotes_query = _run_git_query(cwd, "remote")
    remotes: dict[str, str] = {}
    if remotes_query is not None and remotes_query.returncode == 0:
        for remote_name in [line.strip() for line in remotes_query.stdout.splitlines() if line.strip()]:
            url_query = _run_git_query(cwd, "config", "--get", f"remote.{remote_name}.url")
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


def _repo_context_state(cwd: Path) -> tuple[str, dict[str, object] | None, dict[str, object], list[str]]:
    lines: list[str] = []
    config: dict[str, object] | None

    try:
        config = _load_repo_context()
    except ValueError as exc:
        config = None
        lines.append(f"repo context status: invalid ({exc})")
        detected = _detect_git_repo(cwd)
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

    detected = _detect_git_repo(cwd)
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


def _repo_context_summary(cwd: Path) -> str:
    _, _, _, lines = _repo_context_state(cwd)
    return "\n".join(lines)


def _ensure_remote_url(cwd: Path, remote_name: str, url: str, force_update: bool) -> str:
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
) -> str:
    mode = mode.strip()
    branch_mode = branch_mode.strip() or "default_branch"
    if mode not in {"bind_existing_repo", "attach_to_remote", "init_new_repo", "disable_git"}:
        raise ValueError("mode must be one of: bind_existing_repo, attach_to_remote, init_new_repo, disable_git")
    if branch_mode not in {"default_branch", "specified_branch"}:
        raise ValueError("branch_mode must be 'default_branch' or 'specified_branch'")

    if mode == "disable_git":
        existing = None
        try:
            existing = _load_repo_context()
        except ValueError:
            existing = None
        detected = _detect_git_repo(cwd)
        repository_url = (
            str(existing["repository_url"]) if existing and existing["repository_url"] else str(detected["origin_url"])
        )
        is_fork = existing["is_fork"] if existing else None
        upstream_url = str(existing["upstream_url"]) if existing else ""
        default_branch = str(existing["default_branch"]) if existing else ""
        branch_mode = str(existing["branch_mode"]) if existing and existing.get("branch_mode") else "default_branch"
        commit_branch = str(existing["commit_branch"]) if existing else ""
        config_path = _save_repo_context(
            status="disabled",
            repository_url=repository_url,
            is_fork=is_fork if isinstance(is_fork, bool) else None,
            upstream_url=upstream_url,
            default_branch=default_branch,
            branch_mode=branch_mode,
            commit_branch=commit_branch,
            git_enabled=False,
            disabled_reason=disable_reason or "user choice",
            last_detected_origin=str(detected["origin_url"]),
            last_detected_branch=str(detected["branch"]),
        )
        summary = _repo_context_summary(cwd)
        return f"Saved disabled git policy to {config_path.relative_to(BASE_DIR)}\n\n{summary}"

    repository_url = repository_url.strip()
    if not repository_url:
        raise ValueError("repository_url is required for this setup mode")
    is_fork = _parse_fork_status(fork_status)
    upstream_url = upstream_url.strip()
    default_branch = default_branch.strip()
    commit_branch = commit_branch.strip()
    if branch_mode == "specified_branch" and not commit_branch:
        raise ValueError("commit_branch is required when branch_mode='specified_branch'")

    detected_before = _detect_git_repo(cwd)
    if not detected_before["git_installed"]:
        raise ValueError("Git is not installed or not on PATH.")

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

    actions.append(_ensure_remote_url(work_root, "origin", repository_url, force_origin_update))
    if upstream_url and set_upstream_remote:
        actions.append(_ensure_remote_url(work_root, "upstream", upstream_url, True))

    detected_after = _detect_git_repo(work_root)
    final_branch = str(detected_after["branch"] or default_branch).strip()
    stored_default_branch = default_branch or final_branch
    if branch_mode == "default_branch" and not stored_default_branch:
        raise ValueError("default_branch is required when branch_mode='default_branch'")

    config_path = _save_repo_context(
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


def _extract_git_subcommand(git_args: list[str]) -> str:
    options_with_value = {"-c", "-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env"}
    skip_next = False
    for arg in git_args:
        if skip_next:
            skip_next = False
            continue
        if arg in options_with_value:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        return arg.lower()
    return ""


def _ensure_git_context_for_command(cwd: Path, git_args: list[str] | None = None) -> None:
    state, config, detected, lines = _repo_context_state(cwd)
    if state != "repo_present_bound_ok":
        raise ValueError("Git is blocked for this workspace.\n\n" + "\n".join(lines))
    if config is None:
        raise ValueError("Git is blocked because repo context data is unavailable.")

    subcommand = _extract_git_subcommand(git_args or [])
    branch_sensitive = {"commit", "push", "merge", "rebase", "cherry-pick", "revert", "am"}
    if subcommand not in branch_sensitive:
        return

    target_branch = _target_commit_branch(config)
    if not target_branch:
        raise ValueError(
            "Git is blocked because commit branch policy is not fully configured. "
            "Run setup_git_context(...) and choose default_branch or commit_branch explicitly."
        )

    current_branch = str(detected.get("branch", "")).strip()
    if not current_branch:
        raise ValueError(
            f"Git is blocked because commits for this workspace must happen on {target_branch}, "
            "but the repository is currently detached or the branch is unknown."
        )
    if current_branch != target_branch:
        raise ValueError(
            f"Git is blocked because this workspace is configured to commit on {target_branch}, "
            f"but the current branch is {current_branch}. Switch branches first or update the repo context."
        )


def _read_text_with_replace(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _slice_chunk(
    text: str,
    offset: int = 0,
    limit: int = 0,
    char_limit: int = CHUNK_CHAR_LIMIT,
) -> dict[str, object]:
    lines = text.splitlines(keepends=True)
    start = max(0, offset)
    line_limit = max(1, min(limit or DEFAULT_READ_LINES, 2000))
    total = len(lines)

    if start >= total:
        return {
            "start": start,
            "end": start,
            "total": total,
            "body": "(end of content)",
            "reason": None,
            "oversized_line_chars": None,
            "is_complete": True,
            "char_limit": char_limit,
        }

    selected: list[str] = []
    selected_chars = 0
    stop_reason: str | None = None
    oversized_line_chars: int | None = None

    for index in range(start, total):
        line = lines[index]
        if len(selected) >= line_limit:
            stop_reason = "line limit"
            break
        if selected_chars + len(line) > char_limit:
            stop_reason = "character limit"
            if not selected:
                oversized_line_chars = len(line)
            break
        selected.append(line)
        selected_chars += len(line)

    end = start + len(selected)
    is_complete = end >= total

    if oversized_line_chars is not None:
        body = (
            f"(line {start + 1} is {oversized_line_chars:,} chars long, exceeds the safe response limit "
            f"of {char_limit:,}, and is not split automatically.)"
        )
    else:
        body = "".join(selected) or "(empty result)"

    return {
        "start": start,
        "end": end,
        "total": total,
        "body": body,
        "reason": stop_reason,
        "oversized_line_chars": oversized_line_chars,
        "is_complete": is_complete,
        "char_limit": char_limit,
    }


def _render_chunk_text(chunk: dict[str, object], source_label: str) -> tuple[str, bool]:
    start = int(chunk["start"])
    end = int(chunk["end"])
    total = int(chunk["total"])
    body = str(chunk["body"])
    reason = chunk["reason"]
    is_complete = bool(chunk["is_complete"])
    oversized_line_chars = chunk["oversized_line_chars"]

    header = f"[lines {start}–{end} of {total} | next offset {end}]"
    if oversized_line_chars is not None:
        return header + "\n" + body, False
    if end < total:
        footer = (
            f"\n\n... [{total - end} more lines hidden. Stopped by {reason or 'character limit'}. "
            f"Call read_file(path={source_label!r}, offset={end}) to continue.]"
        )
    else:
        footer = ""
    return header + "\n" + body + footer, is_complete


def _format_chunk_text(text: str, source_label: str, offset: int = 0, limit: int = 0) -> tuple[str, bool]:
    working_char_limit = CHUNK_CHAR_LIMIT

    while True:
        chunk = _slice_chunk(text, offset=offset, limit=limit, char_limit=working_char_limit)
        rendered, is_complete = _render_chunk_text(chunk, source_label)
        overflow = len(rendered) - MAX_OUTPUT_CHARS
        if overflow <= 0 or chunk["oversized_line_chars"] is not None:
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
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
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


async def _capture_process(
    proc: asyncio.subprocess.Process, timeout: int
) -> tuple[bytes, bytes, bool, bool]:
    """Capture bounded output. Returns stdout, stderr, timed_out, truncated."""
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    total = 0
    limit_reached = asyncio.Event()

    async def consume(stream: asyncio.StreamReader, target: bytearray) -> None:
        nonlocal total
        while True:
            chunk = await stream.read(8192)
            if not chunk:
                return
            remaining = MAX_COMMAND_OUTPUT - total
            if remaining <= 0:
                limit_reached.set()
                continue
            accepted = chunk[:remaining]
            target.extend(accepted)
            total += len(accepted)
            if len(accepted) < len(chunk):
                limit_reached.set()

    async def finish() -> None:
        assert proc.stdout is not None and proc.stderr is not None
        await asyncio.gather(
            consume(proc.stdout, stdout_buffer),
            consume(proc.stderr, stderr_buffer),
            proc.wait(),
        )

    run_task = asyncio.create_task(finish())
    limit_task = asyncio.create_task(limit_reached.wait())
    done, _ = await asyncio.wait(
        {run_task, limit_task}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED
    )
    timed_out = not done
    truncated = limit_task in done and limit_reached.is_set()
    if timed_out or truncated:
        await _kill_tree(proc)
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(run_task, timeout=5)
    limit_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await limit_task
    return bytes(stdout_buffer), bytes(stderr_buffer), timed_out, truncated


@tool()
async def workspace_info() -> str:
    """Show the allowed workspace, active mode, and git repo-context status."""
    commands = ", ".join(sorted(ALLOWED_COMMANDS)) if ALLOW_COMMANDS else "disabled"
    mode = "trusted developer mode" if ALLOW_COMMANDS else "file-only mode"
    repo_summary = await asyncio.to_thread(_repo_context_summary, BASE_DIR)
    return (
        f"workspace: {BASE_DIR}\nmode: {mode}\ncommands: {commands}\n"
        f"max text file: {MAX_TEXT_FILE:,} bytes\n"
        f"repo context file: {REPO_CONTEXT_FILE}\n"
        f"{repo_summary}"
    )


@tool()
async def repo_context_status(cwd: str = ".") -> str:
    """Show the current repo-context configuration, git detection, and next setup step."""
    workdir = _path(cwd)
    if not workdir.is_dir():
        raise ValueError(f"cwd is not a directory: {cwd}")
    return await asyncio.to_thread(_repo_context_summary, workdir)


@tool()
async def inspect_git_repository(cwd: str = ".") -> str:
    """Inspect the git repository in this workspace without running any mutating git command."""
    workdir = _path(cwd)
    if not workdir.is_dir():
        raise ValueError(f"cwd is not a directory: {cwd}")
    return await asyncio.to_thread(_inspect_git_repository_text, workdir)


@tool()
async def configure_repo_context(
    repository_url: str,
    is_fork: bool,
    upstream_url: str = "",
    default_branch: str = "",
    branch_mode: str = "default_branch",
    commit_branch: str = "",
) -> str:
    """Low-level manual override for the local repo-context file. Prefer setup_git_context() for normal use."""
    detected = await asyncio.to_thread(_detect_git_repo, BASE_DIR)
    branch_mode = branch_mode.strip() or "default_branch"
    inferred_default_branch = default_branch.strip() or str(detected["branch"] or "").strip()
    config_path = await asyncio.to_thread(
        _save_repo_context,
        status="configured",
        repository_url=repository_url,
        is_fork=is_fork,
        upstream_url=upstream_url,
        default_branch=inferred_default_branch,
        branch_mode=branch_mode,
        commit_branch=commit_branch,
        git_enabled=True,
        disabled_reason="",
        last_detected_origin=str(detected["origin_url"]),
        last_detected_branch=str(detected["branch"] or inferred_default_branch),
    )
    summary = await asyncio.to_thread(_repo_context_summary, BASE_DIR)
    return f"Saved repo context to {config_path.relative_to(BASE_DIR)}\n\n{summary}"


@tool()
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
    )


@tool()
async def list_dir(

    path: str = ".",
    recursive: bool = False,
    include_hidden: bool = False,
    max_results: int = 300,
) -> str:
    """List files inside the workspace. Large dependency/cache folders are skipped."""
    root = _path(path)
    if not root.is_dir():
        raise ValueError(f"Not a directory: {root}")
    limit = max(1, min(max_results, MAX_RESULTS))
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


@tool()
async def file_info(path: str) -> str:
    """Show file or directory metadata."""
    item = _path(path)
    if not item.exists():
        return f"Not found: {path}"
    stat = item.stat()
    kind = "directory" if item.is_dir() else "file"
    modified = dt.datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds")
    return (
        f"path: {item.relative_to(BASE_DIR)}\ntype: {kind}\n"
        f"size: {stat.st_size:,}\nmodified: {modified}"
    )


@tool()
async def read_file(path: str, offset: int = 0, limit: int = 0) -> str:
    """Read a text file in chunks with a character budget that takes priority over line count."""
    item, is_temp_file = _resolve_read_file_path(path)
    if not item.exists():
        raise ValueError(f"File not found: {item}")
    if not item.is_file():
        raise ValueError(f"Not a file: {item}")

    def _read() -> str:
        with item.open("rb") as handle:
            if _is_binary_bytes(handle.read(8192)):
                label = path if is_temp_file else str(item.relative_to(BASE_DIR))
                return f"(binary file, not shown as text): {label} — {item.stat().st_size:,} bytes"
        text_content = _read_text_with_replace(item)
        rendered, is_complete = _format_chunk_text(text_content, path, offset=offset, limit=limit)
        if is_temp_file and is_complete:
            with contextlib.suppress(OSError):
                item.unlink()
        return rendered

    return await asyncio.to_thread(_read)



@tool()
async def write_file(path: str, content: str, overwrite: bool = True) -> str:
    """Write a UTF-8 text file inside the workspace."""
    encoded_size = len(content.encode("utf-8"))
    if encoded_size > MAX_WRITE:
        raise ValueError(f"Content exceeds {MAX_WRITE:,} bytes")
    item = _path(path)
    if item.exists() and not overwrite:
        raise ValueError(f"File already exists: {path}")

    def _write() -> None:
        item.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_text(item, content)

    await asyncio.to_thread(_write)
    return f"Wrote {len(content):,} characters to {item.relative_to(BASE_DIR)}"


@tool()
async def append_file(path: str, content: str) -> str:
    """Append UTF-8 text while keeping the resulting file under the size limit."""
    encoded_size = len(content.encode("utf-8"))
    if encoded_size > MAX_WRITE:
        raise ValueError(f"Content exceeds {MAX_WRITE:,} bytes")
    item = _path(path)
    current_size = item.stat().st_size if item.exists() else 0
    if current_size + encoded_size > MAX_TEXT_FILE:
        raise ValueError(f"Resulting file would exceed {MAX_TEXT_FILE:,} bytes")

    def _append() -> None:
        item.parent.mkdir(parents=True, exist_ok=True)
        with item.open("a", encoding="utf-8") as handle:
            handle.write(content)

    await asyncio.to_thread(_append)
    return f"Appended {len(content):,} characters to {item.relative_to(BASE_DIR)}"


@tool()
async def edit_file(
    path: str,
    old_string: str,
    new_string: str,
    replace_all: bool = False,
) -> str:
    """Replace exact text in a UTF-8 file. Read the file first."""
    item = _path(path)
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


@tool()
async def create_dir(path: str) -> str:
    """Create a directory and missing parents. Existing directories are accepted."""
    item = _path(path)
    await asyncio.to_thread(item.mkdir, parents=True, exist_ok=True)
    return f"Directory ready: {item.relative_to(BASE_DIR)}"


@tool()
async def delete_file(path: str) -> str:
    """Delete one file or one empty directory. Recursive deletion is unavailable."""
    item = _path(path)
    if not item.exists():
        return f"Not found: {path}"
    if item.is_dir():
        await asyncio.to_thread(item.rmdir)
    else:
        await asyncio.to_thread(item.unlink)
    return f"Deleted: {item.relative_to(BASE_DIR)}"


@tool()
async def copy_file(src: str, dst: str, overwrite: bool = False) -> str:
    """Copy one file inside the workspace."""
    source, target = _path(src), _path(dst)
    if not source.is_file():
        raise ValueError(f"Source is not a file: {src}")
    if target.exists() and not overwrite:
        raise ValueError(f"Destination exists: {dst}")
    target.parent.mkdir(parents=True, exist_ok=True)
    await asyncio.to_thread(shutil.copy2, source, target)
    return f"Copied {source.relative_to(BASE_DIR)} -> {target.relative_to(BASE_DIR)}"


@tool()
async def move_file(src: str, dst: str, overwrite: bool = False) -> str:
    """Move or rename one file inside the workspace."""
    source, target = _path(src), _path(dst)
    if not source.is_file():
        raise ValueError(f"Source is not a file: {src}")
    if target.exists() and not overwrite:
        raise ValueError(f"Destination exists: {dst}")
    target.parent.mkdir(parents=True, exist_ok=True)
    await asyncio.to_thread(shutil.move, str(source), str(target))
    return f"Moved {source.relative_to(BASE_DIR)} -> {target.relative_to(BASE_DIR)}"


@tool()
async def glob_files(pattern: str, path: str = ".", max_results: int = 300) -> str:
    """Find workspace files using a glob such as **/*.py."""
    root = _path(path)
    limit = max(1, min(max_results, MAX_RESULTS))
    rows: list[str] = []
    for item in root.glob(pattern):
        if not item.is_file() or any(part in EXCLUDES for part in item.parts):
            continue
        safe_path(BASE_DIR, item)
        rows.append(str(item.relative_to(root)))
        if len(rows) >= limit:
            break
    return "\n".join(sorted(rows)) if rows else "No files matched."


@tool()
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


@tool()
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

    seconds = max(1, min(timeout, 300))
    flags = 0x00000200 if os.name == "nt" else 0

    stdout_capture = _tool_output_path("run-command-stdout")
    stderr_capture = _tool_output_path("run-command-stderr")
    stdout_handle = open(stdout_capture, "wb")
    stderr_handle = open(stderr_capture, "wb")

    try:
        proc = await asyncio.create_subprocess_exec(
            executable,
            *(args or []),
            cwd=str(workdir),
            stdout=stdout_handle,
            stderr=stderr_handle,
            creationflags=flags,
        )
        timed_out = False
        try:
            await asyncio.wait_for(proc.wait(), timeout=seconds)
        except TimeoutError:
            timed_out = True
            await _kill_tree(proc)
    finally:
        stdout_handle.close()
        stderr_handle.close()

    try:
        stdout_text = await asyncio.to_thread(_read_text_with_replace, stdout_capture)
        stderr_text = await asyncio.to_thread(_read_text_with_replace, stderr_capture)
        stdout_text = stdout_text if stdout_text != "" else "(empty result)"
        stderr_text = stderr_text if stderr_text != "" else "(empty result)"

        prefix = (
            f"Timed out after {seconds}s (process tree stopped).\n"
            if timed_out
            else ""
        )
        result = (
            prefix
            + f"exit code: {proc.returncode}\n"
            + f"--- stdout ---\n{stdout_text}\n"
            + f"--- stderr ---\n{stderr_text}"
        )
        return _direct_or_saved_output("run-command", result)
    finally:
        with contextlib.suppress(OSError):
            stdout_capture.unlink()
        with contextlib.suppress(OSError):
            stderr_capture.unlink()


def _extract_token(request) -> str:
    auth = request.headers.get("authorization", "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.headers.get("x-api-key", "").strip()


def _host_allowed(host_header: str) -> bool:
    host = host_header.split(":", 1)[0].strip().lower()
    if host in {"127.0.0.1", "localhost"}:
        return True
    if STABLE_HOSTNAME:
        return host == f"{STABLE_HOSTNAME}{SERVEO_SUFFIX}"
    return host.endswith(SERVEO_SUFFIX)


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if not _host_allowed(request.headers.get("host", "")):
            return JSONResponse({"error": "forbidden host"}, status_code=403)
        incoming = _extract_token(request)
        if not incoming or not hmac.compare_digest(incoming, TOKEN):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if request.url.path == "/health":
            return JSONResponse({"status": "ok"})
        return await call_next(request)


if __name__ == "__main__":
    import uvicorn

    _cleanup_temp_files()
    app = mcp.streamable_http_app()
    app.add_middleware(SecurityMiddleware)
    print(f"Notion Local MCP Easy: http://127.0.0.1:{PORT}/mcp")
    print(f"Workspace: {BASE_DIR}")
    print(f"Commands: {'trusted developer mode' if ALLOW_COMMANDS else 'file-only mode'}")
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="info")
