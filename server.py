from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import fnmatch
import hmac
import os
import shutil
from itertools import islice
from pathlib import Path

from core import (
    DEFAULT_ALLOWED_COMMANDS,
    DEFAULT_EXCLUDES,
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


def _path(value: str = ".") -> Path:
    return safe_path(BASE_DIR, value)


def _text_file(path: Path) -> None:
    if not path.exists():
        raise ValueError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Not a file: {path}")
    size = path.stat().st_size
    if size > MAX_TEXT_FILE:
        raise ValueError(f"File is too large ({size:,} bytes; limit {MAX_TEXT_FILE:,})")


def _atomic_write_text(path: Path, content: str) -> None:
    """Write via temp file + replace so a crash or sync never leaves a partial file."""
    temp = path.with_name(path.name + ".mcp-tmp")
    with temp.open("w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    temp.replace(path)


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


@mcp.tool()
async def workspace_info() -> str:
    """Show the allowed workspace and whether trusted developer commands are enabled."""
    commands = ", ".join(sorted(ALLOWED_COMMANDS)) if ALLOW_COMMANDS else "disabled"
    mode = "trusted developer mode" if ALLOW_COMMANDS else "file-only mode"
    return (
        f"workspace: {BASE_DIR}\nmode: {mode}\ncommands: {commands}\n"
        f"max text file: {MAX_TEXT_FILE:,} bytes"
    )


@mcp.tool()
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
    return "\n".join(rows) + suffix


@mcp.tool()
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


@mcp.tool()
async def read_file(path: str, offset: int = 0, limit: int = 500) -> str:
    """Read a UTF-8 text file by line range (maximum 2000 lines per call)."""
    item = _path(path)
    _text_file(item)
    start = max(0, offset)
    count = max(1, min(limit, 2000))

    def _read() -> str:
        with item.open("r", encoding="utf-8", errors="replace") as handle:
            lines = list(islice(handle, start, start + count))
        return f"[lines {start}-{start + len(lines)}]\n" + "".join(lines)

    return await asyncio.to_thread(_read)


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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
        text = item.read_text(encoding="utf-8")
        found = text.count(old_string)
        if found == 0:
            raise ValueError("old_string was not found")
        if not replace_all and found > 1:
            raise ValueError(
                f"old_string occurs {found} times; use a larger match or replace_all"
            )
        count = found if replace_all else 1
        updated = (
            text.replace(old_string, new_string)
            if replace_all
            else text.replace(old_string, new_string, 1)
        )
        if len(updated.encode("utf-8")) > MAX_TEXT_FILE:
            raise ValueError("Updated file would exceed the size limit")
        _atomic_write_text(item, updated)
        return count

    count = await asyncio.to_thread(_edit)
    return f"Replaced {count} occurrence(s) in {item.relative_to(BASE_DIR)}"


@mcp.tool()
async def create_dir(path: str) -> str:
    """Create a directory and missing parents. Existing directories are accepted."""
    item = _path(path)
    await asyncio.to_thread(item.mkdir, parents=True, exist_ok=True)
    return f"Directory ready: {item.relative_to(BASE_DIR)}"


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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
                                return (
                                    "\n".join(rows)
                                    + f"\n... limited to {limit} results"
                                )
                except (OSError, UnicodeError):
                    continue
        return "\n".join(rows) if rows else "No matches found."

    return await asyncio.to_thread(_grep)


@mcp.tool()
async def run_command(
    program: str,
    args: list[str] | None = None,
    cwd: str = ".",
    timeout: int = 60,
) -> str:
    """Trusted developer mode: run an allow-listed program without a shell.

    The working directory must be inside the workspace, but interpreters such
    as Python or Node can access the wider system with the current user's rights.
    """
    if not ALLOW_COMMANDS:
        raise ValueError(
            "Command execution is disabled. Re-run SETUP.bat to enable trusted developer mode."
        )
    executable = resolve_program(BASE_DIR, program, ALLOWED_COMMANDS)
    workdir = _path(cwd)
    if not workdir.is_dir():
        raise ValueError(f"cwd is not a directory: {cwd}")
    seconds = max(1, min(timeout, 300))
    flags = 0x00000200 if os.name == "nt" else 0
    proc = await asyncio.create_subprocess_exec(
        executable,
        *(args or []),
        cwd=str(workdir),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        creationflags=flags,
    )
    stdout, stderr, timed_out, truncated = await _capture_process(proc, seconds)
    if timed_out:
        return f"Timed out after {seconds}s (process tree stopped)."
    suffix = "\n... output limit reached; process tree stopped" if truncated else ""
    return (
        f"exit code: {proc.returncode}\n"
        f"--- stdout ---\n{stdout.decode('utf-8', errors='replace')}\n"
        f"--- stderr ---\n{stderr.decode('utf-8', errors='replace')}"
        f"{suffix}"
    )


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

    app = mcp.streamable_http_app()
    app.add_middleware(SecurityMiddleware)
    print(f"Notion Local MCP Easy: http://127.0.0.1:{PORT}/mcp")
    print(f"Workspace: {BASE_DIR}")
    print(f"Commands: {'trusted developer mode' if ALLOW_COMMANDS else 'file-only mode'}")
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="info")
