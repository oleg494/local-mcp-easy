from __future__ import annotations

import argparse
import contextlib
import json
import os
import queue
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import TextIO

APP_NAME = "NotionMcpEasy"
VERSION = "1.4.0"
SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / APP_NAME
CONFIG_FILE = CONFIG_DIR / "config.json"
RUNTIME_FILE = CONFIG_DIR / "runtime.json"
CONNECTION_FILE = CONFIG_DIR / "connection.txt"
SERVER_LOG = CONFIG_DIR / "server.log"
TUNNEL_LOG = CONFIG_DIR / "tunnel.log"
URL_PATTERN = re.compile(r"https://[a-zA-Z0-9.-]+\.serveousercontent\.com")


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def yes_no(prompt: str, default: bool) -> bool:
    marker = "Y/n" if default else "y/N"
    while True:
        answer = input(f"{prompt} [{marker}]: ").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes", "д", "да"}:
            return True
        if answer in {"n", "no", "н", "нет"}:
            return False
        print("Please answer yes or no.")


def setup(force: bool = False) -> dict:
    existing = load_json(CONFIG_FILE)
    if existing and not force:
        return existing

    print(f"\n=== Notion Local MCP Easy {VERSION}: first-time setup ===\n")
    default_workspace = SCRIPT_DIR.parent.parent
    raw = input(f"Workspace folder [{default_workspace}]: ").strip().strip('"')
    workspace = Path(raw).expanduser().resolve() if raw else default_workspace.resolve()
    while not workspace.is_dir():
        print(f"Folder does not exist: {workspace}")
        raw = input("Workspace folder: ").strip().strip('"')
        workspace = Path(raw).expanduser().resolve()

    print("\nFile-only mode keeps MCP file operations inside the selected workspace.")
    print("Trusted developer mode adds Python/Git/Node commands with your Windows user rights.")
    print("Those programs can access files and the network outside the workspace.")
    allow_commands = yes_no("Enable trusted developer mode?", False)

    print("\nA reserved Serveo hostname keeps the same Custom MCP URL after restarts.")
    stable_tunnel = yes_no("Use a reserved Serveo hostname?", False)
    serveo_hostname = ""
    ssh_key = ""
    if stable_tunnel:
        while not serveo_hostname:
            raw_hostname = input("Reserved hostname (without domain): ").strip().lower()
            serveo_hostname = raw_hostname.removesuffix(".serveousercontent.com")
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", serveo_hostname):
                print("Use 3-63 lowercase letters, digits or hyphens.")
                serveo_hostname = ""
        default_key = Path.home() / ".ssh" / "serveo_notion_mcp"
        raw_key = input(f"Serveo private SSH key [{default_key}]: ").strip().strip('"')
        key_path = Path(raw_key).expanduser().resolve() if raw_key else default_key.resolve()
        while not key_path.is_file():
            print(f"Private key not found: {key_path}")
            raw_key = input("Serveo private SSH key: ").strip().strip('"')
            key_path = Path(raw_key).expanduser().resolve()
        ssh_key = str(key_path)

    config = {
        "version": VERSION,
        "token": secrets.token_urlsafe(32),
        "workspace": str(workspace),
        "port": 8765,
        "allow_commands": allow_commands,
        "serveo_hostname": serveo_hostname,
        "ssh_key": ssh_key,
        "allowed_commands": [
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
        ],
    }
    save_json(CONFIG_FILE, config)
    print(f"\nConfiguration saved in: {CONFIG_FILE}")
    print("The access token is generated automatically.\n")
    return config


def pid_exists(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def process_command_line(pid: int) -> str:
    if not pid_exists(pid):
        return ""
    if os.name == "nt":
        command = (
            "$p=Get-CimInstance Win32_Process -Filter \"ProcessId="
            + str(pid)
            + "\" -ErrorAction SilentlyContinue; if($p){$p.CommandLine}"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
        return result.stdout.strip()
    proc_cmdline = Path(f"/proc/{pid}/cmdline")
    with contextlib.suppress(OSError):
        return proc_cmdline.read_bytes().replace(b"\0", b" ").decode(errors="replace")
    return ""


def pid_matches(pid: int, expected: str) -> bool:
    command_line = process_command_line(pid)
    return bool(command_line) and expected.lower() in command_line.lower()


def stop_pid(pid: int, expected: str) -> bool:
    if not pid_exists(pid):
        return True
    if not pid_matches(pid, expected):
        print(f"Refusing to stop PID {pid}: process identity does not match {expected!r}.")
        return False
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/T", "/F", "/PID", str(pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        with contextlib.suppress(OSError):
            os.kill(pid, 15)
    return True


def stop_all() -> None:
    runtime = load_json(RUNTIME_FILE)
    pairs = (
        (runtime.get("tunnel_pid", 0), runtime.get("tunnel_match", "serveo.net")),
        (runtime.get("server_pid", 0), runtime.get("server_match", "server.py")),
    )
    all_stopped = True
    for raw_pid, expected in pairs:
        with contextlib.suppress(TypeError, ValueError):
            all_stopped = stop_pid(int(raw_pid), str(expected)) and all_stopped
    if all_stopped:
        RUNTIME_FILE.unlink(missing_ok=True)
        print("Notion Local MCP Easy is stopped.")
    else:
        print("One or more PIDs were not stopped because their identity did not match.")


def port_is_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False


def health_ok(port: int, token: str) -> bool:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/health",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=1) as response:
            payload = json.loads(response.read())
            return response.status == 200 and payload == {"status": "ok"}
    except (OSError, ValueError, urllib.error.URLError):
        return False


def tunnel_log_tail(limit: int = 15) -> str:
    try:
        lines = TUNNEL_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[-limit:])


def tunnel_error(message: str) -> RuntimeError:
    tail = tunnel_log_tail()
    details = f"\n--- last tunnel output ({TUNNEL_LOG}) ---\n{tail}" if tail else f"; see {TUNNEL_LOG}"
    return RuntimeError(message + details)


def public_health_ok(
    url: str,
    token: str,
    attempts: int = 10,
    delay: float = 2.0,
    process: subprocess.Popen | None = None,
) -> bool:
    """Poll the public /health endpoint until the tunnel actually serves traffic."""
    for attempt in range(attempts):
        if process is not None and process.poll() is not None:
            return False
        request = urllib.request.Request(
            url.rstrip("/") + "/health",
            headers={"Authorization": f"Bearer {token}"},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read())
                if response.status == 200 and payload == {"status": "ok"}:
                    return True
        except (OSError, ValueError, urllib.error.URLError):
            pass
        if attempt < attempts - 1:
            time.sleep(delay)
    return False


def wait_for_server(
    port: int, token: str, process: subprocess.Popen, timeout: float = 25.0
) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"MCP server exited with code {process.returncode}; see {SERVER_LOG}"
            )
        if health_ok(port, token):
            return
        time.sleep(0.25)
    raise RuntimeError(f"MCP server health check failed on port {port}; see {SERVER_LOG}")


def start_server(config: dict) -> tuple[subprocess.Popen, TextIO]:
    port = int(config.get("port", 8765))
    if port_is_open(port):
        raise RuntimeError(
            f"Port {port} is already in use. Stop the other service or change the port in {CONFIG_FILE}."
        )
    env = os.environ.copy()
    env.update(
        {
            "MCP_TOKEN": config["token"],
            "MCP_BASE_DIR": config["workspace"],
            "MCP_PORT": str(port),
            "MCP_ALLOW_COMMANDS": "1" if config.get("allow_commands", False) else "0",
            "MCP_ALLOWED_COMMANDS": ",".join(config.get("allowed_commands", [])),
            "MCP_SERVEO_HOSTNAME": str(config.get("serveo_hostname", "")).strip().lower(),
            "PYTHONUNBUFFERED": "1",
        }
    )
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    log = SERVER_LOG.open("w", encoding="utf-8")
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    process = subprocess.Popen(
        [sys.executable, str(SCRIPT_DIR / "server.py")],
        cwd=str(SCRIPT_DIR),
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
        creationflags=flags,
    )
    try:
        wait_for_server(port, config["token"], process)
    except Exception:
        log.close()
        with contextlib.suppress(Exception):
            stop_pid(process.pid, "server.py")
        raise
    return process, log


def build_tunnel_command(config: dict) -> list[str]:
    if not shutil.which("ssh"):
        raise RuntimeError(
            "OpenSSH client was not found. Install Windows Optional Feature: OpenSSH Client."
        )
    port = int(config.get("port", 8765))
    hostname = str(config.get("serveo_hostname", "")).strip().lower()
    command = [
        "ssh",
        "-T",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ServerAliveInterval=30",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "ExitOnForwardFailure=yes",
    ]
    if hostname:
        key_path = Path(str(config.get("ssh_key", ""))).expanduser().resolve()
        if not key_path.is_file():
            raise RuntimeError(f"Serveo private SSH key not found: {key_path}")
        # No BatchMode here: Serveo finishes auth via keyboard-interactive with
        # an empty challenge even for registered keys (the key only authorizes
        # the reserved hostname). BatchMode disables keyboard-interactive and
        # breaks auth entirely — verified live on 2026-07-17.
        command.extend(["-i", str(key_path), "-o", "IdentitiesOnly=yes"])
        remote = f"{hostname}:80:127.0.0.1:{port}"
    else:
        remote = f"80:127.0.0.1:{port}"
    command.extend(["-R", remote, "serveo.net"])
    return command


def start_tunnel(config: dict) -> tuple[subprocess.Popen, queue.Queue[str]]:
    command = build_tunnel_command(config)
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    process = subprocess.Popen(
        command,
        cwd=str(SCRIPT_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=flags,
    )
    lines: queue.Queue[str] = queue.Queue()

    def pump() -> None:
        with TUNNEL_LOG.open("w", encoding="utf-8") as log:
            assert process.stdout is not None
            for line in process.stdout:
                log.write(line)
                log.flush()
                lines.put(line)

    threading.Thread(target=pump, daemon=True).start()
    return process, lines


def wait_for_url(
    process: subprocess.Popen, lines: queue.Queue[str], timeout: float = 45.0
) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process.poll() is not None:
            raise tunnel_error(f"SSH tunnel exited with code {process.returncode}")
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            continue
        match = URL_PATTERN.search(line)
        if match:
            return match.group(0)
    raise tunnel_error("Tunnel URL was not received")


def resolve_tunnel_url(
    config: dict,
    process: subprocess.Popen,
    lines: queue.Queue[str],
    startup_grace: float = 2.0,
) -> str:
    """Return the public tunnel URL for temporary or reserved-hostname mode.

    Temporary Serveo tunnels announce their assigned URL in SSH output. A
    reserved hostname is already known and Serveo may keep SSH output silent,
    so waiting for an announcement would cause a false timeout.
    """
    hostname = str(config.get("serveo_hostname", "")).strip().lower()
    if not hostname:
        return wait_for_url(process, lines)

    deadline = time.time() + max(0.0, startup_grace)
    while time.time() < deadline:
        if process.poll() is not None:
            raise tunnel_error(f"SSH tunnel exited with code {process.returncode}")
        time.sleep(0.1)

    if process.poll() is not None:
        raise tunnel_error(f"SSH tunnel exited with code {process.returncode}")
    return f"https://{hostname}.serveousercontent.com"


def publish_connection(config: dict, url: str, server_pid: int, tunnel_pid: int) -> None:
    endpoint = url.rstrip("/") + "/mcp"
    runtime = {
        "version": VERSION,
        "server_pid": server_pid,
        "server_match": "server.py",
        "tunnel_pid": tunnel_pid,
        "tunnel_match": "serveo.net",
        "url": endpoint,
        "started_at": datetime.now().isoformat(timespec="seconds"),
    }
    save_json(RUNTIME_FILE, runtime)
    mode = "trusted developer" if config.get("allow_commands", False) else "file-only"
    hostname = str(config.get("serveo_hostname", "")).strip()
    tunnel_mode = f"stable ({hostname})" if hostname else "temporary"
    CONNECTION_FILE.write_text(
        f"Notion Local MCP Easy {VERSION}\n"
        f"URL: {endpoint}\n"
        f"Bearer token: {config['token']}\n"
        f"Workspace: {config['workspace']}\n"
        f"Mode: {mode}\n"
        f"Tunnel: {tunnel_mode}\n",
        encoding="utf-8",
    )
    print("\n=======================================================")
    print(f" Notion Local MCP Easy {VERSION} is running")
    print("=======================================================")
    print(f" URL: {endpoint}")
    print(f" Bearer token: {config['token']}")
    print(f" Workspace: {config['workspace']}")
    print(f" Mode: {mode}")
    print(f" Connection info: {CONNECTION_FILE}")
    print("=======================================================")
    print("Keep this window open. Press Ctrl+C to stop.\n")


def run() -> int:
    config = setup()
    runtime = load_json(RUNTIME_FILE)
    old_server = int(runtime.get("server_pid", 0) or 0)
    if pid_matches(old_server, str(runtime.get("server_match", "server.py"))):
        print("The server is already running.")
        if CONNECTION_FILE.exists():
            print(CONNECTION_FILE.read_text(encoding="utf-8"))
        return 0
    RUNTIME_FILE.unlink(missing_ok=True)

    server: subprocess.Popen | None = None
    server_log: TextIO | None = None
    tunnel: subprocess.Popen | None = None
    try:
        server, server_log = start_server(config)
        tunnel, lines = start_tunnel(config)
        url = resolve_tunnel_url(config, tunnel, lines)
        if not public_health_ok(url, config["token"], process=tunnel):
            raise tunnel_error(f"Public health check failed: {url}/health did not answer")
        publish_connection(config, url, server.pid, tunnel.pid)

        while True:
            if server.poll() is not None:
                raise RuntimeError(
                    f"MCP server stopped with code {server.returncode}; see {SERVER_LOG}"
                )
            if tunnel.poll() is not None:
                print("Tunnel disconnected; reconnecting in 3 seconds...")
                time.sleep(3)
                tunnel, lines = start_tunnel(config)
                url = resolve_tunnel_url(config, tunnel, lines)
                healthy = public_health_ok(url, config["token"], process=tunnel)
                publish_connection(config, url, server.pid, tunnel.pid)
                if not healthy:
                    print(f"WARNING: {url}/health is not answering yet; keeping the tunnel up and retrying on next disconnect.")
                elif config.get("serveo_hostname"):
                    print("Stable Serveo tunnel restored with the same URL.")
                if not config.get("serveo_hostname"):
                    print("IMPORTANT: the tunnel URL changed. Update the Custom MCP URL in Notion.")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        return 0
    except Exception as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        if tunnel is not None and tunnel.poll() is None:
            stop_pid(tunnel.pid, "serveo.net")
        if server is not None and server.poll() is None:
            stop_pid(server.pid, "server.py")
        if server_log is not None:
            server_log.close()
        RUNTIME_FILE.unlink(missing_ok=True)


def mask_token(token: str) -> str:
    if len(token) <= 10:
        return "*" * len(token)
    return f"{token[:4]}...{token[-4:]}"


def show_connection(full: bool) -> int:
    if not CONNECTION_FILE.exists():
        print("No connection information yet. Run START.bat first.")
        return 1
    text = CONNECTION_FILE.read_text(encoding="utf-8")
    if not full:
        token = str(load_json(CONFIG_FILE).get("token", ""))
        if token:
            text = text.replace(token, mask_token(token))
        print(text)
        print("Token is masked. Use SHOW_CONNECTION.bat --full to reveal it.")
        return 0
    print(text)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"One-click launcher for Notion Local MCP Easy {VERSION}"
    )
    parser.add_argument("--setup", action="store_true", help="run the setup wizard again")
    parser.add_argument("--stop", action="store_true", help="stop background processes")
    parser.add_argument("--show", action="store_true", help="show current connection details")
    parser.add_argument(
        "--full", action="store_true", help="with --show: reveal the full Bearer token"
    )
    args = parser.parse_args()

    if args.stop:
        stop_all()
        return 0
    if args.setup:
        stop_all()
        setup(force=True)
        return 0
    if args.show:
        return show_connection(args.full)
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
