from __future__ import annotations

import argparse
import contextlib
import json
import os
import queue
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import TextIO

APP_NAME = "LocalMcpEasy"
# Pre-2.0 config lived here; migrate_legacy_config_dir() copies it on upgrade.
LEGACY_APP_NAME = "NotionMcpEasy"
_VERSION_FILE = Path(__file__).resolve().parent / "VERSION"
VERSION = _VERSION_FILE.read_text(encoding="utf-8").strip() \
    if _VERSION_FILE.is_file() else "dev"
SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / APP_NAME
CONFIG_FILE = CONFIG_DIR / "config.json"
RUNTIME_FILE = CONFIG_DIR / "runtime.json"
CONNECTION_FILE = CONFIG_DIR / "connection.txt"
CONNECTIONS_FILE = CONFIG_DIR / "connections.cfg"
LEGACY_CONNECTIONS_FILE = SCRIPT_DIR / "connections.cfg"
CONNECTIONS_TEMPLATE_FILE = SCRIPT_DIR / "connections.example.cfg"
SERVER_LOG = CONFIG_DIR / "server.log"
TUNNEL_LOG = CONFIG_DIR / "tunnel.log"
URL_PATTERN = re.compile(r"https://[a-zA-Z0-9.-]+\.serveousercontent\.com")
PATH_SLOT_PATTERN = re.compile(r"PATH\[(\d+)\]$", re.IGNORECASE)
DEFAULT_CONNECTION_SLOTS = 9

AUTH_MODES = ("legacy", "oauth", "dual")
AUTH_MODE_DESCRIPTIONS = {
    "legacy": "static Bearer token only (e.g. Notion Custom MCP; 1.x behaviour)",
    "oauth": "OAuth 2.1 only (Hyperagent and other OAuth MCP clients)",
    "dual": "Bearer token AND OAuth on the same /mcp endpoint",
}
OAUTH_TEMP_URL_OVERRIDE = "MCP_OAUTH_ALLOW_TEMPORARY_URL"


def config_auth_mode(config: dict) -> str:
    mode = str(config.get("auth_mode", "legacy")).strip().lower()
    return mode if mode in AUTH_MODES else "legacy"


def config_public_url(config: dict) -> str:
    """Effective public base URL for OAuth.

    A custom stable domain (own reverse proxy / tunnel) set via ``public_url``
    takes precedence; otherwise the reserved Serveo hostname is used. Empty
    string means "no stable URL configured"."""
    custom = str(config.get("public_url", "")).strip().rstrip("/")
    if custom:
        return custom
    hostname = str(config.get("serveo_hostname", "")).strip().lower()
    if hostname:
        return f"https://{hostname}.serveousercontent.com"
    return ""


def config_uses_serveo(config: dict) -> bool:
    """Whether the launcher should manage a Serveo tunnel. A custom public_url
    means the operator runs their own tunnel/proxy, so Serveo is skipped."""
    return not str(config.get("public_url", "")).strip()


def _temporary_url_override_enabled() -> bool:
    return os.environ.get(OAUTH_TEMP_URL_OVERRIDE, "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def stable_url_policy(config: dict) -> str:
    """How the configured auth mode copes with the effective public URL.

    OAuth metadata, redirect configuration and token audience all break when
    the public URL changes on restart, so the OAuth half of the server needs a
    stable URL (a reserved Serveo hostname or a custom ``public_url``); the
    Bearer/legacy half does not. Returns one of:

    - ``"ok"``    -- safe to start: legacy mode, a stable public URL is set, or
      the temporary-URL override is enabled.
    - ``"warn"``  -- start but warn: ``dual`` on a temporary tunnel. The Bearer
      token keeps working everywhere; only the OAuth half is unstable, so the
      server still comes up (otherwise a brand-new dual install on a temporary
      tunnel could never start on the very first run).
    - ``"block"`` -- refuse to start: pure ``oauth`` on a temporary tunnel would
      publish issuer/discovery/redirect metadata and token audiences that all
      break on the next restart, leaving no working auth path at all.
    """
    mode = config_auth_mode(config)
    if mode == "legacy":
        return "ok"
    if config_public_url(config):
        return "ok"
    if _temporary_url_override_enabled():
        return "ok"
    return "block" if mode == "oauth" else "warn"


def oauth_requires_stable_hostname(config: dict) -> bool:
    """True only when the configured mode cannot run at all on a temporary URL.

    Kept for callers/tests that want the boolean question. Since 2.1.0 ``dual``
    degrades to a warning rather than a hard block, so only pure ``oauth``
    (see :func:`stable_url_policy`) truly requires a stable hostname."""
    return stable_url_policy(config) == "block"


def load_json(path: Path) -> dict:
    # utf-8-sig tolerates a UTF-8 BOM, which Windows text editors often add and
    # which would otherwise make json.loads reject an otherwise-valid file.
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def load_config_or_abort() -> dict:
    """Load config.json for setup, distinguishing MISSING from CORRUPT.

    A missing file means genuine first-time setup. A file that EXISTS but does
    not parse must NOT be treated as empty: doing so would run first-time setup,
    regenerate the token and drop the OAuth settings, breaking every connected
    client (this is exactly what happens when a hand-edit adds a stray comma or
    a Notepad BOM). Instead, abort loudly and leave the file untouched."""
    if not CONFIG_FILE.exists():
        return {}
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(
            f"ERROR: {CONFIG_FILE} exists but is not valid JSON:\n  {exc}\n\n"
            "Your settings were NOT changed and no new token was generated.\n"
            "Fix the file (a stray comma or a text-editor BOM is the usual cause),\n"
            "or delete it to run first-time setup again."
        )
    return data if isinstance(data, dict) else {}


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temp = Path(temp_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        temp.replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            temp.unlink()
        raise


def save_json(path: Path, value: dict) -> None:
    atomic_write_text(path, json.dumps(value, ensure_ascii=False, indent=2))


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


def normalize_workspace_path(value: str | Path) -> Path:
    return Path(value).expanduser().resolve()


def connections_cfg_template(menu_on: bool, paths: dict[int, str]) -> str:
    slots = sorted(set(range(1, DEFAULT_CONNECTION_SLOTS + 1)) | set(paths))
    lines = [
        "# connections.cfg — сохранённые рабочие области для Local MCP Easy",
        "#",
        "# MENU = on  -> при запуске показывать меню выбора рабочей области.",
        f"# MENU = off -> запускать сервер сразу с областью из {CONFIG_FILE}.",
        "#",
        "# PATH[n] — сохранённые варианты пути к рабочей области.",
        "# Этот файл можно редактировать вручную в любом текстовом редакторе.",
        "# Примеры:",
        r"# PATH[1] = C:\Users\you\Documents\project-one",
        r"# PATH[2] = D:\Work\project-two",
        "#",
        f"MENU = {'on' if menu_on else 'off'}",
        "",
    ]
    for slot in slots:
        lines.append(f"PATH[{slot}] = {paths.get(slot, '')}")
    return "\n".join(lines) + "\n"


def ensure_connections_cfg_exists() -> None:
    if CONNECTIONS_FILE.exists():
        return
    if LEGACY_CONNECTIONS_FILE.exists():
        text = LEGACY_CONNECTIONS_FILE.read_text(encoding="utf-8", errors="replace")
    elif CONNECTIONS_TEMPLATE_FILE.exists():
        text = CONNECTIONS_TEMPLATE_FILE.read_text(encoding="utf-8", errors="replace")
    else:
        text = connections_cfg_template(True, {})
    atomic_write_text(CONNECTIONS_FILE, text)


def load_connections_cfg() -> dict[str, object]:
    ensure_connections_cfg_exists()
    menu_on = True
    paths: dict[int, str] = {}
    text = CONNECTIONS_FILE.read_text(encoding="utf-8", errors="replace")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key.upper() == "MENU":
            menu_on = value.lower() != "off"
            continue
        match = PATH_SLOT_PATTERN.fullmatch(key)
        if match and value:
            paths[int(match.group(1))] = value
    return {"menu_on": menu_on, "paths": paths}


def save_connections_cfg(menu_on: bool, paths: dict[int, str]) -> None:
    ensure_connections_cfg_exists()
    atomic_write_text(CONNECTIONS_FILE, connections_cfg_template(menu_on, paths))


def first_free_connection_slot(paths: dict[int, str]) -> int | None:
    for slot in range(1, DEFAULT_CONNECTION_SLOTS + 1):
        if slot not in paths or not str(paths[slot]).strip():
            return slot
    return None


def find_connection_slot(paths: dict[int, str], workspace: Path) -> int | None:
    target = os.path.normcase(str(workspace))
    for slot, saved in sorted(paths.items()):
        try:
            candidate = os.path.normcase(str(normalize_workspace_path(saved)))
        except OSError:
            continue
        if candidate == target:
            return slot
    return None


def prompt_workspace_folder(prompt: str, default_workspace: Path | None = None) -> Path:
    while True:
        suffix = f" [{default_workspace}]" if default_workspace is not None else ""
        raw = input(f"{prompt}{suffix}: ").strip().strip('"')
        workspace = (
            normalize_workspace_path(raw)
            if raw
            else default_workspace.resolve() if default_workspace is not None else None
        )
        if workspace is None:
            print("Введите путь к существующей папке.")
            continue
        if workspace.is_dir():
            return workspace
        print(f"Folder does not exist: {workspace}")


def remember_workspace_path(
    workspace: Path, *, preferred_slot: int | None = None
) -> tuple[int, bool]:
    connections = load_connections_cfg()
    paths = dict(connections["paths"])
    existing_slot = find_connection_slot(paths, workspace)
    if existing_slot is not None:
        return existing_slot, False
    slot = (
        preferred_slot
        if preferred_slot is not None and preferred_slot not in paths
        else first_free_connection_slot(paths)
    )
    if slot is None:
        slot = max(paths, default=0) + 1
    paths[slot] = str(workspace)
    save_connections_cfg(bool(connections["menu_on"]), paths)
    return slot, True


def bootstrap_workspace_in_connections(config: dict) -> tuple[int | None, bool]:
    workspace_raw = str(config.get("workspace", "")).strip()
    if not workspace_raw:
        return None, False
    try:
        workspace = normalize_workspace_path(workspace_raw)
    except OSError:
        return None, False
    return remember_workspace_path(workspace, preferred_slot=1)


def choose_workspace_from_connections(config: dict) -> dict:
    slot, added = bootstrap_workspace_in_connections(config)
    if added and slot is not None:
        print(
            f"Текущая рабочая область добавлена в {CONNECTIONS_FILE} (слот {slot})."
        )
    connections = load_connections_cfg()
    paths = dict(connections["paths"])
    if not bool(connections["menu_on"]):
        return config

    current_workspace = normalize_workspace_path(config["workspace"])
    print("\n=== Меню рабочих областей Local MCP Easy ===")
    print(f"Список путей хранится в: {CONNECTIONS_FILE}")
    print(f"Текущая рабочая область из конфига: {current_workspace}")
    occupied = sorted(paths.items())
    if occupied:
        print("\nСохранённые рабочие области:")
        for slot_number, saved_path in occupied:
            marker = " (текущая)" if find_connection_slot({slot_number: saved_path}, current_workspace) == slot_number else ""
            suffix = "" if Path(saved_path).expanduser().exists() else " [папка не найдена]"
            print(f" {slot_number}. {saved_path}{marker}{suffix}")
    else:
        print("\nСохранённых рабочих областей пока нет.")
    print(" 0. Задать новую рабочую область")
    print(
        f" q. Выключить меню и запускать сервер сразу с последней областью ({current_workspace})"
    )
    print(f"Подсказка: текущая активная область сохраняется в {CONFIG_FILE}")

    while True:
        choice = input("\nВыберите пункт [Enter = оставить текущую область]: ").strip().lower()
        if not choice:
            if current_workspace.is_dir():
                print(
                    f"Оставляем текущую рабочую область без изменений: {current_workspace}.\n"
                    f"При необходимости отредактируйте {CONNECTIONS_FILE} вручную."
                )
                return config
            print("Текущая рабочая область недоступна. Выберите сохранённый слот или задайте новую папку.")
            continue
        if choice == "q":
            save_connections_cfg(False, paths)
            print(
                f"Меню отключено в {CONNECTIONS_FILE}.\n"
                f"По умолчанию остаётся рабочая область из {CONFIG_FILE}: {current_workspace}"
            )
            return config
        if not choice.isdigit():
            print("Введите номер сохранённой области, 0 для новой области или q для отключения меню.")
            continue
        selected = int(choice)
        if selected == 0:
            default_workspace = current_workspace if current_workspace.is_dir() else SCRIPT_DIR.parent.parent.resolve()
            workspace = prompt_workspace_folder("Новая рабочая область", default_workspace)
            existing_slot = find_connection_slot(paths, workspace)
            if existing_slot is not None:
                print(
                    f"Эта рабочая область уже сохранена в {CONNECTIONS_FILE} (слот {existing_slot})."
                )
            else:
                slot_number = first_free_connection_slot(paths)
                replaced = False
                if slot_number is None:
                    while True:
                        raw_slot = input(
                            "Свободных базовых слотов больше нет. Укажите номер для сохранения (можно 10 и выше): "
                        ).strip()
                        if raw_slot.isdigit() and int(raw_slot) > 0:
                            slot_number = int(raw_slot)
                            replaced = slot_number in paths
                            break
                        print("Введите положительный номер слота, например 9 или 10.")
                paths[slot_number] = str(workspace)
                save_connections_cfg(bool(connections["menu_on"]), paths)
                action = "обновлён" if replaced else "сохранён"
                print(
                    f"Новый путь {action} в {CONNECTIONS_FILE} (слот {slot_number})."
                )
            config["workspace"] = str(workspace)
            save_json(CONFIG_FILE, config)
            print(
                f"Текущая рабочая область обновлена в {CONFIG_FILE}. Сервер продолжит запуск с: {workspace}"
            )
            return config
        if selected not in paths:
            print(f"Слот {selected} пуст. Откройте {CONNECTIONS_FILE} или выберите другой пункт.")
            continue
        workspace = normalize_workspace_path(paths[selected])
        if not workspace.is_dir():
            print(
                f"Сохранённая папка из слота {selected} недоступна: {workspace}.\n"
                f"Исправьте путь в {CONNECTIONS_FILE} или задайте новую область через пункт 0."
            )
            continue
        config["workspace"] = str(workspace)
        save_json(CONFIG_FILE, config)
        print(
            f"Выбрана рабочая область из {CONNECTIONS_FILE} (слот {selected}).\n"
            f"Текущий config обновлён: {CONFIG_FILE}"
        )
        return config


def setup(force: bool = False) -> dict:
    ensure_connections_cfg_exists()
    existing = load_config_or_abort()
    if existing and not force:
        return choose_workspace_from_connections(existing)

    print(f"\n=== Local MCP Easy {VERSION}: first-time setup ===\n")
    default_workspace = (
        normalize_workspace_path(existing["workspace"])
        if existing.get("workspace")
        else SCRIPT_DIR.parent.parent.resolve()
    )
    workspace = prompt_workspace_folder("Workspace folder", default_workspace)

    print("\nFile-only mode keeps MCP file operations inside the selected workspace.")
    print("Trusted developer mode adds Python/Git/Node commands with your Windows user rights.")
    print("Those programs can access files and the network outside the workspace.")
    allow_commands = yes_no(
        "Enable trusted developer mode?", bool(existing.get("allow_commands", False))
    )

    print("\nA reserved Serveo hostname keeps the same Custom MCP URL after restarts.")
    stable_tunnel = yes_no(
        "Use a reserved Serveo hostname?", bool(existing.get("serveo_hostname"))
    )
    serveo_hostname = str(existing.get("serveo_hostname", "")).strip().lower() if stable_tunnel else ""
    ssh_key = str(existing.get("ssh_key", "")).strip() if stable_tunnel else ""
    if stable_tunnel:
        while not serveo_hostname:
            current_hostname = serveo_hostname or ""
            prompt = (
                f"Reserved hostname (without domain) [{current_hostname}]"
                if current_hostname
                else "Reserved hostname (without domain)"
            )
            raw_hostname = input(f"{prompt}: ").strip().lower()
            serveo_hostname = (raw_hostname or serveo_hostname).removesuffix(
                ".serveousercontent.com"
            )
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", serveo_hostname):
                print("Use 3-63 lowercase letters, digits or hyphens.")
                serveo_hostname = ""
        default_key = Path(ssh_key).expanduser().resolve() if ssh_key else (Path.home() / ".ssh" / "serveo_local_mcp").resolve()
        key_path = default_key
        while True:
            raw_key = input(f"Serveo private SSH key [{default_key}]: ").strip().strip('"')
            key_path = normalize_workspace_path(raw_key) if raw_key else default_key.resolve()
            if key_path.is_file():
                break
            print(f"Private key not found: {key_path}")
        ssh_key = str(key_path)

    token = str(existing.get("token", "")).strip() or secrets.token_urlsafe(32)
    # Fresh installs default to "dual" (Bearer token + OAuth 2.1 on the same
    # /mcp endpoint) so both classic token clients and OAuth clients work out of
    # the box. A reconfigure (force) of an EXISTING config preserves its current
    # effective mode: a pre-2.1 config that predates auth_mode stays "legacy",
    # so upgrading never silently switches an operator into OAuth they did not
    # choose. Owner code: server.py refuses to start in oauth/dual without one,
    # so generate it here (reusing any code already configured).
    auth_mode = config_auth_mode(existing) if existing else "dual"
    owner_code = (
        str(existing.get("oauth_owner_code", "")).strip() or secrets.token_urlsafe(9)
    )
    config = {
        "version": VERSION,
        "token": token,
        "workspace": str(workspace),
        "port": int(existing.get("port", 8765) or 8765),
        "allow_commands": allow_commands,
        "auth_mode": auth_mode,
        "oauth_owner_code": owner_code,
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
    saved_slot, added_to_connections = remember_workspace_path(workspace, preferred_slot=1)
    print(f"\nConfiguration saved in: {CONFIG_FILE}")
    if added_to_connections:
        print(f"Рабочая область сохранена в {CONNECTIONS_FILE} (слот {saved_slot}).")
    else:
        print(f"Рабочая область уже есть в {CONNECTIONS_FILE} (слот {saved_slot}).")
    print("Access token is stored in the config and reused on later launches.\n")
    if config_auth_mode(config) in ("oauth", "dual"):
        print(
            f"Auth mode: {config_auth_mode(config)} "
            "-- OAuth 2.1 is enabled alongside the Bearer token."
        )
        print("OAuth owner code (use this to approve new OAuth clients):")
        print(f"    {config['oauth_owner_code']}")
        print(
            "Keep it secret. Change the mode with OAUTH_SETUP.bat; "
            "view it later with SHOW_CONNECTION.bat --full.\n"
        )
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


TUNNEL_BACKOFF_START_SECONDS = 3.0
TUNNEL_BACKOFF_MAX_SECONDS = 300.0


def ensure_config_dir() -> None:
    """Create the per-user config directory with owner-only permissions.

    It stores the Bearer token, OAuth owner code and runtime state, so on shared
    POSIX hosts it must not be group/world readable. chmod only affects the
    POSIX mode bits; on Windows %LOCALAPPDATA% is already per-user via ACLs.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(CONFIG_DIR, 0o700)


def tunnel_backoff_delay(attempt: int) -> float:
    """Exponential reconnect backoff: 3s, 6s, 12s ... capped at 5 minutes."""
    if attempt < 1:
        return 0.0
    delay = TUNNEL_BACKOFF_START_SECONDS * (2 ** (attempt - 1))
    return min(delay, TUNNEL_BACKOFF_MAX_SECONDS)


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
    # open() (unlike pathlib.Path) does not pick a path flavour from os.name,
    # which keeps this testable when os.name is patched to "posix".
    with contextlib.suppress(OSError):
        with open(f"/proc/{pid}/cmdline", "rb") as handle:
            raw = handle.read()
        if raw:
            return raw.replace(b"\0", b" ").decode(errors="replace").strip()
    # macOS/BSD have no /proc; fall back to ps (also covers Linux PIDs whose
    # cmdline is empty, e.g. zombies or kernel threads).
    with contextlib.suppress(OSError, ValueError, subprocess.SubprocessError):
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    return ""


def pid_matches(pid: int, expected: str) -> bool:
    command_line = process_command_line(pid)
    return bool(command_line) and expected.lower() in command_line.lower()


def _wait_until_gone(pid: int, timeout: float = 5.0, interval: float = 0.1) -> bool:
    """Poll until the PID disappears or the timeout elapses; return liveness."""
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        if not pid_exists(pid):
            return True
        if time.monotonic() >= deadline:
            return not pid_exists(pid)
        time.sleep(interval)


def stop_pid(pid: int, expected: str, timeout: float = 5.0) -> bool:
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
        return _wait_until_gone(pid, timeout=timeout)
    # POSIX: request graceful shutdown, wait, then escalate to SIGKILL so a
    # wedged process cannot survive stop.
    with contextlib.suppress(OSError):
        os.kill(pid, signal.SIGTERM)
    if _wait_until_gone(pid, timeout=timeout):
        return True
    with contextlib.suppress(OSError):
        os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))
    return _wait_until_gone(pid, timeout=timeout)


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
        print("Local MCP Easy is stopped.")
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
    hostname = str(config.get("serveo_hostname", "")).strip().lower()
    auth_mode = config_auth_mode(config)
    # Prefer a custom stable domain (own proxy) over the Serveo-derived URL;
    # this is what makes MCP_PUBLIC_URL usable through the normal launcher.
    public_url = config_public_url(config)
    env.update(
        {
            "MCP_TOKEN": config["token"],
            "MCP_BASE_DIR": config["workspace"],
            "MCP_PORT": str(port),
            "MCP_ALLOW_COMMANDS": "1" if config.get("allow_commands", False) else "0",
            "MCP_ALLOWED_COMMANDS": ",".join(config.get("allowed_commands", [])),
            "MCP_SERVEO_HOSTNAME": hostname,
            "MCP_AUTH_MODE": auth_mode,
            "MCP_OAUTH_OWNER_CODE": str(config.get("oauth_owner_code", "")).strip(),
            "MCP_OAUTH_OWNER_GRANT_SCOPES": " ".join(
                config["oauth_owner_grant_scopes"]
                if isinstance(config.get("oauth_owner_grant_scopes"), list)
                else str(config.get("oauth_owner_grant_scopes", "")).split()
            ),
            "MCP_PUBLIC_URL": public_url,
            "PYTHONUNBUFFERED": "1",
        }
    )
    ensure_config_dir()
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
    ensure_config_dir()
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
    if str(config.get("public_url", "")).strip():
        tunnel_mode = "custom stable URL (own proxy)"
    elif hostname:
        tunnel_mode = f"stable ({hostname})"
    else:
        tunnel_mode = "temporary"
    auth_mode = config_auth_mode(config)
    base_url = url.rstrip("/")
    oauth_lines = ""
    oauth_prints: list[str] = []
    if auth_mode in ("oauth", "dual"):
        owner_code = str(config.get("oauth_owner_code", "")).strip()
        oauth_lines = (
            f"OAuth discovery: {base_url}/.well-known/oauth-protected-resource/mcp\n"
            f"OAuth owner code: {owner_code}\n"
        )
        oauth_prints = [
            f" OAuth discovery: {base_url}/.well-known/oauth-protected-resource/mcp",
            f" OAuth owner code: {mask_token(owner_code)} (full: SHOW_CONNECTION.bat --full)",
        ]
    CONNECTION_FILE.write_text(
        f"Local MCP Easy {VERSION}\n"
        f"URL: {endpoint}\n"
        f"Bearer token: {config['token']}\n"
        f"Workspace: {config['workspace']}\n"
        f"Mode: {mode}\n"
        f"Auth mode: {auth_mode}\n"
        f"{oauth_lines}"
        f"Tunnel: {tunnel_mode}\n",
        encoding="utf-8",
    )
    print("\n=======================================================")
    print(f" Local MCP Easy {VERSION} is running")
    print("=======================================================")
    print(f" URL: {endpoint}")
    print(f" Bearer token: {config['token']}")
    print(f" Workspace: {config['workspace']}")
    print(f" Mode: {mode}")
    print(f" Auth mode: {auth_mode}")
    for line in oauth_prints:
        print(line)
    print(f" Connection info: {CONNECTION_FILE}")
    print("=======================================================")
    print("Keep this window open. Press Ctrl+C to stop.\n")


def run() -> int:
    config = setup()
    mode = config_auth_mode(config)
    policy = stable_url_policy(config)
    if policy == "block":
        print(
            f"ERROR: auth mode '{mode}' requires a stable public URL.\n"
            "A temporary tunnel URL changes on every restart, which breaks the\n"
            "OAuth issuer, discovery metadata, redirect configuration and the\n"
            "audience of already issued tokens.\n\n"
            "Fix one of these ways:\n"
            "  1. Run SETUP.bat and configure a reserved Serveo hostname.\n"
            "  2. Run OAUTH_SETUP.bat and set a custom stable public URL\n"
            "     (your own domain / reverse proxy).\n"
            "  3. Run OAUTH_SETUP.bat and switch auth mode back to 'legacy'.\n"
            f"  4. For local experiments only: set {OAUTH_TEMP_URL_OVERRIDE}=1.",
            file=sys.stderr,
        )
        return 1
    if policy == "warn":
        print(
            f"WARNING: auth mode '{mode}' is starting on a temporary tunnel URL.\n"
            "The Bearer token works normally, so classic clients (e.g. Notion)\n"
            "can connect right away. The OAuth half is unstable on a temporary\n"
            "URL: the issuer, discovery metadata, redirects and token audience\n"
            "change whenever the tunnel URL changes, so OAuth clients may need to\n"
            "reconnect after a restart. For stable OAuth, reserve a Serveo\n"
            "hostname (SETUP.bat) or set a custom public URL (OAUTH_SETUP.bat).",
            file=sys.stderr,
        )
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

        if not config_uses_serveo(config):
            # Custom stable domain: the operator runs their own reverse proxy or
            # tunnel that maps public_url -> 127.0.0.1:port. start_server already
            # verified the server is healthy on localhost, so just publish and
            # watch the server; the launcher manages no Serveo tunnel here.
            url = config_public_url(config)
            publish_connection(config, url, server.pid, 0)
            port = int(config.get("port", 8765))
            print(
                "Custom public URL mode: ensure your reverse proxy/tunnel routes\n"
                f"  {url}  ->  http://127.0.0.1:{port}\n"
                "The launcher is not starting a Serveo tunnel."
            )
            while True:
                if server.poll() is not None:
                    raise RuntimeError(
                        f"MCP server stopped with code {server.returncode}; see {SERVER_LOG}"
                    )
                time.sleep(1)

        tunnel, lines = start_tunnel(config)
        url = resolve_tunnel_url(config, tunnel, lines)
        if not public_health_ok(url, config["token"], process=tunnel):
            raise tunnel_error(f"Public health check failed: {url}/health did not answer")
        publish_connection(config, url, server.pid, tunnel.pid)

        reconnect_attempt = 0
        while True:
            if server.poll() is not None:
                raise RuntimeError(
                    f"MCP server stopped with code {server.returncode}; see {SERVER_LOG}"
                )
            if tunnel.poll() is not None:
                reconnect_attempt += 1
                delay = tunnel_backoff_delay(reconnect_attempt)
                print(
                    f"Tunnel disconnected; reconnecting in {int(delay)} seconds "
                    f"(attempt {reconnect_attempt})..."
                )
                time.sleep(delay)
                tunnel, lines = start_tunnel(config)
                url = resolve_tunnel_url(config, tunnel, lines)
                healthy = public_health_ok(url, config["token"], process=tunnel)
                publish_connection(config, url, server.pid, tunnel.pid)
                if not healthy:
                    print(f"WARNING: {url}/health is not answering yet; keeping the tunnel up and retrying on next disconnect.")
                else:
                    reconnect_attempt = 0
                    if config.get("serveo_hostname"):
                        print("Stable Serveo tunnel restored with the same URL.")
                if not config.get("serveo_hostname"):
                    print("IMPORTANT: the tunnel URL changed. Update the MCP server URL in your client.")
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


def modify_allowed_commands(add: list[str] | None = None, remove: list[str] | None = None) -> int:
    """Safely add/remove entries in allowed_commands without hand-editing JSON.

    Hand-editing config.json is the path that broke setups (BOM / stray comma),
    so this offers a first-class, parse-safe way to do the common change, e.g.
    `launcher.py --add-command gh`."""
    config = load_config_or_abort()
    if not config:
        print("Run SETUP.bat first: no configuration exists yet.")
        return 1
    commands = list(config.get("allowed_commands", []))
    changed = False
    for name in add or []:
        name = name.strip().lower()
        if name and name not in commands:
            commands.append(name)
            changed = True
    for name in remove or []:
        name = name.strip().lower()
        if name in commands:
            commands.remove(name)
            changed = True
    if changed:
        config["allowed_commands"] = sorted(commands)
        save_json(CONFIG_FILE, config)
        print("Updated allowed_commands.")
    else:
        print("No change.")
    print("allowed_commands:", ", ".join(sorted(commands)) or "(none)")
    print("Restart the server (START.bat) for the change to take effect.")
    return 0


def migrate_legacy_config_dir() -> None:
    """One-time upgrade migration from the pre-2.0 %LOCALAPPDATA%\\NotionMcpEasy
    directory. When the new LocalMcpEasy config dir does not yet exist but the
    old one does, copy it over so the token, saved workspaces, connections.cfg
    and OAuth state survive the rename to Local MCP Easy 2.0."""
    if CONFIG_DIR.exists():
        return
    legacy_dir = CONFIG_DIR.parent / LEGACY_APP_NAME
    if not legacy_dir.is_dir():
        return
    try:
        shutil.copytree(legacy_dir, CONFIG_DIR)
        print(f"Migrated configuration from {legacy_dir} to {CONFIG_DIR}.")
    except OSError as exc:
        print(f"WARNING: could not migrate old config from {legacy_dir}: {exc}")


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
        config = load_json(CONFIG_FILE)
        for secret in (str(config.get("token", "")), str(config.get("oauth_owner_code", ""))):
            if secret:
                text = text.replace(secret, mask_token(secret))
        print(text)
        print("Secrets are masked. Use SHOW_CONNECTION.bat --full to reveal them.")
        return 0
    print(text)
    return 0


def oauth_setup() -> int:
    """Interactive wizard for the Universal auth mode (legacy/oauth/dual)."""
    config = load_json(CONFIG_FILE)
    if not config:
        print("Run SETUP.bat first: the base configuration does not exist yet.")
        return 1
    current = config_auth_mode(config)
    print(f"\n=== Local MCP Easy {VERSION}: OAuth setup ===\n")
    print(f"Current auth mode: {current}")
    for index, mode in enumerate(AUTH_MODES, start=1):
        print(f"  {index}. {mode} — {AUTH_MODE_DESCRIPTIONS[mode]}")
    choice = input(f"Select auth mode [1-{len(AUTH_MODES)}, Enter keeps '{current}']: ").strip()
    mode = current
    if choice:
        if not choice.isdigit() or not 1 <= int(choice) <= len(AUTH_MODES):
            print("Invalid selection; nothing changed.")
            return 1
        mode = AUTH_MODES[int(choice) - 1]
    config["auth_mode"] = mode

    if mode in ("oauth", "dual"):
        existing_custom = str(config.get("public_url", "")).strip()
        prompt = (
            "Custom stable public URL (own domain/reverse proxy), or Enter to use "
            "a reserved Serveo hostname"
        )
        prompt += f" [{existing_custom}]" if existing_custom else ""
        raw_custom = input(f"{prompt}: ").strip().rstrip("/")
        custom_url = raw_custom or existing_custom
        if custom_url:
            if not re.match(r"^https://[^/\s]+", custom_url) and not re.match(
                r"^http://(127\.0\.0\.1|localhost)(:\d+)?", custom_url
            ):
                print(
                    "Custom public URL must be https:// (or http://127.0.0.1 for "
                    "local testing); nothing changed."
                )
                return 1
            config["public_url"] = custom_url
            print(
                f"Custom public URL saved: {custom_url}\n"
                "You are responsible for routing that URL to 127.0.0.1:port with "
                "your own reverse proxy/tunnel; the launcher will not start Serveo."
            )
        else:
            config.pop("public_url", None)
            if not str(config.get("serveo_hostname", "")).strip():
                print(
                    "\nWARNING: OAuth needs a stable public URL. Configure a reserved\n"
                    "Serveo hostname via SETUP.bat (or set a custom public URL here)\n"
                    "before starting the server, or the launcher will refuse to start.\n"
                    f"(Local experiments only: set {OAUTH_TEMP_URL_OVERRIDE}=1.)"
                )
        owner_code = str(config.get("oauth_owner_code", "")).strip()
        if owner_code:
            if yes_no("Generate a new OAuth owner code?", False):
                owner_code = ""
        if not owner_code:
            owner_code = secrets.token_urlsafe(9)
            print("\nNew OAuth owner code (needed to approve clients on /consent):")
            print(f"  {owner_code}")
            print("It is stored in the config and shown by SHOW_CONNECTION.bat --full.")
        config["oauth_owner_code"] = owner_code
        print(
            "\nHyperagent connection summary:\n"
            "  - Add MCP server -> Streamable HTTP + OAuth\n"
            "  - Server URL: https://<hostname>.serveousercontent.com/mcp\n"
            "  - Leave 'Bring my own OAuth app' OFF for automatic registration (DCR),\n"
            "    or register a client with REGISTER_OAUTH_CLIENT.bat and enter its\n"
            "    client_id/client_secret when 'Bring my own OAuth app' is ON.\n"
            "  - Approve the request on the /consent page with the owner code."
        )
    save_json(CONFIG_FILE, config)
    print(f"\nAuth mode saved: {mode} ({CONFIG_FILE})")
    if mode == "dual":
        print("Static-token clients (e.g. Notion) keep working; OAuth clients connect in parallel.")
    elif mode == "oauth":
        print("NOTE: the Bearer token no longer works on /mcp (only /health for the launcher).")
    return 0


def register_oauth_client() -> int:
    """Pre-register an OAuth client for 'Bring my own OAuth app' flows."""
    from auth import ALL_SCOPES, LocalOAuthProvider, OAuthStore  # lazy heavy import
    from mcp.shared.auth import OAuthClientInformationFull

    config = load_json(CONFIG_FILE)
    if not config:
        print("Run SETUP.bat first: the base configuration does not exist yet.")
        return 1
    if config_auth_mode(config) == "legacy":
        print(
            "WARNING: auth mode is 'legacy'. The client will be stored, but OAuth\n"
            "is disabled until you switch the mode with OAUTH_SETUP.bat."
        )

    print(f"\n=== Local MCP Easy {VERSION}: register OAuth client ===\n")
    print("The MCP client (for example Hyperagent with 'Bring my own OAuth app')")
    print("shows a redirect/callback URL. Enter it here; several URLs are comma-separated.")
    redirect_raw = input("Redirect URI(s): ").strip()
    redirect_uris = [item.strip() for item in redirect_raw.split(",") if item.strip()]
    if not redirect_uris:
        print("At least one redirect URI is required.")
        return 1

    public_client = yes_no("Public client with PKCE and no client secret?", True)
    scopes_raw = input(f"Scopes [{' '.join(ALL_SCOPES)}]: ").strip()
    scopes = scopes_raw.split() if scopes_raw else list(ALL_SCOPES)
    unknown = [scope for scope in scopes if scope not in ALL_SCOPES]
    if unknown:
        print(f"Unknown scopes: {', '.join(unknown)}")
        return 1

    client_id = "byo-" + secrets.token_urlsafe(8)
    client_secret = None if public_client else secrets.token_hex(32)
    client = OAuthClientInformationFull(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uris=redirect_uris,
        token_endpoint_auth_method="none" if public_client else "client_secret_post",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope=" ".join(scopes),
        client_name="Manually registered client (BYO)",
    )
    try:
        LocalOAuthProvider.validate_redirect_uris(client)
    except Exception as exc:
        detail = getattr(exc, "error_description", None) or str(exc)
        print(f"Invalid redirect URI: {detail}")
        return 1

    store = OAuthStore(CONFIG_DIR / "oauth_state.json")
    store.clients[client.client_id] = client.model_dump(mode="json")
    store.save()

    print("\nClient registered. Enter these values in the MCP client:")
    print(f"  client_id: {client_id}")
    if client_secret:
        print(f"  client_secret: {client_secret}")
    else:
        print("  client_secret: (none — public client with PKCE)")
    print(f"  scopes: {' '.join(scopes)}")
    print(f"Stored in: {store.state_file}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"One-click launcher for Local MCP Easy {VERSION}"
    )
    parser.add_argument("--setup", action="store_true", help="run the setup wizard again")
    parser.add_argument("--stop", action="store_true", help="stop background processes")
    parser.add_argument("--show", action="store_true", help="show current connection details")
    parser.add_argument(
        "--full", action="store_true", help="with --show: reveal the full Bearer token"
    )
    parser.add_argument(
        "--oauth", action="store_true", help="configure auth mode (legacy/oauth/dual)"
    )
    parser.add_argument(
        "--register-oauth-client",
        action="store_true",
        help="pre-register an OAuth client (Bring my own OAuth app)",
    )
    parser.add_argument(
        "--add-command",
        action="append",
        metavar="NAME",
        help="safely add a program to allowed_commands (repeatable), e.g. gh",
    )
    parser.add_argument(
        "--remove-command",
        action="append",
        metavar="NAME",
        help="safely remove a program from allowed_commands (repeatable)",
    )
    args = parser.parse_args()

    migrate_legacy_config_dir()

    if args.add_command or args.remove_command:
        return modify_allowed_commands(add=args.add_command, remove=args.remove_command)

    if args.stop:
        stop_all()
        return 0
    if args.setup:
        stop_all()
        setup(force=True)
        return 0
    if args.oauth:
        stop_all()
        return oauth_setup()
    if args.register_oauth_client:
        return register_oauth_client()
    if args.show:
        return show_connection(args.full)
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
