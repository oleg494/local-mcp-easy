import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
RELEASE_DIR = ROOT / "release"
OUTPUT = RELEASE_DIR / f"local-mcp-easy-{VERSION}.zip"
EXCLUDED_DIRS = {".git", ".venv", ".venv-linux", "__pycache__", ".pytest_cache", ".ruff_cache", "temp", "release"}
EXCLUDED_SUFFIXES = {".log", ".pyc", ".zip"}
EXCLUDED_FILES = {"connection.txt", "connections.cfg", "runtime.json", "config.json", "oauth_state.json", "agent-repo-instructions.local.md", "agent-repo-config.local.json"}


def included_files():
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in EXCLUDED_DIRS for part in relative.parts):
            continue
        if (
            path.name in EXCLUDED_FILES
            or path.suffix.lower() in EXCLUDED_SUFFIXES
            or path.name.endswith(".local.json")
            or path.name.endswith(".local.md")
        ):
            continue
        yield path, Path(f"local-mcp-easy-{VERSION}") / relative


def main() -> int:
    RELEASE_DIR.mkdir(exist_ok=True)
    OUTPUT.unlink(missing_ok=True)
    files = list(included_files())
    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for source, destination in files:
            archive.write(source, destination)
    print(f"Created: {OUTPUT}")
    print(f"Release dir: {RELEASE_DIR}")
    print(f"Files: {len(files)}")
    print(f"Size: {OUTPUT.stat().st_size:,} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
