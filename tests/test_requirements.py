"""Guard the pinned dependencies for release 2.3.0 (§1).

The release pins `mcp` exactly (no `[cli]` extra — the launcher/server never
invoke the `mcp` CLI binary) and keeps uvicorn/starlette pinned. This test was
written first (TDD) and failed on the pre-2.3.0 line `mcp[cli]==1.26.0`.
"""
import re
import unittest
from pathlib import Path

REQUIREMENTS = Path(__file__).resolve().parents[1] / "requirements.txt"


def _lines():
    # utf-8-sig tolerates an editor BOM (mirrors the project's config reads).
    text = REQUIREMENTS.read_text(encoding="utf-8-sig")
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def _line_for(name):
    """The requirements line whose package name is `name` (extras-aware), or ''."""
    for ln in _lines():
        # "mcp[cli]==1.26.0" -> pkg "mcp"; "uvicorn==0.41.0" -> "uvicorn"
        pkg = re.split(r"[\[<>=!~\s]", ln, 1)[0]
        if pkg == name:
            return ln
    return ""


def _spec(line):
    """Version specifier of a line, e.g. 'mcp[cli]==1.26.0' -> '==1.26.0'."""
    if not line:
        return ""
    return re.sub(r"^[A-Za-z0-9_.\-]+(\[[^\]]*\])?", "", line).strip()


class RequirementsTests(unittest.TestCase):
    def test_mcp_pinned_without_cli_extra(self):
        """mcp must be an exact pin (==X.Y.Z) and must not carry the [cli] extra.

        2.3.0 ships `mcp==1.27.2`. The launcher/server never invoke the `mcp`
        CLI, so the `[cli]` extra only pulled unused deps (typer, dotenv).
        """
        mcp = _line_for("mcp")
        self.assertTrue(mcp, "no mcp line in requirements.txt")
        self.assertNotIn("[cli]", mcp, f"mcp still carries the [cli] extra: {mcp!r}")
        spec = _spec(mcp)
        self.assertTrue(re.fullmatch(r"==\s*\d[\w.]*", spec),
                        f"mcp must be an exact pin (==X.Y.Z), got spec {spec!r} from {mcp!r}")
        ver = spec.split("==", 1)[1].strip()
        major, minor = int(ver.split(".")[0]), int(ver.split(".")[1])
        self.assertGreaterEqual((major, minor), (1, 27),
                                f"mcp pin {ver} is below the 1.27 target for 2.3.0")

    def test_http_stack_pinned(self):
        """uvicorn and starlette stay exactly pinned (floating invites drift)."""
        for name in ("uvicorn", "starlette"):
            line = _line_for(name)
            self.assertTrue(line, f"no {name} line in requirements.txt")
            spec = _spec(line)
            self.assertTrue(re.fullmatch(r"==\s*\d[\w.]*", spec),
                            f"{name} must be an exact pin (==X.Y.Z), got spec {spec!r} from {line!r}")


if __name__ == "__main__":
    unittest.main()
