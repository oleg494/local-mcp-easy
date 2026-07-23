import os
import sys
import time
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
os.environ["MCP_TOKEN"] = "unit-test-token"
os.environ["MCP_BASE_DIR"] = str(PROJECT)
os.environ["MCP_ALLOW_COMMANDS"] = "0"
os.environ["MCP_SERVEO_HOSTNAME"] = ""
os.environ["MCP_AUTH_MODE"] = "legacy"

import server


def _touch(path: Path, mtime: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"orphan")
    os.utime(path, (mtime, mtime))


class OrphanMcpTmpCleanupTests(unittest.TestCase):
    def setUp(self):
        self._tmp_base = Path(PROJECT / "temp-orphan-base").resolve()
        self._tmp_base.mkdir(parents=True, exist_ok=True)
        self._orig_base_dir = server.BASE_DIR
        server.BASE_DIR = self._tmp_base
        # Force the monotonic throttle to consider a sweep overdue.
        server._last_orphan_sweep = float("-inf")

    def tearDown(self):
        server.BASE_DIR = self._orig_base_dir
        server._last_orphan_sweep = float("-inf")
        import shutil

        shutil.rmtree(self._tmp_base, ignore_errors=True)

    def test_stale_mcp_tmp_is_removed(self):
        stale_age = server.TEMP_FILE_TTL_SECONDS * 2
        cutoff = time.time() - stale_age
        stale = self._tmp_base / "stale.txt.abcdef.mcp-tmp"
        _touch(stale, cutoff)
        self.assertTrue(stale.exists())
        server._cleanup_orphan_mcp_tmp()
        self.assertFalse(stale.exists(), "stale .mcp-tmp orphan should be removed")

    def test_fresh_mcp_tmp_survives(self):
        fresh = self._tmp_base / "fresh.txt.qwerty.mcp-tmp"
        _touch(fresh, time.time())
        server._cleanup_orphan_mcp_tmp()
        self.assertTrue(fresh.exists(), "fresh .mcp-tmp should survive cleanup")

    def test_normal_txt_past_ttl_removed_by_cleanup_temp_files(self):
        # Regression guard: _cleanup_temp_files still sweeps temp/*.txt.
        stale_age = server.TEMP_FILE_TTL_SECONDS * 2
        cutoff = time.time() - stale_age
        temp_dir = server._temp_dir()
        stale_txt = temp_dir / "stale-regression.txt"
        stale_txt.write_bytes(b"old")
        os.utime(stale_txt, (cutoff, cutoff))
        server._cleanup_temp_files()
        self.assertFalse(stale_txt.exists(), "stale .txt should be removed by _cleanup_temp_files")


if __name__ == "__main__":
    unittest.main()
