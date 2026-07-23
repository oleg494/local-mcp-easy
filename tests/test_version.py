import os
import sys
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
os.environ["MCP_TOKEN"] = "unit-test-token"
os.environ["MCP_BASE_DIR"] = str(PROJECT)
os.environ["MCP_ALLOW_COMMANDS"] = "0"
os.environ["MCP_SERVEO_HOSTNAME"] = ""
os.environ["MCP_AUTH_MODE"] = "legacy"

import launcher
import server

EXPECTED_VERSION = "2.3.0"


class VersionConsistencyTests(unittest.TestCase):
    """§6: VERSION must stay byte-exact CRLF (the invariant the 2.1.1 fix
    restored) and launcher/server must read the same version."""

    def test_version_file_is_crlf_byte_exact(self):
        self.assertEqual(
            (PROJECT / "VERSION").read_bytes(),
            EXPECTED_VERSION.encode("ascii") + b"\r\n",
        )

    def test_launcher_and_server_versions_agree(self):
        self.assertEqual(launcher.VERSION, EXPECTED_VERSION)
        self.assertEqual(server.SERVER_VERSION, EXPECTED_VERSION)
        self.assertEqual(launcher.VERSION, server.SERVER_VERSION)


if __name__ == "__main__":
    unittest.main()
