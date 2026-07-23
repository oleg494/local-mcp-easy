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

import server


class ProcessCaptureRemovalTests(unittest.TestCase):
    def test_dead_capture_process_function_is_removed(self):
        # The un-bounded _capture_process helper is dead code (zero live
        # callers in server.py); only _capture_process_to_files is used by
        # run_command and background jobs. The dead symbol must be gone.
        self.assertFalse(
            hasattr(server, "_capture_process"),
            "_capture_process should have been deleted as dead code",
        )
        self.assertNotIn("_capture_process", dir(server))

    def test_capture_process_to_files_still_exists(self):
        # Regression guard: we only deleted the dead helper, not the live
        # capture path used by run_command and background jobs.
        self.assertTrue(hasattr(server, "_capture_process_to_files"))
        self.assertIn("_capture_process_to_files", dir(server))


if __name__ == "__main__":
    unittest.main()
