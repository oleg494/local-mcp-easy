import logging
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

import launcher
import server


class MakeLogWriterTests(unittest.TestCase):
    def test_writer_rotates_when_output_exceeds_max_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "server.log"
            writer = launcher.make_log_writer(path, max_bytes=200, backups=2)
            try:
                for i in range(200):
                    writer.info(f"line {i:04d} " + "x" * 40)
            finally:
                for handler in list(writer.handlers):
                    handler.close()
            self.assertTrue(path.exists())
            # Active file is bounded near max_bytes (a single record may overshoot).
            self.assertLessEqual(path.stat().st_size, 400)
            # Rotation actually happened: at least one backup was produced.
            self.assertTrue((Path(tmp) / "server.log.1").exists())

    def test_writer_does_not_leak_handlers_across_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tunnel.log"
            first = launcher.make_log_writer(path)
            second = launcher.make_log_writer(path)
            try:
                # Same named logger reused, old handler closed and replaced
                # (no file-descriptor leak on tunnel reconnect).
                self.assertIs(first, second)
                self.assertEqual(len(second.handlers), 1)
            finally:
                for handler in list(second.handlers):
                    handler.close()


class ConfigureLoggingTests(unittest.TestCase):
    def test_streamable_http_session_noise_is_silenced(self):
        noisy = logging.getLogger("mcp.server.streamable_http")
        noisy.setLevel(logging.NOTSET)
        server._configure_logging()
        self.assertEqual(noisy.getEffectiveLevel(), logging.WARNING)

    def test_uvicorn_access_logs_are_left_untouched(self):
        access = logging.getLogger("uvicorn.access")
        access.setLevel(logging.NOTSET)
        server._configure_logging()
        # Access logs help diagnose transport drops; we must not pin their level.
        self.assertEqual(access.level, logging.NOTSET)


if __name__ == "__main__":
    unittest.main()
