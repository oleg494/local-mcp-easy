import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

import core
import launcher


class AllowedCommandsSingleSourceTests(unittest.TestCase):
    """§4e: launcher must source the allowed-commands set from
    core.DEFAULT_ALLOWED_COMMANDS instead of duplicating the literal."""

    def test_launcher_imports_default_allowed_commands_from_core(self):
        # The module-level namespace must expose the imported symbol so there is
        # one source of truth in core.py rather than a duplicated literal.
        self.assertIn("DEFAULT_ALLOWED_COMMANDS", dir(launcher))
        self.assertIs(
            launcher.DEFAULT_ALLOWED_COMMANDS, core.DEFAULT_ALLOWED_COMMANDS
        )

    def test_setup_writes_sorted_core_default_allowed_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace-one"
            workspace.mkdir()
            config_file = root / "config.json"
            connections_file = root / "connections.cfg"
            with (
                mock.patch.object(launcher, "CONFIG_FILE", config_file),
                mock.patch.object(launcher, "CONNECTIONS_FILE", connections_file),
                mock.patch("launcher.input", side_effect=[str(workspace)]),
                mock.patch("launcher.yes_no", side_effect=[False, False]),
            ):
                launcher.setup(force=True)
            stored = json.loads(config_file.read_text(encoding="utf-8"))
            self.assertEqual(
                stored["allowed_commands"],
                sorted(core.DEFAULT_ALLOWED_COMMANDS),
            )


if __name__ == "__main__":
    unittest.main()
