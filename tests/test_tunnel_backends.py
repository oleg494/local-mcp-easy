import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
os.environ["MCP_TOKEN"] = "unit-test-token"
os.environ["MCP_BASE_DIR"] = str(PROJECT)
os.environ["MCP_ALLOW_COMMANDS"] = "0"
os.environ["MCP_SERVEO_HOSTNAME"] = ""
os.environ["MCP_AUTH_MODE"] = "legacy"

import launcher
import server


class TunnelBackendConfigTests(unittest.TestCase):
    """sish tunnel-backend: config helpers derive the right public URL and
    tunnel-management decision without breaking the Serveo defaults."""

    def test_backend_defaults_to_serveo_and_normalizes(self):
        self.assertEqual(launcher.config_tunnel_backend({}), "serveo")
        self.assertEqual(
            launcher.config_tunnel_backend({"tunnel_backend": "SISH"}), "sish"
        )
        self.assertEqual(
            launcher.config_tunnel_backend({"tunnel_backend": "bogus"}), "serveo"
        )

    def test_public_url_serveo_unchanged(self):
        self.assertEqual(
            launcher.config_public_url({"serveo_hostname": "h"}),
            "https://h.serveousercontent.com",
        )

    def test_public_url_sish_derived_from_domain(self):
        cfg = {
            "tunnel_backend": "sish",
            "serveo_hostname": "mymcp",
            "tunnel_domain": "tunnel.example.com",
        }
        self.assertEqual(
            launcher.config_public_url(cfg), "https://mymcp.tunnel.example.com"
        )

    def test_public_url_sish_needs_subdomain_and_domain(self):
        self.assertEqual(
            launcher.config_public_url(
                {"tunnel_backend": "sish", "serveo_hostname": "mymcp"}
            ),
            "",
        )

    def test_custom_public_url_wins_over_backend(self):
        cfg = {
            "tunnel_backend": "sish",
            "serveo_hostname": "mymcp",
            "tunnel_domain": "tunnel.example.com",
            "public_url": "https://mcp.example.com/",
        }
        self.assertEqual(launcher.config_public_url(cfg), "https://mcp.example.com")

    def test_uses_serveo_true_for_sish_false_for_custom_ssh(self):
        self.assertTrue(
            launcher.config_uses_serveo({"tunnel_backend": "sish"})
        )
        self.assertFalse(
            launcher.config_uses_serveo({"tunnel_backend": "custom-ssh"})
        )
        self.assertFalse(
            launcher.config_uses_serveo({"public_url": "https://mcp.example.com"})
        )

    def test_process_match_tracks_backend(self):
        self.assertEqual(launcher.tunnel_process_match({}), "serveo.net")
        self.assertEqual(
            launcher.tunnel_process_match(
                {"tunnel_backend": "sish", "tunnel_host": "tunnel.example.com"}
            ),
            "tunnel.example.com",
        )


class SishTunnelCommandTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.key = Path(self._tmp.name).resolve() / "sish_key"
        self.key.write_text("KEY", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def _cfg(self, **extra):
        cfg = {
            "port": 8765,
            "tunnel_backend": "sish",
            "tunnel_host": "tunnel.example.com",
            "tunnel_domain": "tunnel.example.com",
            "serveo_hostname": "mymcp",
            "ssh_key": str(self.key),
        }
        cfg.update(extra)
        return cfg

    @mock.patch.object(launcher.shutil, "which", return_value="ssh")
    def test_sish_command_uses_ssh_remote_forward(self, _which):
        command = launcher.build_tunnel_command(self._cfg(tunnel_ssh_port="2222"))
        self.assertEqual(command[0], "ssh")
        self.assertIn("-R", command)
        self.assertIn("mymcp:80:127.0.0.1:8765", command)
        # Last arg is the sish host (mirrors Serveo's trailing 'serveo.net').
        self.assertEqual(command[-1], "tunnel.example.com")
        self.assertIn("-i", command)
        self.assertIn(str(self.key), command)
        self.assertIn("-p", command)
        self.assertIn("2222", command)

    @mock.patch.object(launcher.shutil, "which", return_value="ssh")
    def test_sish_requires_tunnel_host(self, _which):
        with self.assertRaisesRegex(RuntimeError, "tunnel_host"):
            launcher.build_tunnel_command(self._cfg(tunnel_host=""))

    @mock.patch.object(launcher.shutil, "which", return_value="ssh")
    def test_sish_requires_existing_key(self, _which):
        with self.assertRaisesRegex(RuntimeError, "key not found"):
            launcher.build_tunnel_command(self._cfg(ssh_key=str(self.key) + "-missing"))

    def test_resolve_url_sish_returns_derived_url(self):
        process = mock.Mock()
        process.poll.return_value = None
        url = launcher.resolve_tunnel_url(
            self._cfg(), process, mock.Mock(), startup_grace=0
        )
        self.assertEqual(url, "https://mymcp.tunnel.example.com")

    def test_resolve_url_sish_without_stable_url_raises(self):
        process = mock.Mock()
        process.poll.return_value = None
        with self.assertRaises(RuntimeError):
            launcher.resolve_tunnel_url(
                {"tunnel_backend": "sish", "tunnel_host": "t"},
                process,
                mock.Mock(),
                startup_grace=0,
            )


class HostAllowlistTests(unittest.TestCase):
    """A configured public host must be allowed even in legacy/Bearer mode so a
    self-hosted sish (or custom proxy) domain reaches the server."""

    def test_public_host_allowed_without_oauth(self):
        with (
            mock.patch.object(server, "PUBLIC_HOST", "mymcp.tunnel.example.com"),
            mock.patch.object(server, "OAUTH_ENABLED", False),
        ):
            self.assertTrue(server._host_allowed("mymcp.tunnel.example.com"))
            self.assertTrue(server._host_allowed("mymcp.tunnel.example.com:443"))
            self.assertFalse(server._host_allowed("evil.example.com"))

    def test_localhost_always_allowed(self):
        self.assertTrue(server._host_allowed("127.0.0.1"))
        self.assertTrue(server._host_allowed("localhost:8765"))


class TunnelSetupWizardTests(unittest.TestCase):
    def test_sish_wizard_writes_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            config_file = root / "config.json"
            config_file.write_text(
                json.dumps({"token": "t", "port": 8765}), encoding="utf-8"
            )
            key = root / "sish_key"
            key.write_text("KEY", encoding="utf-8")
            inputs = [
                "2",  # select backend -> sish
                "tunnel.example.com",  # tunnel_host
                "",  # ssh port (blank)
                "tunnel.example.com",  # public wildcard domain
                "mymcp",  # reserved subdomain
                str(key),  # private key path
            ]
            with (
                mock.patch.object(launcher, "CONFIG_FILE", config_file),
                mock.patch("launcher.input", side_effect=inputs),
            ):
                rc = launcher.tunnel_setup()
            self.assertEqual(rc, 0)
            stored = json.loads(config_file.read_text(encoding="utf-8"))
            self.assertEqual(stored["tunnel_backend"], "sish")
            self.assertEqual(stored["tunnel_host"], "tunnel.example.com")
            self.assertEqual(stored["tunnel_domain"], "tunnel.example.com")
            self.assertEqual(stored["serveo_hostname"], "mymcp")
            self.assertEqual(stored["ssh_key"], str(key))
            self.assertEqual(
                launcher.config_public_url(stored),
                "https://mymcp.tunnel.example.com",
            )


if __name__ == "__main__":
    unittest.main()
