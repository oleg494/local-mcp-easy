import json
import os
import queue
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

import launcher


class LauncherTests(unittest.TestCase):
    def test_current_pid_exists(self):
        self.assertTrue(launcher.pid_exists(os.getpid()))

    def test_connections_cfg_is_created_with_menu_and_slots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            connections_file = root / "connections.cfg"
            with mock.patch.object(launcher, "CONNECTIONS_FILE", connections_file):
                launcher.ensure_connections_cfg_exists()
                text = connections_file.read_text(encoding="utf-8")
            self.assertIn("MENU = on", text)
            self.assertIn("PATH[1] =", text)
            self.assertIn("PATH[9] =", text)

    def test_connections_cfg_migrates_from_release_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            connections_file = root / "local" / "connections.cfg"
            legacy_file = root / "release" / "connections.cfg"
            legacy_file.parent.mkdir()
            legacy_file.write_text("MENU = off\nPATH[1] = D:\\Work\\project\n", encoding="utf-8")
            with (
                mock.patch.object(launcher, "CONNECTIONS_FILE", connections_file),
                mock.patch.object(launcher, "LEGACY_CONNECTIONS_FILE", legacy_file),
                mock.patch.object(launcher, "CONNECTIONS_TEMPLATE_FILE", root / "missing.example.cfg"),
            ):
                launcher.ensure_connections_cfg_exists()
                saved = launcher.load_connections_cfg()
            self.assertFalse(saved["menu_on"])
            self.assertEqual(saved["paths"][1], r"D:\Work\project")
            self.assertTrue(connections_file.is_file())

    def test_setup_saves_first_workspace_to_first_slot(self):
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
                config = launcher.setup(force=False)
                saved = launcher.load_connections_cfg()
            self.assertEqual(config["workspace"], str(workspace.resolve()))
            self.assertEqual(saved["paths"][1], str(workspace.resolve()))

    def test_start_menu_switches_to_saved_workspace_without_changing_token(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace_one = root / "workspace-one"
            workspace_two = root / "workspace-two"
            workspace_one.mkdir()
            workspace_two.mkdir()
            config_file = root / "config.json"
            connections_file = root / "connections.cfg"
            config = {
                "token": "fixed-token",
                "workspace": str(workspace_one.resolve()),
                "port": 8765,
            }
            config_file.write_text(json.dumps(config), encoding="utf-8")
            with (
                mock.patch.object(launcher, "CONFIG_FILE", config_file),
                mock.patch.object(launcher, "CONNECTIONS_FILE", connections_file),
            ):
                launcher.save_connections_cfg(
                    True,
                    {1: str(workspace_one.resolve()), 2: str(workspace_two.resolve())},
                )
                with mock.patch("launcher.input", side_effect=["2"]):
                    updated = launcher.setup(force=False)
            self.assertEqual(updated["workspace"], str(workspace_two.resolve()))
            self.assertEqual(updated["token"], "fixed-token")
            stored = json.loads(config_file.read_text(encoding="utf-8"))
            self.assertEqual(stored["workspace"], str(workspace_two.resolve()))

    def test_start_menu_can_save_new_workspace_to_free_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace_one = root / "workspace-one"
            workspace_two = root / "workspace-two"
            workspace_one.mkdir()
            workspace_two.mkdir()
            config_file = root / "config.json"
            connections_file = root / "connections.cfg"
            config = {
                "token": "fixed-token",
                "workspace": str(workspace_one.resolve()),
                "port": 8765,
            }
            config_file.write_text(json.dumps(config), encoding="utf-8")
            with (
                mock.patch.object(launcher, "CONFIG_FILE", config_file),
                mock.patch.object(launcher, "CONNECTIONS_FILE", connections_file),
            ):
                launcher.save_connections_cfg(True, {1: str(workspace_one.resolve())})
                with mock.patch("launcher.input", side_effect=["0", str(workspace_two)]):
                    updated = launcher.setup(force=False)
                saved = launcher.load_connections_cfg()
            self.assertEqual(updated["workspace"], str(workspace_two.resolve()))
            self.assertEqual(saved["paths"][2], str(workspace_two.resolve()))

    def test_start_menu_can_extend_slots_beyond_nine(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current_workspace = root / "workspace-current"
            new_workspace = root / "workspace-new"
            current_workspace.mkdir()
            new_workspace.mkdir()
            config_file = root / "config.json"
            connections_file = root / "connections.cfg"
            config = {
                "token": "fixed-token",
                "workspace": str(current_workspace.resolve()),
                "port": 8765,
            }
            config_file.write_text(json.dumps(config), encoding="utf-8")
            occupied = {}
            for index in range(1, 10):
                path = root / f"saved-{index}"
                path.mkdir()
                occupied[index] = str(path.resolve())
            occupied[1] = str(current_workspace.resolve())
            with (
                mock.patch.object(launcher, "CONFIG_FILE", config_file),
                mock.patch.object(launcher, "CONNECTIONS_FILE", connections_file),
            ):
                launcher.save_connections_cfg(True, occupied)
                with mock.patch("launcher.input", side_effect=["0", str(new_workspace), "10"]):
                    updated = launcher.setup(force=False)
                saved = launcher.load_connections_cfg()
            self.assertEqual(updated["workspace"], str(new_workspace.resolve()))
            self.assertEqual(saved["paths"][10], str(new_workspace.resolve()))

    def test_start_menu_can_disable_itself(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace_one = root / "workspace-one"
            workspace_one.mkdir()
            config_file = root / "config.json"
            connections_file = root / "connections.cfg"
            config = {
                "token": "fixed-token",
                "workspace": str(workspace_one.resolve()),
                "port": 8765,
            }
            config_file.write_text(json.dumps(config), encoding="utf-8")
            with (
                mock.patch.object(launcher, "CONFIG_FILE", config_file),
                mock.patch.object(launcher, "CONNECTIONS_FILE", connections_file),
            ):
                launcher.save_connections_cfg(True, {1: str(workspace_one.resolve())})
                with mock.patch("launcher.input", side_effect=["q"]):
                    updated = launcher.setup(force=False)
                saved = launcher.load_connections_cfg()
            self.assertEqual(updated["workspace"], str(workspace_one.resolve()))
            self.assertFalse(saved["menu_on"])

    def test_missing_pid_does_not_exist(self):
        self.assertFalse(launcher.pid_exists(99_999_999))

    def test_occupied_port_is_detected(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            self.assertTrue(launcher.port_is_open(port))

    def test_free_port_is_not_reported_as_open(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        self.assertFalse(launcher.port_is_open(port))

    @mock.patch("launcher.shutil.which", return_value="ssh.exe")
    def test_temporary_tunnel_command(self, _which):
        command = launcher.build_tunnel_command({"port": 8765})
        self.assertIn("80:127.0.0.1:8765", command)
        # BatchMode must stay OFF here: Serveo anonymous auth is keyboard-interactive.
        self.assertNotIn("BatchMode=yes", command)
        self.assertNotIn("-i", command)

    @mock.patch("launcher.shutil.which", return_value="ssh.exe")
    def test_stable_tunnel_command(self, _which):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "serveo_key"
            key.write_text("test", encoding="utf-8")
            command = launcher.build_tunnel_command(
                {
                    "port": 8765,
                    "serveo_hostname": "my-notion-mcp",
                    "ssh_key": str(key),
                }
            )
        self.assertIn("-i", command)
        # Serveo needs keyboard-interactive even with a registered key.
        self.assertNotIn("BatchMode=yes", command)
        self.assertIn("IdentitiesOnly=yes", command)
        self.assertIn("my-notion-mcp:80:127.0.0.1:8765", command)

    def test_stable_url_does_not_require_ssh_output(self):
        class RunningProcess:
            returncode = None

            @staticmethod
            def poll():
                return None

        url = launcher.resolve_tunnel_url(
            {"serveo_hostname": "my-notion-mcp"},
            RunningProcess(),
            queue.Queue(),
            startup_grace=0,
        )
        self.assertEqual(
            url, "https://my-notion-mcp.serveousercontent.com"
        )

    def test_stable_url_reports_early_ssh_failure(self):
        class FailedProcess:
            returncode = 255

            @staticmethod
            def poll():
                return 255

        with self.assertRaisesRegex(RuntimeError, "SSH tunnel exited with code 255"):
            launcher.resolve_tunnel_url(
                {"serveo_hostname": "my-notion-mcp"},
                FailedProcess(),
                queue.Queue(),
                startup_grace=0,
            )

    @mock.patch("launcher.wait_for_url", return_value="https://temporary.serveousercontent.com")
    def test_temporary_url_still_uses_ssh_announcement(self, wait_for_url):
        process = mock.Mock()
        lines = queue.Queue()
        url = launcher.resolve_tunnel_url({}, process, lines)
        self.assertEqual(url, "https://temporary.serveousercontent.com")
        wait_for_url.assert_called_once_with(process, lines)

    def test_mask_token(self):
        self.assertEqual(launcher.mask_token("abcdEFGHijklMNOP"), "abcd...MNOP")
        self.assertEqual(launcher.mask_token("short"), "*****")

    def test_public_health_fails_fast_on_unreachable_url(self):
        self.assertFalse(
            launcher.public_health_ok(
                "http://127.0.0.1:1/", "token", attempts=1, delay=0
            )
        )

    @mock.patch("launcher.urllib.request.urlopen")
    def test_public_health_accepts_ok_payload(self, urlopen):
        response = mock.MagicMock()
        response.status = 200
        response.read.return_value = b'{"status": "ok"}'
        urlopen.return_value.__enter__.return_value = response
        self.assertTrue(
            launcher.public_health_ok(
                "https://x.serveousercontent.com", "token", attempts=1, delay=0
            )
        )


class OAuthLauncherTests(unittest.TestCase):
    def setUp(self):
        self._env = mock.patch.dict(os.environ)
        self._env.start()
        os.environ.pop(launcher.OAUTH_TEMP_URL_OVERRIDE, None)

    def tearDown(self):
        self._env.stop()

    def test_config_auth_mode_defaults_to_legacy(self):
        self.assertEqual(launcher.config_auth_mode({}), "legacy")
        self.assertEqual(launcher.config_auth_mode({"auth_mode": "DUAL"}), "dual")
        self.assertEqual(launcher.config_auth_mode({"auth_mode": "bogus"}), "legacy")

    def test_oauth_modes_require_stable_hostname(self):
        self.assertFalse(
            launcher.oauth_requires_stable_hostname({"auth_mode": "legacy"})
        )
        self.assertTrue(launcher.oauth_requires_stable_hostname({"auth_mode": "oauth"}))
        self.assertTrue(launcher.oauth_requires_stable_hostname({"auth_mode": "dual"}))
        self.assertFalse(
            launcher.oauth_requires_stable_hostname(
                {"auth_mode": "oauth", "serveo_hostname": "my-host"}
            )
        )

    def test_temporary_url_override_allows_local_experiments(self):
        os.environ[launcher.OAUTH_TEMP_URL_OVERRIDE] = "1"
        self.assertFalse(
            launcher.oauth_requires_stable_hostname({"auth_mode": "oauth"})
        )

    def test_run_blocks_oauth_mode_without_stable_hostname(self):
        config = {"auth_mode": "oauth", "token": "t", "workspace": "w", "port": 1}
        with mock.patch("launcher.setup", return_value=config):
            self.assertEqual(launcher.run(), 1)

    def test_oauth_setup_generates_owner_code(self):
        with tempfile.TemporaryDirectory() as directory:
            config_file = Path(directory) / "config.json"
            config_file.write_text(
                json.dumps(
                    {
                        "token": "t",
                        "workspace": directory,
                        "port": 8765,
                        "serveo_hostname": "stable-host",
                    }
                ),
                encoding="utf-8",
            )
            with (
                mock.patch.object(launcher, "CONFIG_FILE", config_file),
                mock.patch("launcher.input", side_effect=["2"]),
            ):
                self.assertEqual(launcher.oauth_setup(), 0)
            saved = json.loads(config_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["auth_mode"], "oauth")
            self.assertGreaterEqual(len(saved["oauth_owner_code"]), 10)

    def test_oauth_setup_keeps_current_mode_on_enter(self):
        with tempfile.TemporaryDirectory() as directory:
            config_file = Path(directory) / "config.json"
            config_file.write_text(
                json.dumps({"token": "t", "workspace": directory, "port": 8765}),
                encoding="utf-8",
            )
            with (
                mock.patch.object(launcher, "CONFIG_FILE", config_file),
                mock.patch("launcher.input", side_effect=[""]),
            ):
                self.assertEqual(launcher.oauth_setup(), 0)
            saved = json.loads(config_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["auth_mode"], "legacy")
            self.assertNotIn("oauth_owner_code", saved)

    def test_oauth_setup_keeps_existing_owner_code(self):
        with tempfile.TemporaryDirectory() as directory:
            config_file = Path(directory) / "config.json"
            config_file.write_text(
                json.dumps(
                    {
                        "token": "t",
                        "workspace": directory,
                        "port": 8765,
                        "serveo_hostname": "stable-host",
                        "auth_mode": "dual",
                        "oauth_owner_code": "existing-owner-code",
                    }
                ),
                encoding="utf-8",
            )
            with (
                mock.patch.object(launcher, "CONFIG_FILE", config_file),
                mock.patch("launcher.input", side_effect=["3"]),
                mock.patch("launcher.yes_no", side_effect=[False]),
            ):
                self.assertEqual(launcher.oauth_setup(), 0)
            saved = json.loads(config_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["oauth_owner_code"], "existing-owner-code")

    def test_show_connection_masks_owner_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_file = root / "config.json"
            connection_file = root / "connection.txt"
            config_file.write_text(
                json.dumps(
                    {
                        "token": "super-secret-token-value",
                        "oauth_owner_code": "owner-code-secret-value",
                    }
                ),
                encoding="utf-8",
            )
            connection_file.write_text(
                "URL: https://x/mcp\n"
                "Bearer token: super-secret-token-value\n"
                "OAuth owner code: owner-code-secret-value\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(launcher, "CONFIG_FILE", config_file),
                mock.patch.object(launcher, "CONNECTION_FILE", connection_file),
                mock.patch("builtins.print") as fake_print,
            ):
                self.assertEqual(launcher.show_connection(full=False), 0)
            output = "\n".join(str(call.args[0]) for call in fake_print.call_args_list if call.args)
            self.assertNotIn("super-secret-token-value", output)
            self.assertNotIn("owner-code-secret-value", output)
            self.assertIn("supe...alue", output)
            self.assertIn("owne...alue", output)


if __name__ == "__main__":
    unittest.main()
