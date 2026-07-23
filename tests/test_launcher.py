import json
import os
import queue
import signal
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
        # Since 2.1.0 dual degrades to a warning on a temporary URL instead of a
        # hard block, so it no longer "requires" a stable hostname to start.
        self.assertFalse(launcher.oauth_requires_stable_hostname({"auth_mode": "dual"}))
        self.assertFalse(
            launcher.oauth_requires_stable_hostname(
                {"auth_mode": "oauth", "serveo_hostname": "my-host"}
            )
        )

    def test_stable_url_policy_classifies_modes(self):
        self.assertEqual(launcher.stable_url_policy({"auth_mode": "legacy"}), "ok")
        self.assertEqual(launcher.stable_url_policy({"auth_mode": "oauth"}), "block")
        self.assertEqual(launcher.stable_url_policy({"auth_mode": "dual"}), "warn")
        self.assertEqual(
            launcher.stable_url_policy(
                {"auth_mode": "oauth", "serveo_hostname": "my-host"}
            ),
            "ok",
        )
        self.assertEqual(
            launcher.stable_url_policy(
                {"auth_mode": "dual", "public_url": "https://mcp.example.com"}
            ),
            "ok",
        )

    def test_stable_url_policy_override_allows_temporary(self):
        os.environ[launcher.OAUTH_TEMP_URL_OVERRIDE] = "1"
        self.assertEqual(launcher.stable_url_policy({"auth_mode": "oauth"}), "ok")
        self.assertEqual(launcher.stable_url_policy({"auth_mode": "dual"}), "ok")

    def test_temporary_url_override_allows_local_experiments(self):
        os.environ[launcher.OAUTH_TEMP_URL_OVERRIDE] = "1"
        self.assertFalse(
            launcher.oauth_requires_stable_hostname({"auth_mode": "oauth"})
        )

    def test_config_public_url_prefers_custom_over_serveo(self):
        self.assertEqual(
            launcher.config_public_url({"serveo_hostname": "h"}),
            "https://h.serveousercontent.com",
        )
        self.assertEqual(
            launcher.config_public_url(
                {"serveo_hostname": "h", "public_url": "https://mcp.example.com/"}
            ),
            "https://mcp.example.com",
        )
        self.assertEqual(launcher.config_public_url({}), "")

    def test_custom_public_url_is_treated_as_stable(self):
        self.assertFalse(
            launcher.oauth_requires_stable_hostname(
                {"auth_mode": "oauth", "public_url": "https://mcp.example.com"}
            )
        )

    def test_custom_public_url_disables_serveo_management(self):
        self.assertTrue(launcher.config_uses_serveo({"serveo_hostname": "h"}))
        self.assertFalse(
            launcher.config_uses_serveo({"public_url": "https://mcp.example.com"})
        )

    def test_oauth_setup_saves_custom_public_url(self):
        with tempfile.TemporaryDirectory() as directory:
            config_file = Path(directory) / "config.json"
            config_file.write_text(
                json.dumps({"token": "t", "workspace": directory, "port": 8765}),
                encoding="utf-8",
            )
            with (
                mock.patch.object(launcher, "CONFIG_FILE", config_file),
                # mode 2 = oauth, then a custom stable public URL
                mock.patch(
                    "launcher.input",
                    side_effect=["2", "https://mcp.example.com"],
                ),
            ):
                self.assertEqual(launcher.oauth_setup(), 0)
            saved = json.loads(config_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["auth_mode"], "oauth")
            self.assertEqual(saved["public_url"], "https://mcp.example.com")
            self.assertGreaterEqual(len(saved["oauth_owner_code"]), 10)

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
                # mode 2 = oauth, then Enter = keep Serveo hostname (no custom URL)
                mock.patch("launcher.input", side_effect=["2", ""]),
            ):
                self.assertEqual(launcher.oauth_setup(), 0)
            saved = json.loads(config_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["auth_mode"], "oauth")
            self.assertGreaterEqual(len(saved["oauth_owner_code"]), 10)
            self.assertNotIn("public_url", saved)

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
                # mode 3 = dual, then Enter = keep Serveo hostname (no custom URL)
                mock.patch("launcher.input", side_effect=["3", ""]),
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


class ConfigRobustnessTests(unittest.TestCase):
    def test_setup_aborts_on_corrupt_config_without_overwriting(self):
        # Regression: a corrupt config.json (e.g. hand-edit with a stray comma
        # or a BOM) must NOT silently trigger first-time setup and regenerate
        # the token. It must abort and leave the file untouched.
        with tempfile.TemporaryDirectory() as directory:
            cfg = Path(directory) / "config.json"
            connections = Path(directory) / "connections.cfg"
            original = '{"token": "keepme", "allowed_commands": ["git",,,]}'
            cfg.write_text(original, encoding="utf-8")
            with (
                mock.patch.object(launcher, "CONFIG_FILE", cfg),
                mock.patch.object(launcher, "CONNECTIONS_FILE", connections),
            ):
                with self.assertRaises(SystemExit):
                    launcher.setup(force=False)
            self.assertEqual(cfg.read_text(encoding="utf-8"), original)

    def test_load_json_tolerates_utf8_bom(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            # Windows editors often add a UTF-8 BOM; it must not break parsing.
            path.write_text('{"token": "x"}', encoding="utf-8-sig")
            self.assertEqual(launcher.load_json(path), {"token": "x"})

    def test_missing_config_is_treated_as_first_run(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = Path(directory) / "config.json"
            with mock.patch.object(launcher, "CONFIG_FILE", cfg):
                self.assertEqual(launcher.load_config_or_abort(), {})

    def test_add_command_is_parse_safe_and_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = Path(directory) / "config.json"
            cfg.write_text(
                json.dumps({"token": "t", "allowed_commands": ["git"]}),
                encoding="utf-8",
            )
            with mock.patch.object(launcher, "CONFIG_FILE", cfg):
                self.assertEqual(launcher.modify_allowed_commands(add=["gh"]), 0)
                self.assertEqual(launcher.modify_allowed_commands(add=["gh"]), 0)
            saved = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertEqual(sorted(saved["allowed_commands"]), ["gh", "git"])

    def test_remove_command(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = Path(directory) / "config.json"
            cfg.write_text(
                json.dumps({"token": "t", "allowed_commands": ["git", "gh"]}),
                encoding="utf-8",
            )
            with mock.patch.object(launcher, "CONFIG_FILE", cfg):
                self.assertEqual(launcher.modify_allowed_commands(remove=["gh"]), 0)
            saved = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertEqual(saved["allowed_commands"], ["git"])

    def test_migrate_legacy_config_dir_copies_old_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = root / "NotionMcpEasy"
            legacy.mkdir()
            (legacy / "config.json").write_text('{"token": "old"}', encoding="utf-8")
            new_dir = root / "LocalMcpEasy"
            with (
                mock.patch.object(launcher, "CONFIG_DIR", new_dir),
                mock.patch.object(launcher, "LEGACY_APP_NAME", "NotionMcpEasy"),
            ):
                launcher.migrate_legacy_config_dir()
            self.assertTrue((new_dir / "config.json").is_file())
            self.assertIn("old", (new_dir / "config.json").read_text(encoding="utf-8"))


class LauncherHardeningTests(unittest.TestCase):
    """2.2.1 launcher hardening (items G/H/I/J): secure connection file,
    macOS process identity, stop escalation and tunnel reconnect backoff."""

    # H: macOS/BSD have no /proc, so process_command_line must fall back to ps.
    @mock.patch("launcher.subprocess.run")
    @mock.patch("launcher.os.name", "posix")
    @mock.patch("launcher.pid_exists", return_value=True)
    def test_process_command_line_falls_back_to_ps_without_proc(self, _exists, run):
        run.return_value = mock.Mock(returncode=0, stdout="python server.py --flag\n")
        # A PID with no /proc entry (always true on macOS; also for this fake
        # PID on Linux) must force the ps fallback path.
        result = launcher.process_command_line(99_998_877)
        self.assertEqual(result, "python server.py --flag")
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "ps")
        self.assertIn("-p", argv)
        self.assertIn("99998877", argv)
        self.assertIn("command=", argv)

    # I: POSIX stop must escalate SIGTERM -> SIGKILL and report the real result.
    @mock.patch("launcher.time.sleep")
    @mock.patch("launcher.os.kill")
    @mock.patch("launcher.os.name", "posix")
    def test_stop_pid_escalates_to_sigkill_when_process_survives(self, kill, _sleep):
        with (
            mock.patch("launcher.pid_exists", return_value=True),
            mock.patch("launcher.pid_matches", return_value=True),
        ):
            result = launcher.stop_pid(4321, "server.py", timeout=0)
        self.assertFalse(result)  # process never died -> honest False
        sent = [call.args[1] for call in kill.call_args_list]
        self.assertIn(signal.SIGTERM, sent)
        self.assertIn(getattr(signal, "SIGKILL", signal.SIGTERM), sent)

    @mock.patch("launcher.time.sleep")
    @mock.patch("launcher.os.kill")
    @mock.patch("launcher.os.name", "posix")
    def test_stop_pid_returns_true_after_graceful_sigterm(self, kill, _sleep):
        # alive for the initial guard and first poll, gone on the second poll.
        alive = mock.Mock(side_effect=[True, True, False])
        with (
            mock.patch("launcher.pid_exists", alive),
            mock.patch("launcher.pid_matches", return_value=True),
        ):
            result = launcher.stop_pid(4321, "server.py", timeout=5)
        self.assertTrue(result)
        sent = [call.args[1] for call in kill.call_args_list]
        self.assertEqual(sent, [signal.SIGTERM])  # no SIGKILL escalation needed

    def test_stop_pid_refuses_on_identity_mismatch(self):
        with (
            mock.patch("launcher.pid_exists", return_value=True),
            mock.patch("launcher.pid_matches", return_value=False),
            mock.patch("launcher.os.kill") as kill,
        ):
            result = launcher.stop_pid(4321, "server.py")
        self.assertFalse(result)
        kill.assert_not_called()

    # G: connection.txt holds the Bearer token; it and the config dir must be
    # created owner-only on POSIX.
    @unittest.skipIf(os.name == "nt", "POSIX permission bits are not enforced on Windows")
    def test_publish_connection_secures_dir_and_file(self):
        with tempfile.TemporaryDirectory() as directory:
            config_dir = Path(directory) / "cfg"
            connection_file = config_dir / "connection.txt"
            runtime_file = config_dir / "runtime.json"
            config = {
                "token": "secret-bearer-value",
                "workspace": directory,
                "allow_commands": False,
                "auth_mode": "legacy",
            }
            with (
                mock.patch.object(launcher, "CONFIG_DIR", config_dir),
                mock.patch.object(launcher, "CONNECTION_FILE", connection_file),
                mock.patch.object(launcher, "RUNTIME_FILE", runtime_file),
                mock.patch("builtins.print"),
            ):
                launcher.publish_connection(
                    config, "https://x.serveousercontent.com", 111, 222
                )
                self.assertTrue(connection_file.is_file())
                self.assertEqual(connection_file.stat().st_mode & 0o777, 0o600)
                self.assertEqual(config_dir.stat().st_mode & 0o777, 0o700)

    # J: tunnel reconnection uses exponential backoff capped at 5 minutes.
    def test_tunnel_backoff_is_exponential_and_capped(self):
        self.assertEqual(launcher.tunnel_backoff_delay(1), 3)
        self.assertEqual(launcher.tunnel_backoff_delay(2), 6)
        self.assertEqual(launcher.tunnel_backoff_delay(3), 12)
        self.assertEqual(launcher.tunnel_backoff_delay(4), 24)
        self.assertEqual(launcher.tunnel_backoff_delay(30), 300)
        self.assertLessEqual(launcher.tunnel_backoff_delay(100), 300)
        self.assertEqual(launcher.tunnel_backoff_delay(0), 0)


if __name__ == "__main__":
    unittest.main()
