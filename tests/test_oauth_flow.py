"""End-to-end OAuth 2.1 integration tests against a real server process.

Covers the Universal auth criteria from the handoff: discovery metadata,
WWW-Authenticate, Dynamic Client Registration, PKCE, consent with the owner
code, state round-trip, scope enforcement per tool, refresh rotation,
revocation, dual mode (legacy Bearer + X-API-Key + OAuth side by side) and
token survival across a server restart with a stable URL.
"""
import base64
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
OPERATOR_TOKEN = "oauth-flow-operator-token"
OWNER_CODE = "oauth-flow-owner-code"
CALLBACK = "http://127.0.0.1:9755/callback"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def http(url, data=None, headers=None, method=None):
    """Single HTTP round-trip without following redirects.

    Returns the raw header mapping (case-insensitive lookups via .get()).
    """
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with _OPENER.open(request, timeout=5) as response:
            return response.status, response.headers, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read().decode()


def form(payload):
    return urllib.parse.urlencode(payload).encode()


FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}


def pkce_pair():
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


class ServerProcess:
    def __init__(self, auth_mode: str, state_dir: str, workspace: str):
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        env = os.environ.copy()
        env.update(
            {
                "MCP_TOKEN": OPERATOR_TOKEN,
                "MCP_BASE_DIR": workspace,
                "MCP_PORT": str(self.port),
                "MCP_ALLOW_COMMANDS": "0",
                "MCP_SERVEO_HOSTNAME": "",
                "MCP_AUTH_MODE": auth_mode,
                "MCP_OAUTH_OWNER_CODE": OWNER_CODE,
                "MCP_OAUTH_STATE_DIR": state_dir,
                "MCP_PUBLIC_URL": f"http://127.0.0.1:{self.port}",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        self.env = env
        self.process = None
        self.start()

    def start(self):
        self.process = subprocess.Popen(
            [sys.executable, str(PROJECT / "server.py")],
            cwd=str(PROJECT),
            env=self.env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                status, _, _ = http(
                    f"{self.base}/health",
                    headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"},
                )
                if status == 200:
                    return
            except OSError:
                pass
            if self.process.poll() is not None:
                raise RuntimeError(f"Server exited with code {self.process.returncode}")
            time.sleep(0.2)
        raise RuntimeError("Server did not become ready")

    def restart(self):
        self.stop()
        # The port stays the same, so the public URL (and token audience)
        # does not change — like a reserved Serveo hostname in production.
        self.start()

    def stop(self):
        if self.process is None or self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


class OAuthClientDriver:
    """Drives DCR + authorize + consent + token like an MCP client would."""

    def __init__(self, base: str):
        self.base = base

    def register(self, scope: str | None = None) -> dict:
        payload = {
            "client_name": "integration-test-client",
            "redirect_uris": [CALLBACK],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }
        if scope is not None:
            payload["scope"] = scope
        status, _, body = http(
            f"{self.base}/register",
            json.dumps(payload).encode(),
            {"Content-Type": "application/json"},
        )
        assert status == 201, f"DCR failed: {status} {body}"
        return json.loads(body)

    def authorize_to_consent(self, client: dict, challenge: str, state: str):
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": client["client_id"],
                "redirect_uri": CALLBACK,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": state,
                "resource": f"{self.base}/mcp",
            }
        )
        status, headers, _ = http(f"{self.base}/authorize?{query}")
        assert status == 302, f"authorize failed: {status}"
        location = headers["Location"]
        txn = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)["txn"][0]
        status, _, page = http(location)
        assert status == 200
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        return txn, csrf

    def approve(self, txn: str, csrf: str, owner_code: str = OWNER_CODE):
        return http(
            f"{self.base}/consent",
            form(
                {
                    "txn": txn,
                    "csrf": csrf,
                    "owner_code": owner_code,
                    "action": "approve",
                }
            ),
            FORM_HEADERS,
        )

    def exchange(self, client: dict, code: str, verifier: str):
        return http(
            f"{self.base}/token",
            form(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": CALLBACK,
                    "client_id": client["client_id"],
                    "code_verifier": verifier,
                }
            ),
            FORM_HEADERS,
        )

    def obtain_tokens(self, scope: str | None = None, state: str = "state-1") -> dict:
        client = self.register(scope)
        verifier, challenge = pkce_pair()
        txn, csrf = self.authorize_to_consent(client, challenge, state)
        status, headers, _ = self.approve(txn, csrf)
        assert status == 302, f"consent approve failed: {status}"
        callback = headers["Location"]
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(callback).query)
        assert query["state"] == [state], "state was not preserved"
        status, _, body = self.exchange(client, query["code"][0], verifier)
        assert status == 200, f"token exchange failed: {status} {body}"
        tokens = json.loads(body)
        tokens["_client"] = client
        return tokens


def mcp_headers(token: str) -> dict:
    return {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {token}",
    }


INITIALIZE = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "oauth-test", "version": "1"},
        },
    }
).encode()


def tools_call(name: str, arguments: dict) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    ).encode()


class OAuthModeTests(unittest.TestCase):
    server: ServerProcess

    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        root = Path(cls.tempdir.name)
        (root / "workspace").mkdir()
        (root / "workspace" / "hello.txt").write_text("hello", encoding="utf-8")
        cls.server = ServerProcess(
            "oauth", str(root / "state"), str(root / "workspace")
        )
        cls.driver = OAuthClientDriver(cls.server.base)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.tempdir.cleanup()

    def test_01_discovery_documents(self):
        base = self.server.base
        status, _, body = http(f"{base}/.well-known/oauth-authorization-server")
        self.assertEqual(status, 200)
        metadata = json.loads(body)
        for key in (
            "authorization_endpoint",
            "token_endpoint",
            "registration_endpoint",
            "revocation_endpoint",
        ):
            self.assertIn(key, metadata)
        self.assertEqual(metadata["code_challenge_methods_supported"], ["S256"])

        status, _, body = http(f"{base}/.well-known/oauth-protected-resource/mcp")
        self.assertEqual(status, 200)
        resource_doc = json.loads(body)
        self.assertEqual(resource_doc["resource"], f"{base}/mcp")

        status, _, body = http(f"{base}/.well-known/oauth-protected-resource")
        self.assertEqual(status, 200)
        alias_doc = json.loads(body)
        self.assertEqual(alias_doc["resource"], f"{base}/mcp")
        self.assertIn("mcp:files:read", alias_doc["scopes_supported"])

    def test_02_unauthorized_mcp_points_to_resource_metadata(self):
        status, headers, _ = http(
            f"{self.server.base}/mcp",
            INITIALIZE,
            {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
        )
        self.assertEqual(status, 401)
        challenge = headers.get("WWW-Authenticate", "")
        self.assertIn("Bearer", challenge)
        self.assertIn("resource_metadata", challenge)
        self.assertIn("/.well-known/oauth-protected-resource/mcp", challenge)

    def test_03_wrong_owner_code_is_rejected(self):
        client = self.driver.register()
        _, challenge = pkce_pair()
        txn, csrf = self.driver.authorize_to_consent(client, challenge, "st")
        status, _, _ = self.driver.approve(txn, csrf, owner_code="wrong-code")
        self.assertEqual(status, 403)

    def test_04_full_flow_with_pkce_and_tools(self):
        client = self.driver.register()
        verifier, challenge = pkce_pair()
        txn, csrf = self.driver.authorize_to_consent(client, challenge, "roundtrip")
        status, headers, _ = self.driver.approve(txn, csrf)
        self.assertEqual(status, 302)
        query = urllib.parse.parse_qs(
            urllib.parse.urlsplit(headers["Location"]).query
        )
        self.assertEqual(query["state"], ["roundtrip"])
        code = query["code"][0]

        # Wrong PKCE verifier is rejected, the right one succeeds.
        status, _, body = self.driver.exchange(client, code, "wrong-verifier")
        self.assertEqual(status, 400)
        self.assertIn("invalid_grant", body)
        status, _, body = self.driver.exchange(client, code, verifier)
        self.assertEqual(status, 200)
        tokens = json.loads(body)
        self.assertTrue(tokens["access_token"].startswith("mcp_at_"))

        headers = mcp_headers(tokens["access_token"])
        status, _, _ = http(f"{self.server.base}/mcp", INITIALIZE, headers)
        self.assertEqual(status, 200)
        status, _, body = http(
            f"{self.server.base}/mcp",
            tools_call("read_file", {"path": "hello.txt"}),
            headers,
        )
        self.assertEqual(status, 200)
        self.assertIn("hello", body)

    def test_05_legacy_token_is_rejected_on_mcp_but_health_works(self):
        status, _, _ = http(
            f"{self.server.base}/mcp", INITIALIZE, mcp_headers(OPERATOR_TOKEN)
        )
        self.assertEqual(status, 401)
        status, _, body = http(
            f"{self.server.base}/health",
            headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"status": "ok"})
        status, _, _ = http(f"{self.server.base}/health")
        self.assertEqual(status, 401)

    def test_05b_authorize_missing_params_shows_friendly_hint(self):
        # Serveo's free-tier interstitial can strip the query string on the
        # first hit to /authorize; the middleware must replace the SDK's raw
        # JSON 400 with a friendly HTML page -- WITHOUT touching valid requests.
        status, headers, body = http(f"{self.server.base}/authorize")
        self.assertEqual(status, 400)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        self.assertIn("Serveo", body)
        self.assertNotIn("Field required", body)
        # A partial (still-invalid) request is also caught.
        status, _, body = http(f"{self.server.base}/authorize?client_id=x")
        self.assertEqual(status, 400)
        self.assertIn("Serveo", body)
        # A well-formed authorize request is untouched: it still reaches the SDK
        # handler and redirects to the consent page (302). authorize_to_consent
        # asserts the 302 internally, so reaching a txn proves the passthrough.
        client = self.driver.register()
        _, challenge = pkce_pair()
        txn, _csrf = self.driver.authorize_to_consent(client, challenge, "hint-ok")
        self.assertTrue(txn)

    def test_06_read_scope_cannot_write_or_run_commands(self):
        tokens = self.driver.obtain_tokens(scope="mcp:files:read")
        headers = mcp_headers(tokens["access_token"])
        status, _, body = http(
            f"{self.server.base}/mcp",
            tools_call("read_file", {"path": "hello.txt"}),
            headers,
        )
        self.assertEqual(status, 200)
        self.assertIn("hello", body)

        for tool, arguments in (
            ("write_file", {"path": "evil.txt", "content": "x"}),
            ("delete_file", {"path": "hello.txt"}),
            ("run_command", {"program": "git", "args": ["status"]}),
            ("setup_git_context", {"mode": "solo"}),
        ):
            status, _, body = http(
                f"{self.server.base}/mcp", tools_call(tool, arguments), headers
            )
            self.assertEqual(status, 200)
            payload = json.loads(body)
            self.assertTrue(
                payload["result"].get("isError"),
                f"{tool} must be denied for a read-only token",
            )
            self.assertIn("requires OAuth scope", json.dumps(payload))
        # Nothing was written despite the attempts.
        status, _, body = http(
            f"{self.server.base}/mcp",
            tools_call("file_info", {"path": "evil.txt"}),
            headers,
        )
        payload = json.loads(body)
        self.assertIn("Not found: evil.txt", json.dumps(payload))

    def test_07_refresh_rotation_and_revocation(self):
        tokens = self.driver.obtain_tokens()
        client = tokens["_client"]
        base = self.server.base

        status, _, body = http(
            f"{base}/token",
            form(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": tokens["refresh_token"],
                    "client_id": client["client_id"],
                }
            ),
            FORM_HEADERS,
        )
        self.assertEqual(status, 200)
        rotated = json.loads(body)
        self.assertNotEqual(rotated["refresh_token"], tokens["refresh_token"])

        # The previous refresh token is dead after rotation.
        status, _, body = http(
            f"{base}/token",
            form(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": tokens["refresh_token"],
                    "client_id": client["client_id"],
                }
            ),
            FORM_HEADERS,
        )
        self.assertEqual(status, 400)
        self.assertIn("invalid_grant", body)

        # The access token issued together with it is dead as well.
        status, _, _ = http(f"{base}/mcp", INITIALIZE, mcp_headers(tokens["access_token"]))
        self.assertEqual(status, 401)
        status, _, _ = http(f"{base}/mcp", INITIALIZE, mcp_headers(rotated["access_token"]))
        self.assertEqual(status, 200)

        # Revocation kills the rotated access token.
        status, _, _ = http(
            f"{base}/revoke",
            form(
                {
                    "token": rotated["access_token"],
                    "client_id": client["client_id"],
                    "client_secret": "",
                }
            ),
            FORM_HEADERS,
        )
        self.assertEqual(status, 200)
        status, _, _ = http(f"{base}/mcp", INITIALIZE, mcp_headers(rotated["access_token"]))
        self.assertEqual(status, 401)

    def test_08_invalid_redirect_uri_gets_direct_error(self):
        client = self.driver.register()
        _, challenge = pkce_pair()
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": client["client_id"],
                "redirect_uri": "https://evil.example/steal",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        status, headers, _ = http(f"{self.server.base}/authorize?{query}")
        self.assertEqual(status, 400)
        self.assertNotIn("Location", headers)

    def test_09_tokens_survive_server_restart(self):
        tokens = self.driver.obtain_tokens()
        self.server.restart()
        status, _, _ = http(
            f"{self.server.base}/mcp", INITIALIZE, mcp_headers(tokens["access_token"])
        )
        self.assertEqual(status, 200)
        # Refresh still works after the restart, so clients reconnect silently.
        status, _, body = http(
            f"{self.server.base}/token",
            form(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": tokens["refresh_token"],
                    "client_id": tokens["_client"]["client_id"],
                }
            ),
            FORM_HEADERS,
        )
        self.assertEqual(status, 200)
        self.assertIn("access_token", json.loads(body))


class DualModeTests(unittest.TestCase):
    server: ServerProcess

    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        root = Path(cls.tempdir.name)
        (root / "workspace").mkdir()
        cls.server = ServerProcess("dual", str(root / "state"), str(root / "workspace"))
        cls.driver = OAuthClientDriver(cls.server.base)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.tempdir.cleanup()

    def test_legacy_bearer_token_still_works_on_mcp(self):
        status, _, _ = http(
            f"{self.server.base}/mcp", INITIALIZE, mcp_headers(OPERATOR_TOKEN)
        )
        self.assertEqual(status, 200)

    def test_legacy_x_api_key_still_works_on_mcp(self):
        status, _, _ = http(
            f"{self.server.base}/mcp",
            INITIALIZE,
            {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "X-API-Key": OPERATOR_TOKEN,
            },
        )
        self.assertEqual(status, 200)

    def test_wrong_tokens_are_rejected(self):
        status, _, _ = http(f"{self.server.base}/mcp", INITIALIZE, mcp_headers("nope"))
        self.assertEqual(status, 401)
        status, _, _ = http(
            f"{self.server.base}/mcp",
            INITIALIZE,
            {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "X-API-Key": "nope",
            },
        )
        self.assertEqual(status, 401)

    def test_oauth_client_works_alongside_legacy(self):
        tokens = self.driver.obtain_tokens()
        status, _, _ = http(
            f"{self.server.base}/mcp", INITIALIZE, mcp_headers(tokens["access_token"])
        )
        self.assertEqual(status, 200)

    def test_legacy_token_keeps_full_access_to_tools(self):
        status, _, body = http(
            f"{self.server.base}/mcp",
            tools_call("write_file", {"path": "from-legacy.txt", "content": "ok"}),
            mcp_headers(OPERATOR_TOKEN),
        )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertFalse(payload["result"].get("isError"))


if __name__ == "__main__":
    unittest.main()
