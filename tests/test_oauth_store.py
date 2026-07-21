import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from mcp.server.auth.provider import AuthorizationParams, TokenError  # noqa: E402
from mcp.shared.auth import OAuthClientInformationFull  # noqa: E402
from starlette.applications import Starlette  # noqa: E402
from starlette.routing import Route  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from auth import (  # noqa: E402
    ALL_SCOPES,
    ConsentHandler,
    LEGACY_CLIENT_ID,
    LegacyTokenVerifier,
    LocalOAuthProvider,
    OAuthStore,
    SCOPE_FILES_READ,
    normalize_resource,
)
from auth.oauth import PendingAuthorization  # noqa: E402

ISSUER = "https://example.serveousercontent.com"
RESOURCE = f"{ISSUER}/mcp"
REDIRECT = "https://client.example/callback"


def make_client(
    scope: str | None = None,
    client_id: str = "client-1",
    redirect_uris: list[str] | None = None,
) -> OAuthClientInformationFull:
    return OAuthClientInformationFull.model_validate(
        {
            "client_id": client_id,
            "client_secret": None,
            "redirect_uris": redirect_uris or [REDIRECT],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": scope if scope is not None else " ".join(ALL_SCOPES),
            "client_name": "Test client",
        }
    )


def make_params(state: str = "st-1", resource: str | None = RESOURCE) -> AuthorizationParams:
    return AuthorizationParams(
        state=state,
        scopes=None,
        code_challenge="challenge-value",
        redirect_uri=REDIRECT,
        redirect_uri_provided_explicitly=True,
        resource=resource,
    )


class ProviderTestBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tempdir = tempfile.TemporaryDirectory()
        self.state_file = Path(self._tempdir.name) / "oauth_state.json"
        self.provider = self._make_provider()

    def tearDown(self):
        self._tempdir.cleanup()

    def _make_provider(self, legacy_token: str | None = None) -> LocalOAuthProvider:
        return LocalOAuthProvider(
            store=OAuthStore(self.state_file),
            issuer_url=ISSUER,
            canonical_resource=RESOURCE,
            legacy_verifier=LegacyTokenVerifier(legacy_token) if legacy_token else None,
        )

    async def _authorize_and_exchange(self, client, params=None):
        await self.provider.register_client(client)
        location = await self.provider.authorize(client, params or make_params())
        txn_id = parse_qs(urlsplit(location).query)["txn"][0]
        redirect = self.provider.approve_txn(txn_id)
        code = parse_qs(urlsplit(redirect).query)["code"][0]
        loaded = await self.provider.load_authorization_code(client, code)
        self.assertIsNotNone(loaded)
        token = await self.provider.exchange_authorization_code(client, loaded)
        return redirect, token


class NormalizeResourceTests(unittest.TestCase):
    def test_default_ports_and_trailing_slash_are_ignored(self):
        self.assertEqual(
            normalize_resource("HTTPS://Example.COM:443/mcp/"),
            normalize_resource("https://example.com/mcp"),
        )

    def test_non_default_port_is_preserved(self):
        self.assertNotEqual(
            normalize_resource("http://127.0.0.1:8765/mcp"),
            normalize_resource("http://127.0.0.1/mcp"),
        )


class ProviderFlowTests(ProviderTestBase):
    async def test_full_flow_issues_tokens_and_preserves_state(self):
        redirect, token = await self._authorize_and_exchange(make_client())
        query = parse_qs(urlsplit(redirect).query)
        self.assertEqual(query["state"], ["st-1"])
        self.assertTrue(token.access_token.startswith("mcp_at_"))
        self.assertTrue(token.refresh_token.startswith("mcp_rt_"))
        access = await self.provider.load_access_token(token.access_token)
        self.assertIsNotNone(access)
        self.assertEqual(sorted(access.scopes), sorted(ALL_SCOPES))

    async def test_raw_tokens_are_not_persisted(self):
        _, token = await self._authorize_and_exchange(make_client())
        raw = self.state_file.read_text(encoding="utf-8")
        self.assertNotIn(token.access_token, raw)
        self.assertNotIn(token.refresh_token, raw)

    async def test_tokens_survive_store_reload(self):
        _, token = await self._authorize_and_exchange(make_client())
        reloaded = self._make_provider()
        access = await reloaded.load_access_token(token.access_token)
        self.assertIsNotNone(access)
        refresh = await reloaded.load_refresh_token(make_client(), token.refresh_token)
        self.assertIsNotNone(refresh)

    async def test_authorization_code_is_single_use(self):
        client = make_client()
        await self.provider.register_client(client)
        location = await self.provider.authorize(client, make_params())
        txn_id = parse_qs(urlsplit(location).query)["txn"][0]
        redirect = self.provider.approve_txn(txn_id)
        code = parse_qs(urlsplit(redirect).query)["code"][0]
        loaded = await self.provider.load_authorization_code(client, code)
        await self.provider.exchange_authorization_code(client, loaded)
        self.assertIsNone(await self.provider.load_authorization_code(client, code))

    async def test_code_replay_revokes_issued_tokens(self):
        client = make_client()
        await self.provider.register_client(client)
        location = await self.provider.authorize(client, make_params())
        txn_id = parse_qs(urlsplit(location).query)["txn"][0]
        redirect = self.provider.approve_txn(txn_id)
        code = parse_qs(urlsplit(redirect).query)["code"][0]
        loaded = await self.provider.load_authorization_code(client, code)
        token = await self.provider.exchange_authorization_code(client, loaded)
        # Replay: the second lookup revokes everything the code produced.
        self.assertIsNone(await self.provider.load_authorization_code(client, code))
        self.assertIsNone(await self.provider.load_access_token(token.access_token))
        self.assertIsNone(
            await self.provider.load_refresh_token(client, token.refresh_token)
        )

    async def test_refresh_rotation_invalidates_previous_tokens(self):
        client = make_client()
        _, token = await self._authorize_and_exchange(client)
        refresh = await self.provider.load_refresh_token(client, token.refresh_token)
        rotated = await self.provider.exchange_refresh_token(client, refresh, [])
        self.assertNotEqual(rotated.refresh_token, token.refresh_token)
        self.assertIsNone(
            await self.provider.load_refresh_token(client, token.refresh_token)
        )
        self.assertIsNone(await self.provider.load_access_token(token.access_token))
        self.assertIsNotNone(await self.provider.load_access_token(rotated.access_token))

    async def test_refresh_cannot_widen_scopes(self):
        client = make_client(scope=SCOPE_FILES_READ)
        params = make_params()
        params.scopes = [SCOPE_FILES_READ]
        _, token = await self._authorize_and_exchange(client, params)
        refresh = await self.provider.load_refresh_token(client, token.refresh_token)
        with self.assertRaises(TokenError):
            await self.provider.exchange_refresh_token(
                client, refresh, list(ALL_SCOPES)
            )

    async def test_expired_access_token_is_rejected(self):
        self.provider.access_ttl = -1
        _, token = await self._authorize_and_exchange(make_client())
        self.assertIsNone(await self.provider.load_access_token(token.access_token))

    async def test_access_token_is_bound_to_resource_audience(self):
        _, token = await self._authorize_and_exchange(make_client())
        moved = LocalOAuthProvider(
            store=OAuthStore(self.state_file),
            issuer_url="https://other-host.example",
            canonical_resource="https://other-host.example/mcp",
        )
        self.assertIsNone(await moved.load_access_token(token.access_token))

    async def test_authorize_rejects_foreign_resource_indicator(self):
        client = make_client()
        await self.provider.register_client(client)
        from mcp.server.auth.provider import AuthorizeError

        with self.assertRaises(AuthorizeError):
            await self.provider.authorize(
                client, make_params(resource="https://evil.example/mcp")
            )

    async def test_revoking_access_token_also_revokes_refresh_token(self):
        client = make_client()
        _, token = await self._authorize_and_exchange(client)
        access = await self.provider.load_access_token(token.access_token)
        await self.provider.revoke_token(access)
        self.assertIsNone(await self.provider.load_access_token(token.access_token))
        self.assertIsNone(
            await self.provider.load_refresh_token(client, token.refresh_token)
        )

    async def test_denied_consent_redirects_with_access_denied(self):
        client = make_client()
        await self.provider.register_client(client)
        location = await self.provider.authorize(client, make_params(state="deny-state"))
        txn_id = parse_qs(urlsplit(location).query)["txn"][0]
        redirect = self.provider.deny_txn(txn_id)
        query = parse_qs(urlsplit(redirect).query)
        self.assertEqual(query["error"], ["access_denied"])
        self.assertEqual(query["state"], ["deny-state"])

    async def test_registration_rejects_plain_http_redirect(self):
        from mcp.server.auth.provider import RegistrationError

        bad = make_client(redirect_uris=["http://client.example/callback"])
        with self.assertRaises(RegistrationError):
            await self.provider.register_client(bad)

    async def test_localhost_http_redirect_is_allowed(self):
        client = make_client(
            client_id="loopback", redirect_uris=["http://127.0.0.1:9000/cb"]
        )
        await self.provider.register_client(client)
        self.assertIsNotNone(await self.provider.get_client("loopback"))


class DualModeProviderTests(ProviderTestBase):
    async def test_legacy_token_is_accepted_with_full_scopes(self):
        provider = self._make_provider(legacy_token="master-token")
        access = await provider.load_access_token("master-token")
        self.assertIsNotNone(access)
        self.assertEqual(access.client_id, LEGACY_CLIENT_ID)
        self.assertEqual(sorted(access.scopes), sorted(ALL_SCOPES))

    async def test_wrong_legacy_token_is_rejected(self):
        provider = self._make_provider(legacy_token="master-token")
        self.assertIsNone(await provider.load_access_token("wrong-token"))

    async def test_legacy_token_cannot_be_revoked(self):
        provider = self._make_provider(legacy_token="master-token")
        access = await provider.load_access_token("master-token")
        await provider.revoke_token(access)
        self.assertIsNotNone(await provider.load_access_token("master-token"))


class ConsentHandlerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tempdir = tempfile.TemporaryDirectory()
        self.provider = LocalOAuthProvider(
            store=OAuthStore(Path(self._tempdir.name) / "oauth_state.json"),
            issuer_url=ISSUER,
            canonical_resource=RESOURCE,
        )
        self.handler = ConsentHandler(
            provider=self.provider,
            owner_code="owner-code-1",
            server_name="Test MCP",
            server_version="1.5.0",
            max_attempts=2,
            lockout_seconds=60,
        )
        app = Starlette(
            routes=[
                Route("/consent", self.handler.handle, methods=["GET", "POST"]),
            ]
        )
        self.http = TestClient(app)

    def tearDown(self):
        self._tempdir.cleanup()

    async def _make_txn(self) -> PendingAuthorization:
        client = make_client()
        await self.provider.register_client(client)
        location = await self.provider.authorize(client, make_params())
        txn_id = parse_qs(urlsplit(location).query)["txn"][0]
        return self.provider.get_txn(txn_id)

    def test_unknown_txn_returns_expired_page(self):
        response = self.http.get("/consent?txn=missing")
        self.assertEqual(response.status_code, 400)
        self.assertIn("expired", response.text.lower())

    async def test_get_shows_client_and_scopes(self):
        txn = await self._make_txn()
        response = self.http.get(f"/consent?txn={txn.txn_id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test client", response.text)
        self.assertIn("mcp:files:read", response.text)
        self.assertIn(txn.csrf, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["x-frame-options"], "DENY")

    async def test_wrong_csrf_is_rejected(self):
        txn = await self._make_txn()
        response = self.http.post(
            "/consent",
            data={
                "txn": txn.txn_id,
                "csrf": "forged",
                "owner_code": "owner-code-1",
                "action": "approve",
            },
        )
        self.assertEqual(response.status_code, 400)

    async def test_wrong_owner_code_then_lockout(self):
        txn = await self._make_txn()
        form = {
            "txn": txn.txn_id,
            "csrf": txn.csrf,
            "owner_code": "nope",
            "action": "approve",
        }
        first = self.http.post("/consent", data=form)
        self.assertEqual(first.status_code, 403)
        second = self.http.post("/consent", data=form)
        self.assertEqual(second.status_code, 403)
        # max_attempts=2 reached: even the right code is now locked out.
        locked = self.http.post(
            "/consent", data={**form, "owner_code": "owner-code-1"}
        )
        self.assertEqual(locked.status_code, 429)

    async def test_approve_redirects_with_code(self):
        txn = await self._make_txn()
        response = self.http.post(
            "/consent",
            data={
                "txn": txn.txn_id,
                "csrf": txn.csrf,
                "owner_code": "owner-code-1",
                "action": "approve",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        location = response.headers["location"]
        self.assertTrue(location.startswith(REDIRECT))
        self.assertIn("code=", location)
        self.assertIn("state=st-1", location)

    async def test_deny_redirects_with_error(self):
        txn = await self._make_txn()
        response = self.http.post(
            "/consent",
            data={
                "txn": txn.txn_id,
                "csrf": txn.csrf,
                "owner_code": "",
                "action": "deny",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=access_denied", response.headers["location"])


if __name__ == "__main__":
    unittest.main()
