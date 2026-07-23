import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from core import _consteq  # noqa: E402
from mcp.server.auth.provider import (  # noqa: E402
    AuthorizationParams,
    AuthorizeError,
    RegistrationError,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull  # noqa: E402
from starlette.applications import Starlette  # noqa: E402
from starlette.routing import Route  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from auth import (  # noqa: E402
    ALL_SCOPES,
    DEFAULT_SCOPES,
    ConsentHandler,
    LEGACY_CLIENT_ID,
    LegacyTokenVerifier,
    LocalOAuthProvider,
    OAuthStore,
    SCOPE_COMMANDS_RUN,
    SCOPE_FILES_READ,
    SCOPE_GIT,
    build_auth_settings,
    normalize_resource,
    resources_match,
)
from auth.oauth import PendingAuthorization  # noqa: E402


def dcr_client(client_id: str, issued_at, scope: str | None = None) -> OAuthClientInformationFull:
    return OAuthClientInformationFull.model_validate(
        {
            "client_id": client_id,
            "client_secret": None,
            "client_id_issued_at": issued_at,
            "redirect_uris": [REDIRECT],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": scope if scope is not None else " ".join(ALL_SCOPES),
            "client_name": "DCR client",
        }
    )

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
        self.assertIsNone(await self.provider.load_access_token(token.access_token))
        self.assertIsNotNone(await self.provider.load_access_token(rotated.access_token))
        # NOTE: presenting the now-rotated OLD token again (even via a mere
        # load, not just exchange) is reuse per RFC 9700 section 4.14.2 and
        # revokes the whole family, including the just-issued `rotated` one —
        # see RefreshTokenFamilyTests for that scenario. This test therefore
        # does not re-load `token.refresh_token` after rotation.

    async def test_old_refresh_token_cannot_be_exchanged_again_after_rotation(self):
        # The old token is genuinely dead (can't mint more tokens with it),
        # verified via exchange rather than load (load-after-rotation of the
        # old token is itself treated as reuse — see RefreshTokenFamilyTests).
        from mcp.server.auth.provider import RefreshToken

        client = make_client()
        _, token = await self._authorize_and_exchange(client)
        refresh = await self.provider.load_refresh_token(client, token.refresh_token)
        await self.provider.exchange_refresh_token(client, refresh, [])
        forged_old = RefreshToken(
            token=token.refresh_token,
            client_id=client.client_id,
            scopes=list(refresh.scopes),
            expires_at=None,
        )
        with self.assertRaises(TokenError):
            await self.provider.exchange_refresh_token(client, forged_old, [])

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
            server_version="2.0.0",
            max_attempts_per_txn=3,
            failure_window_seconds=60,
            max_failures_per_window=100,
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

    async def test_form_action_csp_allows_client_redirect_origin(self):
        # Without the client's redirect origin in form-action, CSP 3 browsers
        # block the post-approval 302 back to the client. The consent page must
        # allow 'self' plus the client's redirect origin.
        txn = await self._make_txn()
        response = self.http.get(f"/consent?txn={txn.txn_id}")
        csp = response.headers["content-security-policy"]
        self.assertIn("form-action 'self' https://client.example", csp)

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

    async def test_correct_owner_code_always_works_after_wrong_attempts(self):
        # A DoS fix: wrong attempts must NOT lock out the legitimate owner.
        txn = await self._make_txn()
        wrong = {
            "txn": txn.txn_id,
            "csrf": txn.csrf,
            "owner_code": "nope",
            "action": "approve",
        }
        first = self.http.post("/consent", data=wrong)
        self.assertEqual(first.status_code, 403)
        second = self.http.post("/consent", data=wrong)
        self.assertEqual(second.status_code, 403)
        # The correct code still succeeds on the same transaction.
        ok = self.http.post(
            "/consent",
            data={**wrong, "owner_code": "owner-code-1"},
            follow_redirects=False,
        )
        self.assertEqual(ok.status_code, 302)
        self.assertIn("code=", ok.headers["location"])

    async def test_per_transaction_attempt_cap_invalidates_transaction(self):
        txn = await self._make_txn()
        wrong = {
            "txn": txn.txn_id,
            "csrf": txn.csrf,
            "owner_code": "nope",
            "action": "approve",
        }
        # max_attempts_per_txn=3: third wrong attempt burns the transaction.
        self.assertEqual(self.http.post("/consent", data=wrong).status_code, 403)
        self.assertEqual(self.http.post("/consent", data=wrong).status_code, 403)
        self.assertEqual(self.http.post("/consent", data=wrong).status_code, 429)
        # Transaction is gone; further posts (even correct) are "expired".
        self.assertIsNone(self.provider.get_txn(txn.txn_id))
        gone = self.http.post(
            "/consent", data={**wrong, "owner_code": "owner-code-1"}
        )
        self.assertEqual(gone.status_code, 400)

    async def test_global_throttle_limits_wrong_attempts_but_not_correct(self):
        handler = ConsentHandler(
            provider=self.provider,
            owner_code="owner-code-1",
            server_name="Test MCP",
            server_version="2.0.0",
            max_attempts_per_txn=1000,
            failure_window_seconds=60,
            max_failures_per_window=3,
        )
        app = Starlette(
            routes=[Route("/consent", handler.handle, methods=["GET", "POST"])]
        )
        http = TestClient(app)

        async def fresh_txn():
            return await self._make_txn()

        # Exhaust the global wrong-attempt budget across separate transactions.
        for _ in range(3):
            txn = await fresh_txn()
            http.post(
                "/consent",
                data={
                    "txn": txn.txn_id,
                    "csrf": txn.csrf,
                    "owner_code": "nope",
                    "action": "approve",
                },
            )
        throttle_txn = await fresh_txn()
        throttled = http.post(
            "/consent",
            data={
                "txn": throttle_txn.txn_id,
                "csrf": throttle_txn.csrf,
                "owner_code": "still-wrong",
                "action": "approve",
            },
        )
        self.assertEqual(throttled.status_code, 429)
        # A correct code is still accepted despite the global throttle.
        good_txn = await fresh_txn()
        ok = http.post(
            "/consent",
            data={
                "txn": good_txn.txn_id,
                "csrf": good_txn.csrf,
                "owner_code": "owner-code-1",
                "action": "approve",
            },
            follow_redirects=False,
        )
        self.assertEqual(ok.status_code, 302)

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

    async def test_D_non_ascii_owner_code_is_clean_403_not_500(self):
        # A non-ASCII owner code must fail the constant-time comparison with a
        # clean 403 rather than surfacing hmac.compare_digest's TypeError as 500.
        txn = await self._make_txn()
        response = self.http.post(
            "/consent",
            data={
                "txn": txn.txn_id,
                "csrf": txn.csrf,
                "owner_code": "wröng-cödé",
                "action": "approve",
            },
        )
        self.assertEqual(response.status_code, 403)

    async def test_D_non_ascii_csrf_is_clean_400_not_500(self):
        txn = await self._make_txn()
        response = self.http.post(
            "/consent",
            data={
                "txn": txn.txn_id,
                "csrf": "förged-tökén",
                "owner_code": "owner-code-1",
                "action": "approve",
            },
        )
        self.assertEqual(response.status_code, 400)

    async def test_F_bogus_action_is_rejected_and_records_no_grant(self):
        # Anything other than an explicit "approve" (even with a valid owner
        # code and CSRF) must be refused without minting an authorization code.
        txn = await self._make_txn()
        response = self.http.post(
            "/consent",
            data={
                "txn": txn.txn_id,
                "csrf": txn.csrf,
                "owner_code": "owner-code-1",
                "action": "bogus",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 400)
        # No grant recorded: the transaction is still pending and no code exists.
        self.assertIsNotNone(self.provider.get_txn(txn.txn_id))
        self.assertEqual(len(self.provider._codes), 0)


class TokenCompareHardeningTests(unittest.TestCase):
    """Fix D: constant-time comparison must never raise on hostile input."""

    def test_D_consteq_matches_and_rejects_ascii(self):
        self.assertTrue(_consteq("secret-token", "secret-token"))
        self.assertFalse(_consteq("secret-token", "other-token"))

    def test_D_consteq_non_ascii_returns_false_without_raising(self):
        # hmac.compare_digest raises TypeError on non-ASCII str; _consteq must
        # return False instead so a hostile bearer token yields 401, not 500.
        self.assertFalse(_consteq("tökén", "token"))
        self.assertFalse(_consteq("token", "tökén"))

    def test_D_legacy_verifier_non_ascii_token_returns_false(self):
        verifier = LegacyTokenVerifier("master-token")
        self.assertFalse(verifier.matches("nön-ascii-tökén"))
        self.assertTrue(verifier.matches("master-token"))


class ResourceValidationHardeningTests(unittest.IsolatedAsyncioTestCase):
    """Fix E: a malformed resource must yield invalid_request, not a 500."""

    def test_E_malformed_resource_does_not_raise_in_match(self):
        # urlsplit(...).port raises ValueError on an out-of-range port; the
        # audience check must swallow that and simply report a non-match.
        self.assertFalse(resources_match("http://x:99999999", RESOURCE))

    async def test_E_authorize_maps_malformed_resource_to_invalid_request(self):
        store = OAuthStore(Path(tempfile.mktemp()))
        provider = LocalOAuthProvider(
            store=store, issuer_url=ISSUER, canonical_resource=RESOURCE
        )
        client = make_client()
        await provider.register_client(client)
        with self.assertRaises(AuthorizeError) as caught:
            await provider.authorize(
                client, make_params(resource="http://x:99999999")
            )
        self.assertEqual(caught.exception.error, "invalid_request")


class RedirectValidationTests(unittest.TestCase):
    def _validate(self, uri: str):
        LocalOAuthProvider.validate_redirect_uris(make_client(redirect_uris=[uri]))

    def test_accepts_https_with_host_and_loopback_http(self):
        self._validate("https://client.example/callback")
        self._validate("http://127.0.0.1:9000/cb")
        self._validate("http://localhost/cb")

    def test_rejects_fragment(self):
        with self.assertRaises(RegistrationError):
            self._validate("https://client.example/cb#frag")

    def test_rejects_userinfo(self):
        with self.assertRaises(RegistrationError):
            self._validate("https://user:pw@client.example/cb")

    def test_rejects_hostless_https(self):
        # The pydantic AnyUrl model normalizes odd forms like "https:opaque"
        # into a hosted URL, so exercise the host check directly with a value
        # that reaches the validator without a host.
        from types import SimpleNamespace

        with self.assertRaises(RegistrationError):
            LocalOAuthProvider.validate_redirect_uris(
                SimpleNamespace(redirect_uris=["https://"])
            )

    def test_rejects_non_loopback_http(self):
        with self.assertRaises(RegistrationError):
            self._validate("http://client.example/cb")

    def test_rejects_foreign_scheme(self):
        with self.assertRaises(RegistrationError):
            self._validate("ftp://client.example/cb")


class StoreResilienceTests(unittest.TestCase):
    def _store_from(self, text: str) -> OAuthStore:
        path = Path(tempfile.mktemp())
        path.write_text(text, encoding="utf-8")
        return OAuthStore(path)

    def test_null_section_does_not_crash(self):
        store = self._store_from('{"version": 1, "clients": null}')
        self.assertEqual(store.clients, {})

    def test_scalar_sections_are_ignored(self):
        store = self._store_from('{"clients": 5, "access_tokens": "x"}')
        self.assertEqual(store.clients, {})
        self.assertEqual(store.access_tokens, {})

    def test_non_dict_entries_are_dropped(self):
        store = self._store_from('{"clients": {"a": {"client_id": "a"}, "b": 3}}')
        self.assertIn("a", store.clients)
        self.assertNotIn("b", store.clients)

    def test_newer_schema_version_starts_clean(self):
        store = self._store_from('{"version": 999, "clients": {"a": {"x": 1}}}')
        self.assertEqual(store.clients, {})

    def test_garbage_file_starts_clean(self):
        store = self._store_from("not json at all")
        self.assertEqual(store.clients, {})

    def test_utf8_bom_state_file_loads(self):
        # A BOM (e.g. from a text editor) must not silently reset the state.
        path = Path(tempfile.mktemp())
        path.write_text(
            '{"version": 1, "clients": {"a": {"client_id": "a"}}}',
            encoding="utf-8-sig",
        )
        store = OAuthStore(path)
        self.assertIn("a", store.clients)


class InMemoryCapTests(unittest.TestCase):
    """m2: pending transactions and used-code markers are bounded by count,
    not only by TTL, so a burst of public /authorize|/token cannot grow them
    without limit."""

    def setUp(self):
        self.provider = LocalOAuthProvider(
            store=OAuthStore(Path(tempfile.mktemp())),
            issuer_url=ISSUER,
            canonical_resource=RESOURCE,
        )

    def test_pending_txns_are_capped(self):
        import auth.oauth as oauth_mod

        original = oauth_mod.MAX_PENDING_TXNS
        oauth_mod.MAX_PENDING_TXNS = 5
        try:
            base = time.time()
            for i in range(20):
                txn = PendingAuthorization(
                    txn_id=f"t{i}", client=make_client(), params=make_params(),
                    csrf="c", created_at=base + i,
                )
                self.provider._txns[txn.txn_id] = txn
            self.provider._prune_txns()
            self.assertLessEqual(len(self.provider._txns), 5)
            # Newest transactions survive; oldest are evicted.
            self.assertIn("t19", self.provider._txns)
            self.assertNotIn("t0", self.provider._txns)
        finally:
            oauth_mod.MAX_PENDING_TXNS = original

    def test_used_codes_are_capped(self):
        import auth.oauth as oauth_mod

        original = oauth_mod.MAX_USED_CODES
        oauth_mod.MAX_USED_CODES = 5
        try:
            now = time.time()
            for i in range(20):
                self.provider._used_codes[f"c{i}"] = ("a", "r", now + i)
            self.provider._prune_used_codes()
            self.assertLessEqual(len(self.provider._used_codes), 5)
            self.assertIn("c19", self.provider._used_codes)
            self.assertNotIn("c0", self.provider._used_codes)
        finally:
            oauth_mod.MAX_USED_CODES = original


class ClientRegistryTests(ProviderTestBase):
    def _provider(self, max_clients: int, unused_ttl: int = 3600) -> LocalOAuthProvider:
        return LocalOAuthProvider(
            store=OAuthStore(self.state_file),
            issuer_url=ISSUER,
            canonical_resource=RESOURCE,
            max_clients=max_clients,
            unused_client_ttl=unused_ttl,
        )

    async def test_registration_is_capped_by_eviction_of_unused_clients(self):
        provider = self._provider(max_clients=2)
        now = int(time.time())
        await provider.register_client(dcr_client("c1", now))
        await provider.register_client(dcr_client("c2", now + 1))
        await provider.register_client(dcr_client("c3", now + 2))
        # Never exceeds the cap; the oldest unused client was evicted.
        self.assertEqual(len(provider.store.clients), 2)
        self.assertNotIn("c1", provider.store.clients)
        self.assertIn("c3", provider.store.clients)

    async def test_token_bearing_client_is_never_evicted(self):
        provider = self._provider(max_clients=2)
        now = int(time.time())
        await provider.register_client(dcr_client("keep", now))
        # Give "keep" a live token so it must survive registration pressure.
        provider.store.access_tokens["h"] = {
            "client_id": "keep",
            "scopes": [SCOPE_FILES_READ],
            "expires_at": int(now + 10_000_000_000),
            "resource": provider.canonical_resource,
            "refresh_parent": "r",
        }
        await provider.register_client(dcr_client("c2", now + 1))
        await provider.register_client(dcr_client("c3", now + 2))
        self.assertIn("keep", provider.store.clients)

    async def test_manual_client_without_issued_at_is_protected(self):
        provider = self._provider(max_clients=1)
        # Manually registered (no client_id_issued_at) BYO client.
        manual = make_client(client_id="byo")
        provider.store.clients["byo"] = manual.model_dump(mode="json")
        # A DCR registration cannot evict the manual client, so it is rejected.
        with self.assertRaises(RegistrationError):
            await provider.register_client(dcr_client("dcr", 1_000_000))
        self.assertIn("byo", provider.store.clients)

    async def test_prune_removes_old_unused_clients(self):
        provider = self._provider(max_clients=100, unused_ttl=3600)
        old = 1_000  # far in the past
        provider.store.clients["stale"] = dcr_client("stale", old).model_dump(mode="json")
        provider.store.clients["manual"] = make_client(client_id="manual").model_dump(mode="json")
        provider.prune_clients()
        self.assertNotIn("stale", provider.store.clients)
        self.assertIn("manual", provider.store.clients)


class UsedCodeTests(ProviderTestBase):
    async def test_used_codes_are_pruned_by_ttl(self):
        client = make_client()
        _, token = await self._authorize_and_exchange(client)
        self.assertEqual(len(self.provider._used_codes), 1)
        # Age the replay marker past its TTL and prune.
        self.provider._used_codes = {
            code: (entry[0], entry[1], 0.0)
            for code, entry in self.provider._used_codes.items()
        }
        self.provider._prune_used_codes()
        self.assertEqual(self.provider._used_codes, {})
        # A late replay after pruning is handled cleanly (no crash, no token).
        result = await self.provider.load_authorization_code(client, token.access_token)
        self.assertIsNone(result)


class RefreshTokenFamilyTests(ProviderTestBase):
    """RFC 9700 section 4.14.2: rotating refresh tokens form a family. Presenting
    an already-rotated (replayed) token must revoke the ENTIRE family — including
    the currently-valid latest descendant — not merely reject the replayed token.
    """

    async def _rotate(self, client, token):
        refresh = await self.provider.load_refresh_token(client, token.refresh_token)
        self.assertIsNotNone(refresh)
        return await self.provider.exchange_refresh_token(client, refresh, [])

    def _forge(self, client, token):
        from mcp.server.auth.provider import RefreshToken

        return RefreshToken(
            token=token.refresh_token,
            client_id=client.client_id,
            scopes=list(ALL_SCOPES),
            expires_at=None,
        )

    async def test_replaying_rotated_token_revokes_entire_family(self):
        client = make_client()
        _, token_a = await self._authorize_and_exchange(client)  # token A
        token_b = await self._rotate(client, token_a)            # A -> B
        # Sanity: B is currently usable.
        self.assertIsNotNone(await self.provider.load_access_token(token_b.access_token))
        # Replay A: rejected AND kills the whole family (including the live B).
        self.assertIsNone(
            await self.provider.load_refresh_token(client, token_a.refresh_token)
        )
        self.assertIsNone(
            await self.provider.load_refresh_token(client, token_b.refresh_token)
        )
        self.assertIsNone(await self.provider.load_access_token(token_b.access_token))

    async def test_legitimate_redeem_of_latest_fails_after_replay(self):
        client = make_client()
        _, token_a = await self._authorize_and_exchange(client)
        token_b = await self._rotate(client, token_a)            # A -> B
        # Attacker replays A -> whole family revoked.
        self.assertIsNone(
            await self.provider.load_refresh_token(client, token_a.refresh_token)
        )
        # The legitimate client's subsequent redeem of B must now fail too.
        self.assertIsNone(
            await self.provider.load_refresh_token(client, token_b.refresh_token)
        )
        with self.assertRaises(TokenError):
            await self.provider.exchange_refresh_token(
                client, self._forge(client, token_b), []
            )

    async def test_family_id_is_stable_across_rotation(self):
        client = make_client()
        _, token_a = await self._authorize_and_exchange(client)
        families = {
            record.get("family_id")
            for record in self.provider.store.refresh_tokens.values()
        }
        self.assertEqual(len(families), 1)
        self.assertNotIn(None, families)
        family = families.pop()
        await self._rotate(client, token_a)  # A -> B
        after = {
            record.get("family_id")
            for record in self.provider.store.refresh_tokens.values()
        }
        # The rotated descendant carries the SAME family_id as its parent.
        self.assertEqual(after, {family})

    async def test_reuse_detected_through_exchange_path(self):
        # Defensive: even reaching exchange_refresh_token directly with an
        # already-rotated token must revoke the family, not just reject.
        client = make_client()
        _, token_a = await self._authorize_and_exchange(client)
        token_b = await self._rotate(client, token_a)
        with self.assertRaises(TokenError):
            await self.provider.exchange_refresh_token(
                client, self._forge(client, token_a), []
            )
        self.assertIsNone(await self.provider.load_access_token(token_b.access_token))

    async def test_replay_of_oldest_token_after_two_rotations_kills_current(self):
        # A -> B -> C: replaying the oldest link A still revokes the live C.
        client = make_client()
        _, token_a = await self._authorize_and_exchange(client)
        token_b = await self._rotate(client, token_a)
        token_c = await self._rotate(client, token_b)
        self.assertIsNotNone(await self.provider.load_access_token(token_c.access_token))
        self.assertIsNone(
            await self.provider.load_refresh_token(client, token_a.refresh_token)
        )
        self.assertIsNone(await self.provider.load_access_token(token_c.access_token))

    def test_rotated_refresh_markers_are_capped(self):
        # Mirrors InMemoryCapTests: the rotated-token markers are bounded by
        # count (not only TTL) so heavy rotation cannot grow them without limit.
        import auth.oauth as oauth_mod

        original = oauth_mod.MAX_ROTATED_REFRESH
        oauth_mod.MAX_ROTATED_REFRESH = 5
        try:
            now = time.time()
            for i in range(20):
                self.provider._rotated_refresh[f"h{i}"] = (f"fam{i}", now + i)
            self.provider._prune_rotated_refresh()
            self.assertLessEqual(len(self.provider._rotated_refresh), 5)
            # Newest markers survive; oldest are evicted.
            self.assertIn("h19", self.provider._rotated_refresh)
            self.assertNotIn("h0", self.provider._rotated_refresh)
        finally:
            oauth_mod.MAX_ROTATED_REFRESH = original

    def test_rotated_refresh_markers_pruned_by_ttl(self):
        import auth.oauth as oauth_mod

        # Aged past the TTL, a marker is dropped on prune.
        stale = time.time() - oauth_mod.ROTATED_REFRESH_TTL - 1
        self.provider._rotated_refresh["old"] = ("fam", stale)
        self.provider._rotated_refresh["fresh"] = ("fam2", time.time())
        self.provider._prune_rotated_refresh()
        self.assertNotIn("old", self.provider._rotated_refresh)
        self.assertIn("fresh", self.provider._rotated_refresh)


class ClientSecretStorageTests(ProviderTestBase):
    """Confidential DCR clients must be persisted with only a SHA-256 hash of
    their client_secret; the raw secret must never touch oauth_state.json, and
    get_client must never hand the secret (raw or hashed) back to the SDK."""

    def _confidential(self, secret: str, client_id: str = "confidential-1"):
        return OAuthClientInformationFull.model_validate(
            {
                "client_id": client_id,
                "client_secret": secret,
                "client_id_issued_at": int(time.time()),
                "redirect_uris": [REDIRECT],
                "token_endpoint_auth_method": "client_secret_post",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "scope": " ".join(ALL_SCOPES),
                "client_name": "Confidential client",
            }
        )

    async def test_client_secret_is_hashed_at_rest(self):
        from auth.oauth import hash_client_secret

        secret = "super-secret-value-abc123-xyz"
        await self.provider.register_client(self._confidential(secret))
        raw = self.state_file.read_text(encoding="utf-8")
        # The plaintext secret is nowhere in the persisted state file...
        self.assertNotIn(secret, raw)
        # ...but its hash is.
        self.assertIn(hash_client_secret(secret), raw)

    async def test_stored_secret_survives_reload_as_hash(self):
        from auth.oauth import hash_client_secret

        secret = "another-secret-value-42"
        await self.provider.register_client(self._confidential(secret))
        reloaded = self._make_provider()
        self.assertEqual(
            reloaded.store.clients["confidential-1"]["client_secret"],
            hash_client_secret(secret),
        )

    async def test_get_client_never_exposes_secret(self):
        await self.provider.register_client(self._confidential("hide-me-please"))
        loaded = await self.provider.get_client("confidential-1")
        self.assertIsNotNone(loaded)
        # get_client always blanks the secret so the SDK's own ClientAuthenticator
        # never compares against the stored hash.
        self.assertIsNone(loaded.client_secret)


class DefaultScopeTests(unittest.TestCase):
    def test_dcr_default_scopes_exclude_dangerous_scopes(self):
        settings = build_auth_settings("https://x.serveousercontent.com", "Test")
        options = settings.client_registration_options
        self.assertEqual(set(options.valid_scopes), set(ALL_SCOPES))
        self.assertEqual(set(options.default_scopes), set(DEFAULT_SCOPES))
        self.assertNotIn(SCOPE_COMMANDS_RUN, options.default_scopes)
        self.assertNotIn(SCOPE_GIT, options.default_scopes)

    def test_granted_scopes_fallback_is_least_privilege(self):
        provider = LocalOAuthProvider(
            store=OAuthStore(Path(tempfile.mktemp())),
            issuer_url=ISSUER,
            canonical_resource=RESOURCE,
        )
        client = make_client(scope="")
        params = make_params()
        params.scopes = None
        txn = PendingAuthorization(
            txn_id="t", client=client, params=params, csrf="c"
        )
        self.assertEqual(set(provider.granted_scopes(txn)), set(DEFAULT_SCOPES))


class OwnerGrantScopesTests(unittest.TestCase):
    def _provider(self, owner_scopes):
        return LocalOAuthProvider(
            store=OAuthStore(Path(tempfile.mktemp())),
            issuer_url=ISSUER,
            canonical_resource=RESOURCE,
            owner_grant_scopes=owner_scopes,
        )

    def _txn(self, requested):
        params = make_params()
        params.scopes = requested
        return PendingAuthorization(
            txn_id="t", client=make_client(scope=" ".join(ALL_SCOPES)),
            params=params, csrf="c",
        )

    def test_override_replaces_requested_scopes(self):
        provider = self._provider([SCOPE_FILES_READ, SCOPE_GIT])
        # Client requested everything, but the owner override wins.
        granted = provider.granted_scopes(self._txn(list(ALL_SCOPES)))
        self.assertEqual(set(granted), {SCOPE_FILES_READ, SCOPE_GIT})

    def test_override_filters_invalid_scopes(self):
        provider = self._provider([SCOPE_FILES_READ, "mcp:bogus"])
        self.assertEqual(provider.owner_grant_scopes, [SCOPE_FILES_READ])

    def test_no_override_by_default(self):
        provider = self._provider(None)
        self.assertIsNone(provider.owner_grant_scopes)
        # Falls back to requested scopes when no override is configured.
        granted = provider.granted_scopes(self._txn([SCOPE_FILES_READ]))
        self.assertEqual(granted, [SCOPE_FILES_READ])

    def test_empty_override_is_disabled(self):
        provider = self._provider([])
        self.assertIsNone(provider.owner_grant_scopes)


if __name__ == "__main__":
    unittest.main()
