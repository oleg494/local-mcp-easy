"""Constant-time verification of the static master Bearer token.

This mirrors the 1.4.x behaviour: one shared secret grants full access to
every MCP tool. In ``dual`` mode this verifier runs before the OAuth token
lookup, so Notion keeps connecting exactly as before.
"""
from __future__ import annotations

import hmac

from mcp.server.auth.provider import AccessToken

from .base import ALL_SCOPES, LEGACY_CLIENT_ID


class LegacyTokenVerifier:
    """TokenVerifier for the static master token (full access, no expiry)."""

    def __init__(self, token: str):
        if not token:
            raise ValueError("Legacy token must not be empty")
        self._token = token

    def matches(self, candidate: str) -> bool:
        if not candidate:
            return False
        return hmac.compare_digest(candidate, self._token)

    async def verify_token(self, token: str) -> AccessToken | None:
        if not self.matches(token):
            return None
        return AccessToken(
            token=token,
            client_id=LEGACY_CLIENT_ID,
            scopes=list(ALL_SCOPES),
            expires_at=None,
        )
