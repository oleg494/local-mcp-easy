"""Embedded OAuth 2.1 Authorization Server state and provider.

Built on top of the official ``mcp`` SDK server-side auth machinery:
the SDK handlers implement /authorize, /token, /register and /revoke with
PKCE (S256), exact redirect_uri matching, client authentication and
metadata documents. This module supplies the storage-backed
``OAuthAuthorizationServerProvider`` those handlers call into, plus the
consent transaction API used by the /consent page.

Security properties:
- Raw access/refresh tokens are never persisted — only SHA-256 hashes.
- Authorization codes are single-use, short-lived and kept in memory only.
- Reuse of an already-exchanged authorization code revokes the tokens that
  were issued for it (RFC 6749 section 4.1.2 recommendation).
- Refresh tokens rotate on every use; the previous refresh token and the
  access tokens issued with it are invalidated.
- Access tokens are audience-bound to this server's /mcp resource URL
  (RFC 8707); tokens minted for another resource are rejected.
- The static master token (dual mode) is compared in constant time and is
  never written to the OAuth state file.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from .base import ALL_SCOPES, normalize_resource, resources_match
from .legacy import LegacyTokenVerifier

STATE_FILE_VERSION = 1
DEFAULT_ACCESS_TTL = 3600
DEFAULT_REFRESH_TTL = 30 * 24 * 3600
CODE_TTL = 300
TXN_TTL = 600

ACCESS_PREFIX = "mcp_at_"
REFRESH_PREFIX = "mcp_rt_"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now() -> float:
    return time.time()


@dataclass
class PendingAuthorization:
    """An /authorize request waiting for owner approval on /consent."""

    txn_id: str
    client: OAuthClientInformationFull
    params: AuthorizationParams
    csrf: str
    created_at: float = field(default_factory=_now)

    def expired(self) -> bool:
        return _now() > self.created_at + TXN_TTL


class OAuthStore:
    """Persistent OAuth state: registered clients and hashed tokens.

    The state lives outside the repository and the release archive, next to
    config.json (``%LOCALAPPDATA%\\NotionMcpEasy\\oauth_state.json`` on
    Windows). Raw token values are never written to disk.
    """

    def __init__(self, state_file: Path):
        self.state_file = Path(state_file)
        self.clients: dict[str, dict[str, Any]] = {}
        self.access_tokens: dict[str, dict[str, Any]] = {}
        self.refresh_tokens: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        self.clients = dict(raw.get("clients", {}))
        self.access_tokens = dict(raw.get("access_tokens", {}))
        self.refresh_tokens = dict(raw.get("refresh_tokens", {}))
        self.prune()

    def save(self) -> None:
        self.prune()
        payload = {
            "version": STATE_FILE_VERSION,
            "clients": self.clients,
            "access_tokens": self.access_tokens,
            "refresh_tokens": self.refresh_tokens,
        }
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=".oauth_state_", suffix=".tmp", dir=str(self.state_file.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
            os.replace(temp_name, self.state_file)
        except BaseException:
            _unlink_quietly(temp_name)
            raise
        try:
            os.chmod(self.state_file, 0o600)
        except OSError:
            # Windows ACLs already restrict %LOCALAPPDATA% to the current user.
            pass

    def prune(self) -> None:
        now = _now()
        self.access_tokens = {
            key: value
            for key, value in self.access_tokens.items()
            if not value.get("expires_at") or value["expires_at"] > now
        }
        self.refresh_tokens = {
            key: value
            for key, value in self.refresh_tokens.items()
            if not value.get("expires_at") or value["expires_at"] > now
        }


def _unlink_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


class LocalOAuthProvider:
    """OAuthAuthorizationServerProvider backed by OAuthStore.

    ``legacy_verifier`` is set in dual mode only: it lets the static master
    token keep working on /mcp while OAuth clients use short-lived tokens.
    """

    def __init__(
        self,
        store: OAuthStore,
        issuer_url: str,
        canonical_resource: str,
        legacy_verifier: LegacyTokenVerifier | None = None,
        access_ttl: int = DEFAULT_ACCESS_TTL,
        refresh_ttl: int = DEFAULT_REFRESH_TTL,
    ):
        self.store = store
        self.issuer_url = issuer_url.rstrip("/")
        self.canonical_resource = normalize_resource(canonical_resource)
        self.legacy_verifier = legacy_verifier
        self.access_ttl = int(access_ttl)
        self.refresh_ttl = int(refresh_ttl)
        self._txns: dict[str, PendingAuthorization] = {}
        self._codes: dict[str, AuthorizationCode] = {}
        # code -> (access_hash, refresh_hash) issued for it, for replay revocation
        self._used_codes: dict[str, tuple[str, str]] = {}

    # ------------------------------------------------------------------
    # Client registry
    # ------------------------------------------------------------------

    @staticmethod
    def validate_redirect_uris(client_info: OAuthClientInformationFull) -> None:
        from urllib.parse import urlsplit

        for uri in client_info.redirect_uris or []:
            raw = str(uri)
            parts = urlsplit(raw)
            scheme = parts.scheme.lower()
            host = (parts.hostname or "").lower()
            if scheme == "https":
                continue
            if scheme == "http" and host in {"127.0.0.1", "localhost", "::1"}:
                continue
            raise RegistrationError(
                error="invalid_redirect_uri",
                error_description=(
                    "redirect_uri must use https, or http on localhost/127.0.0.1: "
                    f"{raw}"
                ),
            )

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        raw = self.store.clients.get(client_id)
        if raw is None:
            return None
        return OAuthClientInformationFull.model_validate(raw)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self.validate_redirect_uris(client_info)
        self.store.clients[client_info.client_id] = client_info.model_dump(mode="json")
        self.store.save()

    # ------------------------------------------------------------------
    # Authorization flow (consent transactions)
    # ------------------------------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        if params.resource and not resources_match(params.resource, self.canonical_resource):
            raise AuthorizeError(
                error="invalid_request",
                error_description=(
                    "resource indicator does not match this MCP server: "
                    f"{params.resource}"
                ),
            )
        self._prune_txns()
        txn = PendingAuthorization(
            txn_id=secrets.token_urlsafe(24),
            client=client,
            params=params,
            csrf=secrets.token_urlsafe(24),
        )
        self._txns[txn.txn_id] = txn
        return f"{self.issuer_url}/consent?txn={txn.txn_id}"

    def _prune_txns(self) -> None:
        self._txns = {key: txn for key, txn in self._txns.items() if not txn.expired()}

    def _prune_codes(self) -> None:
        now = _now()
        self._codes = {
            key: code for key, code in self._codes.items() if code.expires_at > now
        }

    def get_txn(self, txn_id: str) -> PendingAuthorization | None:
        self._prune_txns()
        return self._txns.get(txn_id)

    def granted_scopes(self, txn: PendingAuthorization) -> list[str]:
        if txn.params.scopes:
            return list(txn.params.scopes)
        registered = (txn.client.scope or "").split()
        return registered or list(ALL_SCOPES)

    def approve_txn(self, txn_id: str) -> str:
        """Owner approved: mint a single-use authorization code."""
        txn = self._txns.pop(txn_id, None)
        if txn is None or txn.expired():
            raise KeyError("authorization request expired")
        code = AuthorizationCode(
            code=secrets.token_urlsafe(32),
            scopes=self.granted_scopes(txn),
            expires_at=_now() + CODE_TTL,
            client_id=txn.client.client_id,
            code_challenge=txn.params.code_challenge,
            redirect_uri=txn.params.redirect_uri,
            redirect_uri_provided_explicitly=txn.params.redirect_uri_provided_explicitly,
            resource=txn.params.resource,
        )
        self._codes[code.code] = code
        return construct_redirect_uri(
            str(txn.params.redirect_uri), code=code.code, state=txn.params.state
        )

    def deny_txn(self, txn_id: str) -> str:
        """Owner denied: send the client an access_denied error."""
        txn = self._txns.pop(txn_id, None)
        if txn is None:
            raise KeyError("authorization request expired")
        return construct_redirect_uri(
            str(txn.params.redirect_uri),
            error="access_denied",
            error_description="The resource owner denied the request",
            state=txn.params.state,
        )

    # ------------------------------------------------------------------
    # Codes and tokens
    # ------------------------------------------------------------------

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        used = self._used_codes.pop(authorization_code, None)
        if used is not None:
            # Replay of an already exchanged code: revoke what it produced.
            access_hash, refresh_hash = used
            self.store.access_tokens.pop(access_hash, None)
            self.refresh_and_children_forget(refresh_hash)
            self.store.save()
            return None
        self._prune_codes()
        code = self._codes.get(authorization_code)
        if code is None or code.client_id != client.client_id:
            return None
        return code

    def refresh_and_children_forget(self, refresh_hash: str) -> None:
        self.store.refresh_tokens.pop(refresh_hash, None)
        self.store.access_tokens = {
            key: value
            for key, value in self.store.access_tokens.items()
            if value.get("refresh_parent") != refresh_hash
        }

    def _issue_tokens(
        self, client_id: str, scopes: list[str]
    ) -> tuple[str, str, str, str]:
        access_token = ACCESS_PREFIX + secrets.token_urlsafe(32)
        refresh_token = REFRESH_PREFIX + secrets.token_urlsafe(32)
        access_hash = _hash_token(access_token)
        refresh_hash = _hash_token(refresh_token)
        now = _now()
        self.store.refresh_tokens[refresh_hash] = {
            "client_id": client_id,
            "scopes": scopes,
            "expires_at": int(now + self.refresh_ttl),
        }
        self.store.access_tokens[access_hash] = {
            "client_id": client_id,
            "scopes": scopes,
            "expires_at": int(now + self.access_ttl),
            "resource": self.canonical_resource,
            "refresh_parent": refresh_hash,
        }
        self.store.save()
        return access_token, refresh_token, access_hash, refresh_hash

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        stored = self._codes.pop(authorization_code.code, None)
        if stored is None:
            raise TokenError(
                error="invalid_grant", error_description="authorization code is not valid"
            )
        if authorization_code.resource and not resources_match(
            authorization_code.resource, self.canonical_resource
        ):
            raise TokenError(
                error="invalid_grant",
                error_description="authorization code was issued for another resource",
            )
        scopes = list(authorization_code.scopes)
        access_token, refresh_token, access_hash, refresh_hash = self._issue_tokens(
            client.client_id, scopes
        )
        self._used_codes[authorization_code.code] = (access_hash, refresh_hash)
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=self.access_ttl,
            refresh_token=refresh_token,
            scope=" ".join(scopes),
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        record = self.store.refresh_tokens.get(_hash_token(refresh_token))
        if record is None or record.get("client_id") != client.client_id:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=record["client_id"],
            scopes=list(record.get("scopes", [])),
            expires_at=record.get("expires_at"),
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        old_hash = _hash_token(refresh_token.token)
        if old_hash not in self.store.refresh_tokens:
            raise TokenError(
                error="invalid_grant", error_description="refresh token is not valid"
            )
        granted = list(scopes) if scopes else list(refresh_token.scopes)
        if not set(granted).issubset(set(refresh_token.scopes)):
            raise TokenError(
                error="invalid_scope",
                error_description="requested scopes exceed the original grant",
            )
        # Rotation: the previous refresh token and its access tokens die here.
        self.refresh_and_children_forget(old_hash)
        access_token, new_refresh_token, _, _ = self._issue_tokens(
            client.client_id, granted
        )
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=self.access_ttl,
            refresh_token=new_refresh_token,
            scope=" ".join(granted),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        if self.legacy_verifier is not None:
            legacy = await self.legacy_verifier.verify_token(token)
            if legacy is not None:
                return legacy
        record = self.store.access_tokens.get(_hash_token(token))
        if record is None:
            return None
        expires_at = record.get("expires_at")
        if expires_at and expires_at < _now():
            return None
        if not resources_match(record.get("resource"), self.canonical_resource):
            # Audience mismatch: the token was minted for another resource URL.
            return None
        return AccessToken(
            token=token,
            client_id=record["client_id"],
            scopes=list(record.get("scopes", [])),
            expires_at=int(expires_at) if expires_at else None,
            resource=record.get("resource"),
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        from .base import LEGACY_CLIENT_ID

        if token.client_id == LEGACY_CLIENT_ID:
            # The master token is not an OAuth token and cannot be revoked here.
            return
        token_hash = _hash_token(token.token)
        if token_hash in self.store.refresh_tokens:
            self.refresh_and_children_forget(token_hash)
        removed = self.store.access_tokens.pop(token_hash, None)
        if removed is not None:
            # Also revoke the sibling refresh token, per SDK guidance.
            parent = removed.get("refresh_parent")
            if parent:
                self.refresh_and_children_forget(parent)
        self.store.save()
