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
  access tokens issued with it are invalidated. Every token in a rotation
  chain shares a family_id, and replaying an already-rotated token revokes the
  whole family — the live descendant included (RFC 9700 section 4.14.2).
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

from .base import ALL_SCOPES, DEFAULT_SCOPES, normalize_resource, resources_match
from .legacy import LegacyTokenVerifier

STATE_FILE_VERSION = 1
DEFAULT_ACCESS_TTL = 3600
DEFAULT_REFRESH_TTL = 30 * 24 * 3600
CODE_TTL = 300
TXN_TTL = 600
# How long a replay marker for an exchanged authorization code is kept. A code
# only lives CODE_TTL, so a window comfortably larger than that catches any
# realistic replay while bounding the in-memory dict.
USED_CODE_TTL = 3600
# Bound the persisted client registry so open Dynamic Client Registration
# cannot grow oauth_state.json without limit.
DEFAULT_MAX_CLIENTS = 100
# DCR-registered clients that never complete authorization are pruned after
# this long. Real clients finish DCR -> authorize -> token within seconds, so
# this both bounds storage and lets a registration flood self-heal quickly.
DEFAULT_UNUSED_CLIENT_TTL = 3600
# Hard count caps (independent of TTL) so a burst of public /authorize or
# /token calls cannot grow these in-memory maps without bound.
MAX_PENDING_TXNS = 512
MAX_USED_CODES = 4096
# Reuse-detection markers for rotated refresh tokens (RFC 9700 section 4.14.2).
# A rotated token can plausibly be replayed until it would have expired, so keep
# its marker for the refresh-token lifetime; the count cap bounds memory under a
# high rotation rate the same way MAX_USED_CODES bounds exchanged auth-codes.
ROTATED_REFRESH_TTL = DEFAULT_REFRESH_TTL
MAX_ROTATED_REFRESH = 4096

ACCESS_PREFIX = "mcp_at_"
REFRESH_PREFIX = "mcp_rt_"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_client_secret(secret: str) -> str:
    """SHA-256 hash of a DCR client_secret for storage/comparison.

    Same SHA-256-over-utf8-hex scheme as access/refresh token hashing; kept as
    a distinct, public name because it is the sole thing shared between the
    OAuthStore (which hashes secrets at rest) and the server's
    ClientSecretAuthMiddleware (which hashes the presented secret to compare)."""
    return _hash_token(secret)


def _now() -> float:
    return time.time()


def _as_dict_of_dicts(value: Any) -> dict[str, Any]:
    """Coerce a loaded JSON value into a str->dict mapping, dropping anything
    malformed. Guards against a hand-edited or corrupted state file (e.g.
    ``{"clients": null}`` or a stray scalar) crashing startup."""
    if not isinstance(value, dict):
        return {}
    return {
        key: val
        for key, val in value.items()
        if isinstance(key, str) and isinstance(val, dict)
    }


@dataclass
class PendingAuthorization:
    """An /authorize request waiting for owner approval on /consent."""

    txn_id: str
    client: OAuthClientInformationFull
    params: AuthorizationParams
    csrf: str
    created_at: float = field(default_factory=_now)
    attempts: int = 0

    def expired(self) -> bool:
        return _now() > self.created_at + TXN_TTL


class OAuthStore:
    """Persistent OAuth state: registered clients and hashed tokens.

    The state lives outside the repository and the release archive, next to
    config.json (``%LOCALAPPDATA%\\LocalMcpEasy\\oauth_state.json`` on
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
            # utf-8-sig tolerates a BOM (symmetry with the launcher config
            # loader); a BOM would otherwise silently reset the whole state.
            raw = json.loads(self.state_file.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        version = raw.get("version", 0)
        if not isinstance(version, int) or version > STATE_FILE_VERSION:
            # Unknown or newer schema: start clean rather than misinterpret it.
            return
        self.clients = _as_dict_of_dicts(raw.get("clients"))
        self.access_tokens = _as_dict_of_dicts(raw.get("access_tokens"))
        self.refresh_tokens = _as_dict_of_dicts(raw.get("refresh_tokens"))
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

    def store_client(self, client_id: str, record: dict[str, Any]) -> None:
        """Persist a client record with any raw client_secret replaced by its
        SHA-256 hash, so oauth_state.json never holds the plaintext secret.

        The raw secret is disclosed to the client exactly once, in the DCR HTTP
        response (which serializes the input object, not this stored copy);
        secret correctness at /token is enforced by the server's
        ClientSecretAuthMiddleware against the hash stored here."""
        record = dict(record)
        secret = record.get("client_secret")
        if secret:
            record["client_secret"] = hash_client_secret(secret)
        self.clients[client_id] = record

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


def _reject_redirect(raw: str, reason: str) -> None:
    raise RegistrationError(
        error="invalid_redirect_uri",
        error_description=f"invalid redirect_uri ({reason}): {raw}",
    )


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
        max_clients: int = DEFAULT_MAX_CLIENTS,
        unused_client_ttl: int = DEFAULT_UNUSED_CLIENT_TTL,
        owner_grant_scopes: list[str] | None = None,
    ):
        self.store = store
        self.issuer_url = issuer_url.rstrip("/")
        self.canonical_resource = normalize_resource(canonical_resource)
        self.legacy_verifier = legacy_verifier
        self.access_ttl = int(access_ttl)
        self.refresh_ttl = int(refresh_ttl)
        self.max_clients = max(1, int(max_clients))
        self.unused_client_ttl = int(unused_client_ttl)
        self.owner_grant_scopes = (
            [scope for scope in owner_grant_scopes if scope in ALL_SCOPES]
            if owner_grant_scopes
            else None
        )
        self._txns: dict[str, PendingAuthorization] = {}
        self._codes: dict[str, AuthorizationCode] = {}
        # code -> (access_hash, refresh_hash, created_at) for replay revocation
        self._used_codes: dict[str, tuple[str, str, float]] = {}
        # Reuse-detection markers for already-rotated refresh tokens: hash ->
        # (family_id, rotated_at). Kept even after the token record itself is
        # deleted so a later replay can still be recognized and the whole
        # family revoked (RFC 9700 section 4.14.2).
        self._rotated_refresh: dict[str, tuple[str, float]] = {}

    # ------------------------------------------------------------------
    # Client registry
    # ------------------------------------------------------------------

    @staticmethod
    def validate_redirect_uris(client_info: OAuthClientInformationFull) -> None:
        from urllib.parse import urlsplit

        loopback = {"127.0.0.1", "localhost", "::1"}
        for uri in client_info.redirect_uris or []:
            raw = str(uri)
            parts = urlsplit(raw)
            scheme = parts.scheme.lower()
            host = (parts.hostname or "").lower()
            if scheme not in {"https", "http"}:
                _reject_redirect(raw, "scheme must be https or http")
            if parts.fragment:
                _reject_redirect(raw, "must not contain a fragment")
            if parts.username or parts.password:
                _reject_redirect(raw, "must not contain userinfo")
            if not host:
                # Rejects opaque forms like "https:opaque" that have no host.
                _reject_redirect(raw, "must include a host")
            if scheme == "http" and host not in loopback:
                _reject_redirect(
                    raw, "http is only allowed on loopback (127.0.0.1/localhost/::1)"
                )

    def _client_has_tokens(self, client_id: str) -> bool:
        for record in self.store.access_tokens.values():
            if record.get("client_id") == client_id:
                return True
        for record in self.store.refresh_tokens.values():
            if record.get("client_id") == client_id:
                return True
        return False

    def prune_clients(self) -> None:
        """Drop DCR clients that registered but never obtained tokens within
        ``unused_client_ttl``. Manually registered clients (no
        ``client_id_issued_at``) and clients with live tokens are protected."""
        cutoff = _now() - self.unused_client_ttl
        for client_id in list(self.store.clients):
            record = self.store.clients.get(client_id, {})
            issued = record.get("client_id_issued_at")
            if (
                isinstance(issued, (int, float))
                and issued < cutoff
                and not self._client_has_tokens(client_id)
            ):
                del self.store.clients[client_id]

    def _evict_one_unused_client(self) -> bool:
        """Make room for a new registration by dropping the oldest DCR client
        that has no tokens. Never evicts token-bearing or manually registered
        (``client_id_issued_at`` is None) clients."""
        candidates = [
            (record.get("client_id_issued_at"), client_id)
            for client_id, record in self.store.clients.items()
            if isinstance(record.get("client_id_issued_at"), (int, float))
            and not self._client_has_tokens(client_id)
        ]
        if not candidates:
            return False
        candidates.sort(key=lambda item: item[0])
        del self.store.clients[candidates[0][1]]
        return True

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        raw = self.store.clients.get(client_id)
        if raw is None:
            return None
        # The stored client_secret is a SHA-256 hash, never the raw value, and
        # ClientSecretAuthMiddleware is now the sole real enforcer of secret
        # correctness. Blank the secret here so the SDK's own ClientAuthenticator
        # comparison (against get_client's return) is always skipped as falsy —
        # which is safe, because a request lacking a valid secret is already
        # rejected by the middleware before the SDK handler runs — and so the
        # stored hash never leaks back out through get_client.
        data = dict(raw)
        data["client_secret"] = None
        return OAuthClientInformationFull.model_validate(data)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self.validate_redirect_uris(client_info)
        self.prune_clients()
        while len(self.store.clients) >= self.max_clients:
            if not self._evict_one_unused_client():
                raise RegistrationError(
                    error="invalid_client_metadata",
                    error_description=(
                        "client registration limit reached; remove unused clients "
                        "or try again later"
                    ),
                )
        self.store.store_client(
            client_info.client_id, client_info.model_dump(mode="json")
        )
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
        if len(self._txns) > MAX_PENDING_TXNS:
            # Bound memory under a burst of /authorize calls: drop the oldest.
            for key in sorted(self._txns, key=lambda k: self._txns[k].created_at)[
                : len(self._txns) - MAX_PENDING_TXNS
            ]:
                self._txns.pop(key, None)

    def _prune_codes(self) -> None:
        now = _now()
        self._codes = {
            key: code for key, code in self._codes.items() if code.expires_at > now
        }

    def _prune_used_codes(self) -> None:
        cutoff = _now() - USED_CODE_TTL
        self._used_codes = {
            code: entry
            for code, entry in self._used_codes.items()
            if entry[2] > cutoff
        }
        if len(self._used_codes) > MAX_USED_CODES:
            for code in sorted(self._used_codes, key=lambda c: self._used_codes[c][2])[
                : len(self._used_codes) - MAX_USED_CODES
            ]:
                self._used_codes.pop(code, None)

    def _prune_rotated_refresh(self) -> None:
        cutoff = _now() - ROTATED_REFRESH_TTL
        self._rotated_refresh = {
            token_hash: entry
            for token_hash, entry in self._rotated_refresh.items()
            if entry[1] > cutoff
        }
        if len(self._rotated_refresh) > MAX_ROTATED_REFRESH:
            for token_hash in sorted(
                self._rotated_refresh, key=lambda h: self._rotated_refresh[h][1]
            )[: len(self._rotated_refresh) - MAX_ROTATED_REFRESH]:
                self._rotated_refresh.pop(token_hash, None)

    def get_txn(self, txn_id: str) -> PendingAuthorization | None:
        self._prune_txns()
        return self._txns.get(txn_id)

    def invalidate_txn(self, txn_id: str) -> None:
        """Drop a pending authorization (e.g. too many wrong owner-code tries)."""
        self._txns.pop(txn_id, None)

    def granted_scopes(self, txn: PendingAuthorization) -> list[str]:
        # Single-owner override: every token is gated by the owner code on
        # /consent, so when the owner opts in we grant a fixed scope set
        # regardless of what the client requested. Off by default.
        if self.owner_grant_scopes:
            return list(self.owner_grant_scopes)
        if txn.params.scopes:
            return list(txn.params.scopes)
        registered = (txn.client.scope or "").split()
        return registered or list(DEFAULT_SCOPES)

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
        self._prune_used_codes()
        used = self._used_codes.pop(authorization_code, None)
        if used is not None:
            # Replay of an already exchanged code: revoke what it produced.
            access_hash, refresh_hash, _ = used
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

    def _prune_rotated_refresh(self) -> None:
        cutoff = _now() - ROTATED_REFRESH_TTL
        self._rotated_refresh = {
            key: entry
            for key, entry in self._rotated_refresh.items()
            if entry[1] > cutoff
        }
        if len(self._rotated_refresh) > MAX_ROTATED_REFRESH:
            for key in sorted(
                self._rotated_refresh, key=lambda k: self._rotated_refresh[k][1]
            )[: len(self._rotated_refresh) - MAX_ROTATED_REFRESH]:
                self._rotated_refresh.pop(key, None)

    def _revoke_family(self, family_id: str) -> None:
        """RFC 9700 section 4.14.2: reuse of a rotated refresh token revokes
        every token descended from its family, including the currently-valid
        latest descendant, not merely the replayed token itself."""
        if not family_id:
            # Never mass-revoke on a missing family (would sweep legacy records).
            return
        dead = [
            refresh_hash
            for refresh_hash, record in self.store.refresh_tokens.items()
            if record.get("family_id") == family_id
        ]
        for refresh_hash in dead:
            self.refresh_and_children_forget(refresh_hash)
        self.store.save()

    def _issue_tokens(
        self, client_id: str, scopes: list[str], family_id: str | None = None
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
            "family_id": family_id or secrets.token_hex(16),
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
        self._used_codes[authorization_code.code] = (access_hash, refresh_hash, _now())
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
        token_hash = _hash_token(refresh_token)
        record = self.store.refresh_tokens.get(token_hash)
        if record is None:
            self._prune_rotated_refresh()
            rotated = self._rotated_refresh.get(token_hash)
            if rotated is not None:
                # Replay of an already-rotated token: kill the whole family,
                # including whatever descendant is currently live.
                self._revoke_family(rotated[0])
            return None
        if record.get("client_id") != client.client_id:
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
        record = self.store.refresh_tokens.get(old_hash)
        if record is None:
            self._prune_rotated_refresh()
            rotated = self._rotated_refresh.get(old_hash)
            if rotated is not None:
                self._revoke_family(rotated[0])
            raise TokenError(
                error="invalid_grant", error_description="refresh token is not valid"
            )
        granted = list(scopes) if scopes else list(refresh_token.scopes)
        if not set(granted).issubset(set(refresh_token.scopes)):
            raise TokenError(
                error="invalid_scope",
                error_description="requested scopes exceed the original grant",
            )
        # A token loaded from a pre-family state file has no family_id; give it
        # one now so the whole chain from this rotation onward is linked and a
        # later replay never revokes on a None family.
        family_id = record.get("family_id") or secrets.token_hex(16)
        # Rotation: the previous refresh token and its access tokens die here,
        # but a marker survives so a later replay of THIS token is still
        # recognized as reuse even after the record itself is gone.
        self.refresh_and_children_forget(old_hash)
        self._prune_rotated_refresh()
        self._rotated_refresh[old_hash] = (family_id, _now())
        access_token, new_refresh_token, _, _ = self._issue_tokens(
            client.client_id, granted, family_id=family_id
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
