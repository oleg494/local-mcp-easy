"""OAuth discovery configuration for the FastMCP HTTP application.

The SDK publishes, based on AuthSettings:
- /.well-known/oauth-authorization-server (RFC 8414 metadata),
- /.well-known/oauth-protected-resource/mcp (RFC 9728, path-aware),
- WWW-Authenticate with resource_metadata on 401/403 responses from /mcp,
- /authorize, /token, /register (DCR) and /revoke endpoints.

This module builds those settings and the extra root-level protected
resource document some clients still request (spec revisions before
2025-06 used the non path-aware form).
"""
from __future__ import annotations

from typing import Any

from mcp.server.auth.settings import (
    AuthSettings,
    ClientRegistrationOptions,
    RevocationOptions,
)
from mcp.shared.auth import ProtectedResourceMetadata

from .base import ALL_SCOPES, DEFAULT_SCOPES


def resource_url_for(public_url: str) -> str:
    return public_url.rstrip("/") + "/mcp"


def build_auth_settings(public_url: str, resource_name: str) -> AuthSettings:
    issuer = public_url.rstrip("/")
    return AuthSettings(
        issuer_url=issuer,
        service_documentation_url=None,
        resource_server_url=resource_url_for(issuer),
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            # Clients MAY request any scope, but a client that registers
            # without asking for scopes gets the least-privilege default
            # (workspace read/write) — not command execution or git.
            valid_scopes=list(ALL_SCOPES),
            default_scopes=list(DEFAULT_SCOPES),
        ),
        revocation_options=RevocationOptions(enabled=True),
        # Scope enforcement is per tool (deny-by-default in server.tool());
        # transport-level middleware only requires an authenticated token.
        required_scopes=None,
    )


def protected_resource_document(public_url: str) -> dict[str, Any]:
    """RFC 9728 document served additionally at the non path-aware location."""
    issuer = public_url.rstrip("/")
    metadata = ProtectedResourceMetadata(
        resource=resource_url_for(issuer),
        authorization_servers=[issuer],
        scopes_supported=list(ALL_SCOPES),
    )
    return metadata.model_dump(mode="json", exclude_none=True)
