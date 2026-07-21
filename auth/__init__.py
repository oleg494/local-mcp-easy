"""Authorization layer for Notion Local MCP Easy (Universal).

Modes:
- legacy: static master Bearer token only (1.4.x behaviour, Notion).
- oauth:  OAuth 2.1 only (Hyperagent and other MCP clients).
- dual:   both of the above on the same /mcp endpoint.
"""
from .base import (
    ALL_SCOPES,
    AUTH_MODE_DUAL,
    AUTH_MODE_LEGACY,
    AUTH_MODE_OAUTH,
    AUTH_MODES,
    LEGACY_CLIENT_ID,
    SCOPE_COMMANDS_RUN,
    SCOPE_DESCRIPTIONS,
    SCOPE_FILES_READ,
    SCOPE_FILES_WRITE,
    SCOPE_GIT,
    normalize_resource,
    parse_auth_mode,
    resources_match,
)
from .consent import ConsentHandler
from .discovery import (
    build_auth_settings,
    protected_resource_document,
    resource_url_for,
)
from .legacy import LegacyTokenVerifier
from .oauth import LocalOAuthProvider, OAuthStore

__all__ = [
    "ALL_SCOPES",
    "AUTH_MODES",
    "AUTH_MODE_DUAL",
    "AUTH_MODE_LEGACY",
    "AUTH_MODE_OAUTH",
    "ConsentHandler",
    "LEGACY_CLIENT_ID",
    "LegacyTokenVerifier",
    "LocalOAuthProvider",
    "OAuthStore",
    "SCOPE_COMMANDS_RUN",
    "SCOPE_DESCRIPTIONS",
    "SCOPE_FILES_READ",
    "SCOPE_FILES_WRITE",
    "SCOPE_GIT",
    "build_auth_settings",
    "normalize_resource",
    "parse_auth_mode",
    "protected_resource_document",
    "resource_url_for",
    "resources_match",
]
