"""Passbolt SDK: the Rust SDK, with Python names.

    import passbolt

    with passbolt.Client.login(url, private_key, passphrase) as client:
        for view in client.list_resource_views("github"):
            print(view["name"], view["username"])

The calls block. The generated UniFFI module is ``passbolt._ffi``; this package adds keyword
arguments, a context manager, parsed JSON and Python names for its types and errors.
"""

from __future__ import annotations

import json
from enum import IntEnum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union, cast

from ._ffi.passbolt_ffi import (
    FfiAro,
    FfiComment,
    FfiDeleteBlockers,
    FfiFavorite,
    FfiFolder,
    FfiFolderQuery,
    FfiFolderTreeNode,
    FfiGpgKey,
    FfiGroup,
    FfiGroupDeleteDryRun,
    FfiGroupUser,
    FfiLoginOptions,
    FfiManagedGroup,
    FfiMetadataKeysSettings,
    FfiMetadataTypesSettings,
    FfiOwnedItem,
    FfiPasswordExpirySettings,
    FfiPermission,
    FfiResource,
    FfiResourceQuery,
    FfiResourceType,
    FfiRole,
    FfiSecret,
    FfiSecretData,
    FfiServerKey,
    FfiTag,
    FfiTotpData,
    FfiUser,
    FfiUserDeleteDryRun,
    FfiUserProfile,
    FfiUserQuery,
    PassboltClient,
    PassboltFfiError,
    decrypt_message,
    encrypt_message,
    fetch_server_key as _fetch_server_key,
    get_key_fingerprint,
)

__all__ = [
    "ApiError",
    "Aro",
    "AuthError",
    "Client",
    "Comment",
    "ConfigError",
    "CryptoError",
    "DeleteBlockers",
    "Favorite",
    "Folder",
    "FolderQuery",
    "FolderTreeNode",
    "GpgKey",
    "Group",
    "GroupDeleteDryRun",
    "GroupUser",
    "InvalidArgumentError",
    "LoginOptions",
    "ManagedGroup",
    "MetadataKeysSettings",
    "MetadataTypesSettings",
    "NotFoundError",
    "OwnedItem",
    "PassboltError",
    "PasswordExpirySettings",
    "Permission",
    "PermissionType",
    "Resource",
    "ResourceQuery",
    "ResourceType",
    "Role",
    "Secret",
    "SecretData",
    "ServerKey",
    "Tag",
    "TotpData",
    "TransportError",
    "User",
    "UserDeleteDryRun",
    "UserProfile",
    "UserQuery",
    "decrypt_message",
    "encrypt_message",
    "fetch_server_key",
    "get_key_fingerprint",
]

# ── Errors ──────────────────────────────────────────────────────────────────

#: Base class of every error the SDK raises; its subclasses say what failed.
PassboltError = PassboltFfiError
TransportError = PassboltFfiError.Transport
AuthError = PassboltFfiError.Auth
CryptoError = PassboltFfiError.Crypto
#: The server answered with an error: ``status`` is the HTTP status.
ApiError = PassboltFfiError.Api
NotFoundError = PassboltFfiError.NotFound
ConfigError = PassboltFfiError.Config
InvalidArgumentError = PassboltFfiError.InvalidArgument


def _error_message(error: PassboltFfiError) -> str:
    reason = str(getattr(error, "reason", ""))
    status = getattr(error, "status", None)
    return f"{reason} (HTTP {status})" if status is not None else reason


# The generated message is "reason='…'": show the reason itself.
PassboltFfiError.__str__ = _error_message  # type: ignore[assignment]

# ── Types ───────────────────────────────────────────────────────────────────

Aro = FfiAro
Comment = FfiComment
DeleteBlockers = FfiDeleteBlockers
Favorite = FfiFavorite
Folder = FfiFolder
FolderQuery = FfiFolderQuery
FolderTreeNode = FfiFolderTreeNode
GpgKey = FfiGpgKey
Group = FfiGroup
GroupDeleteDryRun = FfiGroupDeleteDryRun
GroupUser = FfiGroupUser
LoginOptions = FfiLoginOptions
ManagedGroup = FfiManagedGroup
MetadataKeysSettings = FfiMetadataKeysSettings
MetadataTypesSettings = FfiMetadataTypesSettings
OwnedItem = FfiOwnedItem
PasswordExpirySettings = FfiPasswordExpirySettings
Permission = FfiPermission
Resource = FfiResource
ResourceQuery = FfiResourceQuery
ResourceType = FfiResourceType
Role = FfiRole
Secret = FfiSecret
SecretData = FfiSecretData
ServerKey = FfiServerKey
Tag = FfiTag
TotpData = FfiTotpData
User = FfiUser
UserDeleteDryRun = FfiUserDeleteDryRun
UserProfile = FfiUserProfile
UserQuery = FfiUserQuery


class PermissionType(IntEnum):
    """Passbolt's permission types, for ``share_resource`` and ``share_folder``."""

    READ = 1
    UPDATE = 7
    OWNER = 15
    #: Removes the access of the users and groups given.
    REVOKE = -1


def fetch_server_key(server_url: str, *, tls_skip_verify: bool = False) -> ServerKey:
    """The server public key and its fingerprint, to pin with
    ``Client.login(server_public_key=…)`` once the user confirmed the fingerprint."""
    return _fetch_server_key(server_url, tls_skip_verify)


