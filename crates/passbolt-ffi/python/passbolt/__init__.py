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


# ── Client ──────────────────────────────────────────────────────────────────

JsonObject = Dict[str, Any]


def _json_fields(fields: Union[Mapping[str, Any], str, None], extra: Mapping[str, Any]) -> str:
    if isinstance(fields, str):
        if extra:
            raise TypeError("give the fields as JSON text or as keyword arguments, not both")
        return fields
    return json.dumps({**(fields or {}), **extra})


class Client(PassboltClient):
    """A logged-in session. Use it as a context manager to log out at the end::

        with passbolt.Client.login(url, private_key, passphrase) as client:
            ...

    The methods not redefined here are those of the generated ``PassboltClient``.
    """

    @classmethod
    def login(  # type: ignore[override]
        cls,
        server_url: str,
        private_key_armored: str,
        passphrase: str,
        *,
        server_public_key: Optional[str] = None,
        metadata_key_fingerprint: Optional[str] = None,
        mfa_totp_token: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        tls_skip_verify: bool = False,
        proxy: Optional[str] = None,
        client_certificate_pem: Optional[str] = None,
        client_key_pem: Optional[str] = None,
    ) -> Client:
        """Log in with GPGAuth.

        ``server_public_key`` and ``metadata_key_fingerprint`` pin the keys saved earlier;
        ``mfa_totp_token`` is the base32 TOTP secret of an account with TOTP;
        ``timeout_seconds`` is 60 by default, 0 waits forever.
        """
        options = LoginOptions(
            tls_skip_verify=tls_skip_verify,
            proxy=proxy,
            mfa_totp_token=mfa_totp_token,
            server_public_key=server_public_key,
            metadata_key_fingerprint=metadata_key_fingerprint,
            timeout_seconds=timeout_seconds,
            client_certificate_pem=client_certificate_pem,
            client_key_pem=client_key_pem,
        )
        client = cls.login_with_config(server_url, private_key_armored, passphrase, options)
        return cast(Client, client)

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.logout()

    # Resource views and writes: JSON on the FFI side, dicts here.

    def get_resource_view(self, id: str) -> JsonObject:  # type: ignore[override]
        """A resource with its metadata and secret decrypted: ``name``, ``username``, ``uris``,
        ``description``, ``password``, ``metadata``, ``secret``…"""
        return cast(JsonObject, json.loads(super().get_resource_view(id)))

    def list_resource_views(  # type: ignore[override]
        self, search: Optional[str] = None, with_secrets: bool = False
    ) -> List[JsonObject]:
        """The resources with their metadata decrypted, searched by name; with their secrets too
        with ``with_secrets``. One that does not decrypt has an ``error``."""
        views = super().list_resource_views(search, with_secrets)
        return cast(List[JsonObject], json.loads(views))

    def create_resource(  # type: ignore[override]
        self, fields: Union[Mapping[str, Any], str, None] = None, /, **kwargs: Any
    ) -> Resource:
        """Create a resource of any type: ``create_resource(name="GitHub", password="…")``.

        The fields: ``name``, ``username``, ``uris``, ``description``, ``password``, ``totp``,
        ``note``, ``pin_code``, ``custom_fields``, ``folder_parent_id``, ``expired``,
        ``resource_type``, ``metadata_fields``, ``secret_fields``."""
        return super().create_resource(_json_fields(fields, kwargs))

    def update_resource(  # type: ignore[override]
        self, id: str, changes: Union[Mapping[str, Any], str, None] = None, /, **kwargs: Any
    ) -> Resource:
        """Change the fields given, keep the others: ``update_resource(id, password="new")``;
        ``expired=None`` clears the expiry."""
        return super().update_resource(id, _json_fields(changes, kwargs))

    # Optional arguments.

