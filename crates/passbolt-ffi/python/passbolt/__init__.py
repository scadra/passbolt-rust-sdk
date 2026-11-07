"""Passbolt SDK: the Rust SDK, with Python names.

    import passbolt

    with passbolt.Client.login(url, private_key, passphrase) as client:
        for view in client.list_resource_views("github"):
            print(view.name, view.username)

The calls block. The generated UniFFI module is ``passbolt._ffi``; this package adds keyword
login options, a context manager and Python names for its errors.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Optional, cast

from ._ffi.passbolt_ffi import (
    Aro,
    Comment,
    DeleteBlockers,
    Favorite,
    Folder,
    FolderQuery,
    FolderTreeNode,
    GpgKey,
    Group,
    GroupDeleteDryRun,
    GroupUser,
    LoginOptions,
    ManagedGroup,
    MetadataKeysSettings,
    MetadataTypesSettings,
    NewResource,
    OwnedItem,
    PassboltClient,
    PassboltError,
    PasswordExpirySettings,
    Permission,
    Resource,
    ResourceChanges,
    ResourceQuery,
    ResourceType,
    ResourceView,
    Role,
    Secret,
    SecretData,
    ServerKey,
    Tag,
    TotpData,
    User,
    UserDeleteDryRun,
    UserProfile,
    UserQuery,
    decrypt_message,
    encrypt_message,
    fetch_server_key,
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
    "NewResource",
    "NotFoundError",
    "OwnedItem",
    "PassboltError",
    "PasswordExpirySettings",
    "Permission",
    "PermissionType",
    "Resource",
    "ResourceChanges",
    "ResourceQuery",
    "ResourceType",
    "ResourceView",
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

#: Base class of every error the SDK raises; its subclasses say what failed.
TransportError = PassboltError.Transport
AuthError = PassboltError.Auth
CryptoError = PassboltError.Crypto
#: The server answered with an error: ``status`` is the HTTP status.
ApiError = PassboltError.Api
NotFoundError = PassboltError.NotFound
ConfigError = PassboltError.Config
InvalidArgumentError = PassboltError.InvalidArgument


def _error_message(error: PassboltError) -> str:
    reason = str(getattr(error, "reason", ""))
    status = getattr(error, "status", None)
    return f"{reason} (HTTP {status})" if status is not None else reason


# The generated message is "reason='…'": show the reason itself.
PassboltError.__str__ = _error_message  # type: ignore[assignment]


class PermissionType(IntEnum):
    """Passbolt's permission types, for ``share_resource`` and ``share_folder``."""

    READ = 1
    UPDATE = 7
    OWNER = 15
    #: Removes the access of the users and groups given.
    REVOKE = -1


class Client(PassboltClient):
    """A logged-in session. Use it as a context manager to log out at the end::

        with passbolt.Client.login(url, private_key, passphrase) as client:
            ...

    The other methods are those of the generated ``PassboltClient``.
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
