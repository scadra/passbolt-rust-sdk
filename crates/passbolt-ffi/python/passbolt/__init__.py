"""Passbolt SDK: the Rust SDK, with Python names.

    import passbolt

    with passbolt.Client.login(url, private_key, passphrase) as client:
        for view in client.list_resource_views("github"):
            print(view.name, view.username)

The calls block; ``passbolt.AsyncClient`` has the same methods to ``await``::

    async with await passbolt.AsyncClient.login(url, private_key, passphrase) as client:
        views = await client.list_resource_views("github")

The generated UniFFI module is ``passbolt._ffi``; this package adds keyword login options,
context managers and Python names for its errors.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Optional, cast

from ._ffi.passbolt_ffi import (
    AsyncPassboltClient,
    Aro,
    Comment,
    DeleteBlockers,
    Favorite,
    Folder,
    FolderQuery,
    FolderTreeNode,
    GeneratorType,
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
    PassphraseGeneratorSettings,
    PasswordExpirySettings,
    PasswordGeneratorSettings,
    PasswordPolicies,
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
    Strength,
    Tag,
    TotpData,
    User,
    UserDeleteDryRun,
    UserProfile,
    UserQuery,
    WordCase,
    decrypt_message,
    default_password_policies,
    encrypt_message,
    fetch_server_key,
    generate_pin_code,
    get_key_fingerprint,
    secret_entropy,
    secret_strength,
)
from ._ffi.passbolt_ffi import generate_passphrase as _generate_passphrase
from ._ffi.passbolt_ffi import generate_password as _generate_password
from ._ffi.passbolt_ffi import generate_secret as _generate_secret

__all__ = [
    "ApiError",
    "Aro",
    "AsyncClient",
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
    "GeneratorType",
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
    "PassphraseGeneratorSettings",
    "PasswordExpirySettings",
    "PasswordGeneratorSettings",
    "PasswordPolicies",
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
    "Strength",
    "Tag",
    "TotpData",
    "TransportError",
    "User",
    "UserDeleteDryRun",
    "UserProfile",
    "UserQuery",
    "WordCase",
    "decrypt_message",
    "default_password_policies",
    "encrypt_message",
    "fetch_server_key",
    "generate_passphrase",
    "generate_password",
    "generate_pin_code",
    "generate_secret",
    "get_key_fingerprint",
    "secret_entropy",
    "secret_strength",
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


def generate_password(settings: Optional[PasswordGeneratorSettings] = None) -> str:
    """A password drawn as the browser extension draws it, from ``settings``: by default 18
    characters of every set but emoji. ``PasswordGeneratorSettings(length=24)`` keeps the other
    defaults."""
    return _generate_password(settings or PasswordGeneratorSettings())


def generate_passphrase(settings: Optional[PassphraseGeneratorSettings] = None) -> str:
    """A passphrase of words of the EFF list, from ``settings``: by default 9 lowercase words
    joined by spaces."""
    return _generate_passphrase(settings or PassphraseGeneratorSettings())


def generate_secret(policies: Optional[PasswordPolicies] = None) -> str:
    """A secret from the default generator of ``policies``, those of
    ``client.get_password_policies()``; without them, the defaults of Passbolt."""
    return _generate_secret(policies or default_password_policies())


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

    def __exit__(self, exc_type: object, *exc_info: object) -> None:
        # A failed logout raises, unless it would hide the exception that left the block.
        try:
            self.logout()
        except PassboltError:
            if exc_type is None:
                raise


class AsyncClient(AsyncPassboltClient):
    """A logged-in session whose calls are awaited, for asyncio. Use it as an async context
    manager to log out at the end::

        async with await passbolt.AsyncClient.login(url, private_key, passphrase) as client:
            ...

    The methods are those of ``Client``, as coroutines; the network calls run on the SDK's own
    threads, the event loop goes on meanwhile.
    """

    @classmethod
    async def login(  # type: ignore[override]
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
    ) -> AsyncClient:
        """Log in with GPGAuth; the options are those of ``Client.login``."""
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
        client = await AsyncPassboltClient.login_with_config(
            server_url, private_key_armored, passphrase, options
        )
        # The generated constructor makes an AsyncPassboltClient, whatever the class.
        client.__class__ = cls
        return cast(AsyncClient, client)

    async def __aenter__(self) -> AsyncClient:
        return self

    async def __aexit__(self, exc_type: object, *exc_info: object) -> None:
        # The same rule as Client.__exit__.
        try:
            await self.logout()
        except PassboltError:
            if exc_type is None:
                raise
