# The installed wheel loads its native library, maps Rust errors to Python exceptions and
# exposes the Python names of the generated bindings.
import asyncio

import passbolt
from passbolt import _ffi

try:
    passbolt.get_key_fingerprint("not a key")
except passbolt.CryptoError as error:
    assert isinstance(error, passbolt.PassboltError), type(error).__mro__
    assert str(error) == error.reason, str(error)
    print(f"ok: {error!r}")
else:
    raise SystemExit("expected a crypto error")

missing = [
    name
    for name in _ffi.passbolt_ffi.__all__
    if name not in ("PassboltClient", "AsyncPassboltClient", "InternalError")
    and not hasattr(passbolt, name)
]
assert not missing, f"not exported by passbolt: {missing}"
assert all(hasattr(passbolt, name) for name in passbolt.__all__)
assert issubclass(passbolt.Client, _ffi.PassboltClient)
assert hasattr(passbolt.Client, "__enter__") and hasattr(passbolt.Client, "__exit__")
print("ok: passbolt names")
assert issubclass(passbolt.AsyncClient, _ffi.AsyncPassboltClient)
assert hasattr(passbolt.AsyncClient, "__aenter__") and hasattr(passbolt.AsyncClient, "__aexit__")


async def refused_login() -> passbolt.PassboltError:
    try:
        await passbolt.AsyncClient.login("https://127.0.0.1:9", "not a key", "")
    except passbolt.CryptoError as error:
        return error
    raise SystemExit("expected a crypto error")


# The awaited call runs on the SDK's runtime and raises with its fields, as the blocking one.
print(f"ok: async {asyncio.run(refused_login())!r}")
