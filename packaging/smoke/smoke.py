# The installed wheel loads its native library, maps Rust errors to Python exceptions and
# exposes the Python names of the generated bindings.
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
    if name.startswith("Ffi") and not hasattr(passbolt, name[len("Ffi"):])
]
assert not missing, f"no alias in passbolt for {missing}"
assert all(hasattr(passbolt, name) for name in passbolt.__all__)
assert issubclass(passbolt.Client, _ffi.PassboltClient)
assert hasattr(passbolt.Client, "__enter__") and hasattr(passbolt.Client, "__exit__")
print("ok: passbolt names")
