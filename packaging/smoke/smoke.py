# The installed wheel loads its native library and maps Rust errors to Python exceptions.
import passbolt_ffi

try:
    passbolt_ffi.get_key_fingerprint("not a key")
except passbolt_ffi.PassboltFfiError.Crypto as error:
    print(f"ok: {error}")
else:
    raise SystemExit("expected a crypto error")
