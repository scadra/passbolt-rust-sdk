// The package exposes the bindings, the .NET host loads the native library of runtimes/<rid>/native,
// and Rust errors become the nested classes of PassboltFfiException.
using Passbolt.Sdk;

try
{
    PassboltFfi.GetKeyFingerprint("not a key");
}
catch (PassboltFfiException.Crypto error)
{
    Console.WriteLine($"ok: {error.reason}");
    return;
}
throw new InvalidOperationException("expected a crypto error");
