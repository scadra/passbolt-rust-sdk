// The package exposes the bindings, the .NET host loads the native library of runtimes/<rid>/native,
// and Rust errors become the nested classes of PassboltException.
using Passbolt.Sdk;

try
{
    PassboltFfi.GetKeyFingerprint("not a key");
}
catch (PassboltException.Crypto error)
{
    Console.WriteLine($"ok: {error.reason}");
    return;
}
throw new InvalidOperationException("expected a crypto error");
