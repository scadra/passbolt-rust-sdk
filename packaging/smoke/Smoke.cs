// The package exposes the bindings, the .NET host loads the native library of runtimes/<rid>/native,
// and Rust errors become the nested classes of PassboltException.
using Passbolt.Sdk;

// The OpenPGP engine of the native library encrypts and decrypts in this host: a test key of the
// repository, CI checking the engine each package is built with.
var engine = PassboltFfi.OpenpgpEngine();
var expected = Environment.GetEnvironmentVariable("PASSBOLT_EXPECTED_ENGINE");
if (expected is not null && engine != expected)
{
    throw new InvalidOperationException($"engine {engine}, expected {expected}");
}
var keys = Environment.GetEnvironmentVariable("PASSBOLT_SMOKE_KEYS") ?? "crates/passbolt-sdk/tests/fixtures/keys";
var armored = PassboltFfi.EncryptMessage(
    System.Text.Encoding.UTF8.GetBytes("smoke"),
    new[] { File.ReadAllText(Path.Combine(keys, "erin_public.asc")) });
var plaintext = PassboltFfi.DecryptMessage(
    armored, File.ReadAllText(Path.Combine(keys, "erin_private.asc")), "erin-passphrase");
if (System.Text.Encoding.UTF8.GetString(plaintext) != "smoke")
{
    throw new InvalidOperationException("the message did not come back");
}
Console.WriteLine($"ok: {engine} encrypts and decrypts");

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
