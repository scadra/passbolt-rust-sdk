# Passbolt SDK for .NET

The .NET bindings of the Passbolt Rust SDK: GPGAuth login, resources, folders, users, groups and
sharing, with the OpenPGP encryption done in Rust. .NET 8 or later, on Linux (x64, arm64), macOS
(x64, arm64) and Windows (x64).

```csharp
using Passbolt.Sdk;

var privateKey = File.ReadAllText("private.asc");
var passphrase = Environment.GetEnvironmentVariable("PASSBOLT_PASSPHRASE")!;

using var client = PassboltClient.Login("https://passbolt.example.com", privateKey, passphrase);
try
{
    foreach (var view in client.ListResourceViews(search: "github"))
    {
        Console.WriteLine($"{view.id} {view.name}");
    }
}
finally
{
    client.Logout();
}
```

The calls block and throw `PassboltException` (`Auth`, `Crypto`, `Api`, `NotFound`…).
Documentation: https://github.com/scadra/passbolt-rust-sdk/blob/master/docs/sdk/dotnet.md

License: AGPL-3.0-or-later.
