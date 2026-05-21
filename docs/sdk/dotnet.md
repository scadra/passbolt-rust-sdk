---
title: .NET
sidebar_position: 7
---

# .NET

```bash
dotnet add package SwitchCase.Passbolt.Sdk
```

.NET 8 or later, on Linux (x86_64, aarch64), macOS and Windows: the package holds the native
library of each platform under `runtimes/<rid>/native`, which the .NET host loads. The namespace
is `Passbolt.Sdk`.

## Log in and list

```csharp
using System.Text.Json;
using Passbolt.Sdk;

var privateKey = File.ReadAllText("private.asc");
using var client = PassboltClient.Login(
    "https://passbolt.example.com", privateKey, Environment.GetEnvironmentVariable("PASSBOLT_PASSPHRASE")!);
try
{
    using var views = JsonDocument.Parse(client.ListResourceViews("github", false));
    foreach (var view in views.RootElement.EnumerateArray())
    {
        Console.WriteLine($"{view.GetProperty("id")} {view.GetProperty("name")}");
    }
}
finally
{
    client.Logout();
}
```

`PassboltClient.LoginWithConfig` takes an `FfiLoginOptions`, with the fields of the
[Python](python.md#pinning-the-server-mfa-tls) example in PascalCase.

The calls block, and throw the exception generated for `PassboltFfiError`, with one nested class
per variant (`Crypto`, `Api`…). The methods are those of the
[overview](README.md#what-the-api-covers), in PascalCase.
