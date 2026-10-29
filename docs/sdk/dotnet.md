---
title: .NET
sidebar_position: 7
---

# .NET

```bash
dotnet add package SwitchCase.Passbolt.Sdk
```

.NET 8 or later, on Linux (x86_64, aarch64), macOS (Intel, Apple silicon) and Windows (x86_64):
the package holds the native library of each platform under `runtimes/<rid>/native`, which the
.NET host loads. The namespace is `Passbolt.Sdk`.

## Log in and list

```csharp
using System.Text.Json;
using Passbolt.Sdk;

var privateKey = File.ReadAllText("private.asc");
var passphrase = Environment.GetEnvironmentVariable("PASSBOLT_PASSPHRASE")!;

using var client = PassboltClient.Login("https://passbolt.example.com", privateKey, passphrase);
try
{
    using var views = JsonDocument.Parse(client.ListResourceViews("github", withSecrets: false));
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

`PassboltClient` is `IDisposable`: `using` frees the native session, `Logout` ends it on the
server.

The calls block. In a desktop app, keep them off the UI thread:
`await Task.Run(() => client.ListResourceViews(null, false))`.

