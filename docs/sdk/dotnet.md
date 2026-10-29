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

## Pinning the server, MFA, TLS

```csharp
using Passbolt.Sdk;

var privateKey = File.ReadAllText("private.asc");
var passphrase = Environment.GetEnvironmentVariable("PASSBOLT_PASSPHRASE")!;

var serverKey = PassboltFfi.FetchServerKey("https://passbolt.example.com", tlsSkipVerify: false);
Console.WriteLine($"Check this fingerprint with your administrator: {serverKey.fingerprint}");

var options = new FfiLoginOptions(
    tlsSkipVerify: false,
    proxy: null,
    mfaTotpToken: null,               // the base32 TOTP secret, for an account with TOTP
    serverPublicKey: serverKey.armoredKey,
    metadataKeyFingerprint: null,
    timeoutSeconds: null,             // 60 by default, 0 waits forever
    clientCertificatePem: null,
    clientKeyPem: null);
using var client = PassboltClient.LoginWithConfig(
    "https://passbolt.example.com", privateKey, passphrase, options);

// The records are immutable: change a field with `with`.
var throughProxy = options with { proxy = "http://proxy.example.com:3128" };
```

## Reading and writing

```csharp
using System.Text.Json;
using Passbolt.Sdk;

static void Example(PassboltClient client, string resourceId, string userId)
{
    using var view = JsonDocument.Parse(client.GetResourceView(resourceId));
    Console.WriteLine(view.RootElement.GetProperty("password"));

    var created = client.CreateResource(
        JsonSerializer.Serialize(new { name = "GitHub", username = "ada", password = "…" }));
    client.UpdateResource(created.id, JsonSerializer.Serialize(new { password = "new" }));
    client.ShareResource(created.id, [userId], [], permissionType: 7);

    foreach (var folder in client.ListFolders(search: null))
    {
        Console.WriteLine($"{folder.id} {folder.name}");
    }
}
```

The typed results (`FfiResource`, `FfiFolder`, `FfiUser`…) are C# records; their members keep the
camelCase of the generator (`created.id`, `folder.name`). Lists come back as arrays.

