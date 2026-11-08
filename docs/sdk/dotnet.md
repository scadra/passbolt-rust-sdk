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

`PassboltClient` is `IDisposable`: `using` frees the native session, `Logout` ends it on the
server.

The calls block. In a desktop app, keep them off the UI thread:
`await Task.Run(() => client.ListResourceViews())`.

## Pinning the server, MFA, TLS

```csharp
using Passbolt.Sdk;

var privateKey = File.ReadAllText("private.asc");
var passphrase = Environment.GetEnvironmentVariable("PASSBOLT_PASSPHRASE")!;

var serverKey = PassboltFfi.FetchServerKey("https://passbolt.example.com");
Console.WriteLine($"Check this fingerprint with your administrator: {serverKey.fingerprint}");

// The arguments left out keep their default.
var options = new LoginOptions(
    serverPublicKey: serverKey.armoredKey,
    timeoutSeconds: 30);              // 60 by default, 0 waits forever
using var client = PassboltClient.LoginWithConfig(
    "https://passbolt.example.com", privateKey, passphrase, options);

// The records are immutable: change a field with `with`.
var throughProxy = options with { proxy = "http://proxy.example.com:3128" };
```

## Reading and writing

```csharp
using Passbolt.Sdk;

static void Example(PassboltClient client, string resourceId, string userId)
{
    var view = client.GetResourceView(resourceId);
    Console.WriteLine(view.password);

    var created = client.CreateResource(
        new NewResource(name: "GitHub", username: "ada", password: "…"));
    client.UpdateResource(created.id, new ResourceChanges(password: "new"));
    // 1 read, 7 update, 15 owner, -1 revokes.
    client.ShareResource(created.id, permissionType: 7, userIds: [userId]);

    foreach (var folder in client.ListFolders())
    {
        Console.WriteLine($"{folder.id} {folder.name}");
    }
}
```

The typed results (`ResourceView`, `Resource`, `Folder`, `User`…) are C# records; their members
keep the camelCase of the generator (`created.id`, `folder.name`). Lists come back as arrays. A
`ResourceView` holds the fields every resource type shares, decrypted; the others, custom fields
and icon among them, are the JSON objects `metadataJson` and `secretJson`.

## Errors

```csharp
using Passbolt.Sdk;

try
{
    PassboltFfi.GetKeyFingerprint("not a key");
}
catch (PassboltException.Crypto error)
{
    Console.WriteLine($"not a key: {error.reason}");
}
catch (PassboltException.Api error) when (error.status == 404)
{
    Console.WriteLine("not on the server");
}
catch (PassboltException error)
{
    Console.WriteLine($"failed: {error.Message}");
}
```

`PassboltException` derives from `System.Exception`, with one nested class per variant of the
[overview](README.md#concepts) (`Auth`, `Crypto`, `Api`, `NotFound`…).

The methods are those of the [overview](README.md#what-the-api-covers), in PascalCase:
`ListFolders`, `CreateFolder`, `DeleteUserWithTransfer`, `SetResourceTags`… The stateless
functions are static methods of `PassboltFfi`: `FetchServerKey`, `GetKeyFingerprint`,
`EncryptMessage`, `DecryptMessage`.
