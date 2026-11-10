---
title: .NET
sidebar_position: 7
---

# .NET

Use the `SwitchCase.Passbolt.Sdk` package to log in to Passbolt and read, write and share secrets
from C#, with blocking calls or `Task`.

## Installation

The package is on NuGet as `SwitchCase.Passbolt.Sdk`. It needs .NET 8 or later, on Linux (x86_64,
aarch64), macOS (Intel, Apple silicon) or Windows (x86_64).

```bash
dotnet add package SwitchCase.Passbolt.Sdk
```

The package holds the native library of each platform under `runtimes/<rid>/native`, which the
.NET host loads. The namespace is `Passbolt.Sdk`.

## Initialize

Log in with `PassboltClient.Login`. `PassboltClient` is `IDisposable`: `using` frees the native
session, `Logout` ends it on the server.

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

The calls block. To await them, see [Async calls](#async-calls).

## Login options

`PassboltClient.LoginWithConfig` takes a `LoginOptions`. The arguments you leave out keep their
default.

| Argument | Type | Description |
|---|---|---|
| `serverPublicKey` | `string?` | The armored server key pinned with `PassboltFfi.FetchServerKey`. |
| `metadataKeyFingerprint` | `string?` | The pinned fingerprint of the shared metadata key. |
| `mfaTotpToken` | `string?` | The base32 TOTP secret, for an account with TOTP. |
| `timeoutSeconds` | `ulong?` | Seconds a request may take. Default: 60; `0` waits forever. |
| `proxy` | `string?` | The proxy URL. |
| `tlsSkipVerify` | `bool` | Skip the certificate check. Default: `false`. |
| `clientCertificatePem`, `clientKeyPem` | `string?` | The PEM certificate and key, for mTLS. |

### Pin the server key and use a proxy

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

## Read resources

The typed results (`ResourceView`, `Resource`, `Folder`, `User`…) are C# records. Their members
keep the camelCase of the generator (`view.id`, `folder.name`), and lists come back as arrays.

A `ResourceView` holds the fields every resource type shares, decrypted; the others, custom
fields and icon among them, are the JSON objects `metadataJson` and `secretJson`.

### Read a password and list your folders

```csharp
using Passbolt.Sdk;

static void ReadResources(PassboltClient client, string resourceId)
{
    var view = client.GetResourceView(resourceId);
    Console.WriteLine(view.password);

    foreach (var folder in client.ListFolders())
    {
        Console.WriteLine($"{folder.id} {folder.name}");
    }
}
```

## Create and share resources

`CreateResource` takes a `NewResource`, `UpdateResource` a `ResourceChanges`. The arguments you
leave out keep their default.

### Create, update and share a resource

```csharp
using Passbolt.Sdk;

static void WriteResources(PassboltClient client, string userId)
{
    var created = client.CreateResource(
        new NewResource(name: "GitHub", username: "ada", password: "…"));
    client.UpdateResource(created.id, new ResourceChanges(password: "new"));
    // 1 read, 7 update, 15 owner, -1 revokes.
    client.ShareResource(created.id, permissionType: 7, userIds: [userId]);
}
```

## Generate a password

Generate passwords from character sets, passphrases of words of the EFF list, and PIN codes, as
the browser extension does. Start from the password policies of the organization or from settings
of your own: the arguments you leave out keep the defaults of Passbolt.

Without a session, `PassboltFfi.DefaultPasswordPolicies()` gives the defaults of Passbolt.

### Generate secrets and rate them

```csharp
var policies = client.GetPasswordPolicies(); // the organization's: generator and settings
var secret = PassboltFfi.GenerateSecret(policies);

var password = PassboltFfi.GeneratePassword(new PasswordGeneratorSettings(length: 24));
var passphrase = PassboltFfi.GeneratePassphrase(
    new PassphraseGeneratorSettings(words: 6, wordCase: WordCase.Camelcase));
var pinCode = PassboltFfi.GeneratePinCode(6);

var strength = PassboltFfi.SecretStrength(password); // VeryStrong, as the extension shows it
```

## Handle errors

`PassboltException` derives from `System.Exception`, with one nested class per variant of the
[overview](README.md#concepts) (`Auth`, `Crypto`, `Api`, `NotFound`…).

### Catch a crypto error and an API error

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

## Async calls

`AsyncPassboltClient` has the same methods returning a `Task`. Await them from a UI thread or an
ASP.NET request without holding a thread while the server answers.

The methods keep their names, without the usual `Async` suffix: UniFFI names them.

### Log in and search without blocking

```csharp
using Passbolt.Sdk;

var privateKey = File.ReadAllText("private.asc");
var passphrase = Environment.GetEnvironmentVariable("PASSBOLT_PASSPHRASE")!;

using var client = await AsyncPassboltClient.Login(
    "https://passbolt.example.com", privateKey, passphrase);
try
{
    foreach (var view in await client.ListResourceViews(search: "github"))
    {
        Console.WriteLine($"{view.id} {view.name}");
    }
}
finally
{
    await client.Logout();
}
```

## Method names

The methods are those of the [overview](README.md#what-the-api-covers), in PascalCase:
`ListFolders`, `CreateFolder`, `DeleteUserWithTransfer`, `SetResourceTags`… The stateless
functions are static methods of `PassboltFfi`: `FetchServerKey`, `GetKeyFingerprint`,
`EncryptMessage`, `DecryptMessage`.

## Related

- [Overview](README.md): the concepts shared by every language.
- [API reference](api.md): every method, function and record.
- [Upgrading](upgrading.md): the breaking changes since the 0.1.1 packages.
