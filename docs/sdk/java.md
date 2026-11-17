---
title: Java
sidebar_position: 5
---

# Java

Use the `passbolt-sdk` jar to log in to Passbolt and read, write and share secrets from Java, with
blocking calls or `CompletableFuture`.

## Installation

The package is on Maven Central as `io.github.scadra:passbolt-sdk`. It needs Java 21 or later.

```xml title="pom.xml"
<dependency>
  <groupId>io.github.scadra</groupId>
  <artifactId>passbolt-sdk</artifactId>
  <version>0.1.1</version>
</dependency>
```

```kotlin title="build.gradle.kts"
dependencies {
    implementation("io.github.scadra:passbolt-sdk:0.1.1")
}
```

- The jar holds the bindings and the native library for Linux (x86_64, aarch64), macOS (Intel,
  Apple silicon) and Windows (x86_64), loaded through JNA, which Maven brings along.
- The package is `com.passbolt.sdk`, and so is the automatic module name.
- For Android, use the [AAR](android.md).

## Initialize

Log in with `PassboltClient.login`. `PassboltClient` is `AutoCloseable`: try-with-resources frees
the native session, `logout` ends it on the server.

```java
import com.passbolt.sdk.PassboltClient;
import com.passbolt.sdk.PassboltException;
import com.passbolt.sdk.ResourceView;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class ListResources {
    public static void main(String[] args) throws IOException, PassboltException {
        String privateKey = Files.readString(Path.of("private.asc"));
        String passphrase = System.getenv("PASSBOLT_PASSPHRASE");

        try (PassboltClient client =
                PassboltClient.login("https://passbolt.example.com", privateKey, passphrase)) {
            try {
                for (ResourceView view : client.listResourceViews("github", false)) {
                    System.out.println(view.id() + " " + view.name());
                }
            } finally {
                client.logout();
            }
        }
    }
}
```

The calls block: in a desktop app, keep them off the UI thread, or use
[`AsyncPassboltClient`](#async-calls).

## Login options

`PassboltClient.loginWithConfig` takes a `LoginOptions`, built with `LoginOptionsBuilder`. An
option you leave unset keeps its default.

| Builder method | Description |
|---|---|
| `serverPublicKey(String)` | The armored server key pinned with `PassboltFfi.fetchServerKey`. |
| `metadataKeyFingerprint(String)` | The pinned fingerprint of the shared metadata key. |
| `mfaTotpToken(String)` | The base32 TOTP secret, for an account with TOTP. |
| `timeoutSeconds(long)` | Seconds a request may take. Default: 60; `0` waits forever. |
| `proxy(String)` | The proxy URL. |
| `tlsSkipVerify(boolean)` | Skip the certificate check, for a test server only. |
| `clientCertificate(certificatePem, keyPem)` | The PEM certificate and key, for mTLS. |

### Pin the server key and answer MFA

```java
import com.passbolt.sdk.LoginOptions;
import com.passbolt.sdk.LoginOptionsBuilder;
import com.passbolt.sdk.PassboltClient;
import com.passbolt.sdk.PassboltException;
import com.passbolt.sdk.PassboltFfi;
import com.passbolt.sdk.ServerKey;

public class PinnedLogin {
    static PassboltClient login(String privateKey, String passphrase, String totpSecret)
            throws PassboltException {
        ServerKey serverKey = PassboltFfi.fetchServerKey("https://passbolt.example.com", false);
        System.out.println("Check this fingerprint with your administrator: " + serverKey.fingerprint());

        LoginOptions options = new LoginOptionsBuilder()
            .serverPublicKey(serverKey.armoredKey())
            .mfaTotpToken(totpSecret) // the base32 TOTP secret, for an account with TOTP
            .timeoutSeconds(30)       // 60 by default, 0 waits forever
            .build();
        return PassboltClient.loginWithConfig(
            "https://passbolt.example.com", privateKey, passphrase, options);
    }
}
```

## Read resources

The typed results (`ResourceView`, `Resource`, `Folder`, `User`…) are Java records, read with
their accessors (`view.id()`). Lists are `java.util.List`, and an absent value is `null`.

A `ResourceView` holds the fields every resource type shares, decrypted; the others, custom
fields and icon among them, are the JSON objects `metadataJson()` and `secretJson()`.

### Read a password and list your folders

```java
import com.passbolt.sdk.Folder;
import com.passbolt.sdk.PassboltClient;
import com.passbolt.sdk.PassboltException;
import com.passbolt.sdk.ResourceView;

public class ReadResources {
    static void example(PassboltClient client, String resourceId) throws PassboltException {
        ResourceView view = client.getResourceView(resourceId);
        System.out.println(view.password());

        for (Folder folder : client.listFolders(null)) {
            System.out.println(folder.id() + " " + folder.name());
        }
    }
}
```

## Create and share resources

The records you write have builders in the same package, with the required fields as constructor
arguments and every other field at its default: `uris` empty, flags false, the rest `null`.
`NewResourceBuilder(name)`, `ResourceChangesBuilder()`, `LoginOptionsBuilder()` and
`TotpDataBuilder(secretKey)` each end with `build()`. The records' constructors remain, with every
field in order.

Java has no default arguments: a method takes all its arguments, `null` for an optional value,
`false` for an unset flag and `List.of()` for no ID (`listFolders(null)`,
`listResources(null, false, false)`, `shareResource(id, 7, List.of(userId), List.of())`).

### Create, update and share a resource

```java
import com.passbolt.sdk.NewResourceBuilder;
import com.passbolt.sdk.PassboltClient;
import com.passbolt.sdk.PassboltException;
import com.passbolt.sdk.Resource;
import com.passbolt.sdk.ResourceChangesBuilder;
import com.passbolt.sdk.TotpDataBuilder;

import java.util.List;

public class WriteResources {
    static void example(PassboltClient client, String userId) throws PassboltException {
        Resource created = client.createResource(new NewResourceBuilder("GitHub")
            .username("ada")
            .uris("https://github.com")
            .password("…")
            .totp(new TotpDataBuilder("JBSWY3DPEHPK3PXP").build())
            .build());
        // A field left unset keeps its current value.
        client.updateResource(created.id(), new ResourceChangesBuilder()
            .password("new")
            .removeTotp()
            .build());
        // 1 read, 7 update, 15 owner, -1 revokes.
        client.shareResource(created.id(), 7, List.of(userId), List.of());
    }
}
```

## Generate a password

Generate passwords from character sets, passphrases of words of the EFF list, and PIN codes, as
the browser extension does. Start from the password policies of the organization or from settings
of your own: the builders start from the defaults of Passbolt, or from the settings they are
given.

### Generate secrets and rate them

```java
import com.passbolt.sdk.PassboltClient;
import com.passbolt.sdk.PassboltException;
import com.passbolt.sdk.PassboltFfi;
import com.passbolt.sdk.PassphraseGeneratorSettingsBuilder;
import com.passbolt.sdk.PasswordGeneratorSettingsBuilder;
import com.passbolt.sdk.PasswordPolicies;
import com.passbolt.sdk.Strength;
import com.passbolt.sdk.WordCase;

public class Secrets {
    static String generate(PassboltClient client) throws PassboltException {
        // The organization's: generator and settings.
        PasswordPolicies policies = client.getPasswordPolicies();
        String secret = PassboltFfi.generateSecret(policies);

        String password = PassboltFfi.generatePassword(
            new PasswordGeneratorSettingsBuilder().length(24).build());
        String longer = PassboltFfi.generatePassword(
            new PasswordGeneratorSettingsBuilder(policies.passwordGeneratorSettings())
                .length(32).build());
        String passphrase = PassboltFfi.generatePassphrase(
            new PassphraseGeneratorSettingsBuilder().words(6).wordCase(WordCase.CAMELCASE).build());
        String pinCode = PassboltFfi.generatePinCode(6);

        // As the extension shows it.
        boolean strong = PassboltFfi.secretStrength(password) == Strength.VERY_STRONG;
        return strong ? secret + longer + passphrase + pinCode : password;
    }
}
```

## Handle errors

`PassboltException` is a checked exception, with one nested subclass per variant of the
[overview](README.md#concepts) (`Auth`, `Crypto`, `Api`, `NotFound`…): every call declares
`throws PassboltException`.

### Catch a crypto error and an API error

```java
import com.passbolt.sdk.PassboltFfi;
import com.passbolt.sdk.PassboltException;

public class Errors {
    public static void main(String[] args) {
        try {
            PassboltFfi.getKeyFingerprint("not a key");
        } catch (PassboltException.Crypto error) {
            System.out.println("not a key: " + error.reason());
        } catch (PassboltException.Api error) {
            System.out.println("the server answered " + error.status());
        } catch (PassboltException error) {
            System.out.println("failed: " + error.getMessage());
        }
    }
}
```

## Async calls

`AsyncPassboltClient` has the same methods returning a `CompletableFuture`, which the SDK's own
threads complete. A failure completes it exceptionally with the `PassboltException`.

### Chain the login, a search and the logout

```java
import com.passbolt.sdk.AsyncPassboltClient;
import com.passbolt.sdk.ResourceView;

import java.util.List;
import java.util.concurrent.CompletableFuture;

public class AsyncNames {
    static CompletableFuture<List<String>> names(String privateKey, String passphrase) {
        return AsyncPassboltClient.login("https://passbolt.example.com", privateKey, passphrase)
            .thenCompose(client -> client.listResourceViews("github", false)
                .thenCompose(views -> client.logout().thenApply(done -> views))
                .whenComplete((views, error) -> client.close()))
            .thenApply(views -> views.stream().map(ResourceView::name).toList());
    }
}
```

## Method names

The methods are those of the [overview](README.md#what-the-api-covers), in camelCase:
`listFolders`, `createFolder`, `deleteUserWithTransfer`, `setResourceTags`… The stateless
functions are static methods of `PassboltFfi`: `fetchServerKey`, `getKeyFingerprint`,
`encryptMessage`, `decryptMessage`.

## Related

- [Overview](README.md): the concepts shared by every language.
- [API reference](api.md): every method, function and record.
- [Android](android.md): the same API in Kotlin.
- [Upgrading](upgrading.md): the breaking changes since the 0.1.1 packages.
