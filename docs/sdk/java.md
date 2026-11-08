---
title: Java
sidebar_position: 5
---

# Java

```xml
<dependency>
  <groupId>io.github.scadra</groupId>
  <artifactId>passbolt-sdk</artifactId>
  <version>0.1.1</version>
</dependency>
```

Java 21 or later. The jar holds the bindings and the native library for Linux (x86_64, aarch64),
macOS (Intel, Apple silicon) and Windows (x86_64), loaded through JNA, which Maven brings along.
The package is `com.passbolt.sdk` (automatic module name `com.passbolt.sdk`). For Android, use
the [AAR](android.md).

## Log in and list

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

`PassboltClient` is `AutoCloseable`: try-with-resources frees the native session, `logout` ends
it on the server. The calls block: in a desktop app, keep them off the UI thread.

## Pinning the server, MFA, TLS

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

`LoginOptionsBuilder` also sets `proxy`, `tlsSkipVerify` (for a test server only),
`metadataKeyFingerprint` and `clientCertificate(certificatePem, keyPem)` for mTLS; an option left
unset keeps its default.

## Reading and writing

```java
import com.passbolt.sdk.Folder;
import com.passbolt.sdk.NewResourceBuilder;
import com.passbolt.sdk.PassboltClient;
import com.passbolt.sdk.PassboltException;
import com.passbolt.sdk.Resource;
import com.passbolt.sdk.ResourceChangesBuilder;
import com.passbolt.sdk.ResourceView;
import com.passbolt.sdk.TotpDataBuilder;

import java.util.List;

public class ReadWrite {
    static void example(PassboltClient client, String resourceId, String userId)
            throws PassboltException {
        ResourceView view = client.getResourceView(resourceId);
        System.out.println(view.password());

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

        for (Folder folder : client.listFolders(null)) {
            System.out.println(folder.id() + " " + folder.name());
        }
    }
}
```

A `ResourceView` holds the fields every resource type shares, decrypted; the others, custom
fields and icon among them, are the JSON objects `metadataJson()` and `secretJson()`.

The typed results (`ResourceView`, `Resource`, `Folder`, `User`…) are Java records, read with their
accessors (`created.id()`); lists are `java.util.List`, and an absent value is `null`.

The records you write have builders in the same package, with the required fields as constructor
arguments and every other field at its default: `uris` empty, flags false, the rest `null`.
`NewResourceBuilder(name)`, `ResourceChangesBuilder()`, `LoginOptionsBuilder()` and
`TotpDataBuilder(secretKey)` each end with `build()`; the records' constructors remain, with every
field in order.

Java has no default arguments: a method takes all its arguments, `null` for an optional value,
`false` for an unset flag and `List.of()` for no ID (`listFolders(null)`,
`listResources(null, false, false)`, `shareResource(id, 7, List.of(userId), List.of())`).

## Errors

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

`PassboltException` is a checked exception, with one nested subclass per variant of the
[overview](README.md#concepts) (`Auth`, `Crypto`, `Api`, `NotFound`…): every call declares
`throws PassboltException`.

The methods are those of the [overview](README.md#what-the-api-covers), in camelCase:
`listFolders`, `createFolder`, `deleteUserWithTransfer`, `setResourceTags`… The stateless
functions are static methods of `PassboltFfi`: `fetchServerKey`, `getKeyFingerprint`,
`encryptMessage`, `decryptMessage`.
