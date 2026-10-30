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
import com.passbolt.sdk.PassboltFfiException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class ListResources {
    public static void main(String[] args) throws IOException, PassboltFfiException {
        String privateKey = Files.readString(Path.of("private.asc"));
        String passphrase = System.getenv("PASSBOLT_PASSPHRASE");

        try (PassboltClient client =
                PassboltClient.login("https://passbolt.example.com", privateKey, passphrase)) {
            try {
                // A JSON array of views: parse it with your JSON library.
                System.out.println(client.listResourceViews("github", false));
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
import com.passbolt.sdk.FfiLoginOptions;
import com.passbolt.sdk.FfiServerKey;
import com.passbolt.sdk.PassboltClient;
import com.passbolt.sdk.PassboltFfi;
import com.passbolt.sdk.PassboltFfiException;

public class PinnedLogin {
    static PassboltClient login(String privateKey, String passphrase) throws PassboltFfiException {
        FfiServerKey serverKey = PassboltFfi.fetchServerKey("https://passbolt.example.com", false);
        System.out.println("Check this fingerprint with your administrator: " + serverKey.fingerprint());

        FfiLoginOptions options = new FfiLoginOptions(
            false,                    // tlsSkipVerify
            null,                     // proxy
            null,                     // mfaTotpToken: the base32 TOTP secret, for an account with TOTP
            serverKey.armoredKey(),   // serverPublicKey
            null,                     // metadataKeyFingerprint
            null,                     // timeoutSeconds: 60 by default, 0 waits forever
            null,                     // clientCertificatePem
            null);                    // clientKeyPem
        return PassboltClient.loginWithConfig(
            "https://passbolt.example.com", privateKey, passphrase, options);
    }
}
```

## Reading and writing

```java
import com.passbolt.sdk.FfiFolder;
import com.passbolt.sdk.FfiResource;
import com.passbolt.sdk.PassboltClient;
import com.passbolt.sdk.PassboltFfiException;

import java.util.List;

public class ReadWrite {
    static void example(PassboltClient client, String resourceId, String userId)
            throws PassboltFfiException {
        // JSON text: parse it with your JSON library.
        System.out.println(client.getResourceView(resourceId));

        FfiResource created = client.createResource(
            "{\"name\": \"GitHub\", \"username\": \"ada\", \"password\": \"…\"}");
        client.updateResource(created.id(), "{\"password\": \"new\"}");
        client.shareResource(created.id(), List.of(userId), List.of(), 7);

        for (FfiFolder folder : client.listFolders(null)) {
            System.out.println(folder.id() + " " + folder.name());
        }
    }
}
```

The typed results (`FfiResource`, `FfiFolder`, `FfiUser`…) are Java records, read with their
accessors (`created.id()`); lists are `java.util.List`. An absent value is `null`, as is an
argument left out (`listFolders(null)`).

## Errors

```java
import com.passbolt.sdk.PassboltFfi;
import com.passbolt.sdk.PassboltFfiException;

public class Errors {
    public static void main(String[] args) {
        try {
            PassboltFfi.getKeyFingerprint("not a key");
        } catch (PassboltFfiException.Crypto error) {
            System.out.println("not a key: " + error.reason());
        } catch (PassboltFfiException.Api error) {
            System.out.println("the server answered " + error.status());
        } catch (PassboltFfiException error) {
            System.out.println("failed: " + error.getMessage());
        }
    }
}
```

`PassboltFfiException` is a checked exception, with one nested subclass per variant of the
[overview](README.md#concepts) (`Auth`, `Crypto`, `Api`, `NotFound`…): every call declares
`throws PassboltFfiException`.

The methods are those of the [overview](README.md#what-the-api-covers), in camelCase:
`listFolders`, `createFolder`, `deleteUserWithTransfer`, `setResourceTags`… The stateless
functions are static methods of `PassboltFfi`: `fetchServerKey`, `getKeyFingerprint`,
`encryptMessage`, `decryptMessage`.
