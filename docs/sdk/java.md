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
import com.passbolt.sdk.ServerKey;
import com.passbolt.sdk.PassboltClient;
import com.passbolt.sdk.PassboltFfi;
import com.passbolt.sdk.PassboltException;

public class PinnedLogin {
    static PassboltClient login(String privateKey, String passphrase) throws PassboltException {
        ServerKey serverKey = PassboltFfi.fetchServerKey("https://passbolt.example.com", false);
        System.out.println("Check this fingerprint with your administrator: " + serverKey.fingerprint());

        // Java has no default arguments: each one is given, null when unused.
        LoginOptions options = new LoginOptions(
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
import com.passbolt.sdk.Folder;
import com.passbolt.sdk.NewResource;
import com.passbolt.sdk.PassboltClient;
import com.passbolt.sdk.PassboltException;
import com.passbolt.sdk.Resource;
import com.passbolt.sdk.ResourceChanges;
import com.passbolt.sdk.ResourceView;

import java.util.List;

public class ReadWrite {
    static void example(PassboltClient client, String resourceId, String userId)
            throws PassboltException {
        ResourceView view = client.getResourceView(resourceId);
        System.out.println(view.password());

        Resource created = client.createResource(new NewResource(
            "GitHub",                 // name
            null,                     // resourceType: from the fields set
            "ada",                    // username
            List.of(),                // uris
            null, null,               // description, note
            "…",                      // password
            null, null, null, null,   // totp, pinCode, folderParentId, expired
            null, null));             // metadataFieldsJson, secretFieldsJson
        client.updateResource(created.id(), new ResourceChanges(
            null, null, null, null, null,
            "new",                    // password
            null, null, false, null, false, null, null));
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
accessors (`created.id()`); lists are `java.util.List`. An absent value is `null`, as is an
argument left out (`listFolders(null)`).

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
