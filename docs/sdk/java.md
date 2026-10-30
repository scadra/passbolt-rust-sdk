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

The calls block, and throw the exception generated for `PassboltFfiError`, whose variants say
what failed. The methods are those of the [overview](README.md#what-the-api-covers), in camelCase.
