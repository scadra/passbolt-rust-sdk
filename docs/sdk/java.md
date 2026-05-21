---
title: Java
sidebar_position: 5
---

# Java

```xml
<dependency>
  <groupId>io.github.scadra</groupId>
  <artifactId>passbolt-sdk</artifactId>
  <version>0.1.0</version>
</dependency>
```

Java 21 or later. The jar holds the bindings and the native library for Linux (x86_64, aarch64),
macOS (Intel, Apple silicon) and Windows (x86_64), loaded through JNA, which Maven brings along.
For Android, use the [AAR](android.md).

## Log in and list

```java
import com.passbolt.sdk.PassboltClient;

import java.nio.file.Files;
import java.nio.file.Path;

public class ListResources {
    public static void main(String[] args) throws Exception {
        String privateKey = Files.readString(Path.of("private.asc"));
        PassboltClient client = PassboltClient.login(
            "https://passbolt.example.com", privateKey, System.getenv("PASSBOLT_PASSPHRASE"));
        try {
            // A JSON array of views: parse it with your JSON library.
            System.out.println(client.listResourceViews("github", false));
        } finally {
            client.logout();
            client.close();
        }
    }
}
```

The stateless functions are static methods of `com.passbolt.sdk.PassboltFfi`:
`PassboltFfi.fetchServerKey(serverUrl, false)`, `PassboltFfi.getKeyFingerprint(privateKey)`…
`PassboltClient.loginWithConfig` takes an `FfiLoginOptions`, with the fields of the
[Python](python.md#pinning-the-server-mfa-tls) example in camelCase.

The calls block, and throw the exception generated for `PassboltFfiError`, whose variants say
what failed. The methods are those of the [overview](README.md#what-the-api-covers), in camelCase.
