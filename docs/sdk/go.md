---
title: Go
sidebar_position: 8
---

# Go

The `passbolt-sdk-go-<version>.tar.gz` of a release is a Go module,
`github.com/passbolt/passbolt-sdk-go`, holding the bindings and the static library of Linux
(x86_64, aarch64) and macOS (Intel, Apple silicon), linked with cgo. Windows is not covered.

```bash
tar xzf passbolt-sdk-go-0.1.0.tar.gz
go mod edit -require github.com/passbolt/passbolt-sdk-go@v0.0.0 \
            -replace github.com/passbolt/passbolt-sdk-go=./passbolt-sdk-go
CGO_ENABLED=1 go build
```

## Log in and list

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"

	passbolt "github.com/passbolt/passbolt-sdk-go"
)

func main() {
	privateKey, err := os.ReadFile("private.asc")
	if err != nil {
		panic(err)
	}
	client, err := passbolt.PassboltClientLogin(
		"https://passbolt.example.com", string(privateKey), os.Getenv("PASSBOLT_PASSPHRASE"))
	if err != nil {
		panic(err)
	}
	defer client.Destroy()
	defer client.Logout()

	search := "github"
	viewsJSON, err := client.ListResourceViews(&search, false)
	if err != nil {
		panic(err)
	}
	var views []map[string]any
	if err := json.Unmarshal([]byte(viewsJSON), &views); err != nil {
		panic(err)
	}
	for _, view := range views {
		fmt.Println(view["id"], view["name"])
	}
}
```

Optional arguments are pointers (`nil` for none). Each constructor of the Rust client is a
function named after it: `PassboltClientLogin`, `PassboltClientLoginWithConfig`. Errors are
`*passbolt.PassboltFfiError`, one variant per failure. The methods are those of the
[overview](README.md#what-the-api-covers), in PascalCase.
