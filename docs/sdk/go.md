---
title: Go
sidebar_position: 8
---

# Go

```bash
go get github.com/scadra/passbolt-sdk-go@v0.1.1
```

The package is `passbolt`. It links the static library of Linux (x86_64, aarch64) or macOS (Intel,
Apple silicon) with cgo, so it builds with `CGO_ENABLED=1` and a C compiler; Windows is not covered.
Its calls block until the server answers.

The same module is the `passbolt-sdk-go-<version>.tar.gz` of each release, for a build without
network access:

```bash
tar xzf passbolt-sdk-go-0.1.1.tar.gz
go mod edit -require github.com/scadra/passbolt-sdk-go@v0.0.0 \
            -replace github.com/scadra/passbolt-sdk-go=./passbolt-sdk-go
```

## Log in and list

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	passbolt "github.com/scadra/passbolt-sdk-go"
)

// The fields of a resource view used here; the overview lists the others.
type resourceView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

func main() {
	privateKey, err := os.ReadFile("private.asc")
	if err != nil {
		log.Fatal(err)
	}
	client, err := passbolt.PassboltClientLogin(
		"https://passbolt.example.com", string(privateKey), os.Getenv("PASSBOLT_PASSPHRASE"))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close() // logs out and releases the client

	search := "github"
	viewsJSON, err := client.ListResourceViews(&search, false)
	if err != nil {
		log.Fatal(err)
	}
	var views []resourceView
	if err := json.Unmarshal([]byte(viewsJSON), &views); err != nil {
		log.Fatal(err)
	}
	for _, view := range views {
		fmt.Println(view.ID, view.Name, view.Username)
	}
}
```

`Close` makes the client an `io.Closer`; `Logout` and `Destroy` are the two halves of it.

## Pinning the server, MFA, TLS

The fields of `FfiLoginOptions` left out keep their default: optional fields are pointers, `nil`
for none.

```go
serverKey, err := passbolt.FetchServerKey("https://passbolt.example.com", false)
if err != nil {
	return err
}
fmt.Println("Check this fingerprint with your administrator:", serverKey.Fingerprint)

totpSecret := os.Getenv("PASSBOLT_TOTP_SECRET") // the base32 TOTP secret, for an account with TOTP
timeout := uint64(30)                           // 60 by default, 0 waits forever
client, err := passbolt.PassboltClientLoginWithConfig(
	"https://passbolt.example.com", privateKey, passphrase,
	passbolt.FfiLoginOptions{
		ServerPublicKey: &serverKey.ArmoredKey,
		MfaTotpToken:    &totpSecret,
		TimeoutSeconds:  &timeout,
	})
if err != nil {
	return err
}
defer client.Close()
```

## Reading and writing

Views come as JSON text, and resources are written from JSON text, with the fields of the
[overview](README.md#concepts):

```go
viewJSON, err := client.GetResourceView(resourceID)
if err != nil {
	return err
}
var view struct {
	Password string `json:"password"`
}
if err := json.Unmarshal([]byte(viewJSON), &view); err != nil {
	return err
}

fields, err := json.Marshal(map[string]any{"name": "GitHub", "username": "ada", "password": "…"})
if err != nil {
	return err
}
created, err := client.CreateResource(string(fields))
if err != nil {
	return err
}
if _, err := client.UpdateResource(created.Id, `{"password": "new"}`); err != nil {
	return err
}
// 1 read, 7 update, 15 owner, -1 revokes.
if err := client.ShareResource(created.Id, []string{userID}, nil, 7); err != nil {
	return err
}
```

## Errors

Each call returns its failure as a `*passbolt.PassboltFfiError` wrapping one variant per cause,
`PassboltFfiErrorAuth`, `PassboltFfiErrorApi` (with the HTTP `Status`), `PassboltFfiErrorNotFound`…
each with its `Reason`. Match the variant with `errors.As`, or its kind with `errors.Is` and the
`ErrPassboltFfiError…` values:

```go
_, err := client.GetResource(resourceID)
var apiErr *passbolt.PassboltFfiErrorApi
switch {
case err == nil:
case errors.Is(err, passbolt.ErrPassboltFfiErrorNotFound):
	fmt.Println("no such resource")
case errors.As(err, &apiErr):
	fmt.Println("the server answered", apiErr.Status, apiErr.Reason)
default:
	return err
}
```

## Names

The methods are those of the [overview](README.md#what-the-api-covers), in PascalCase, generated
from the Rust names:

- A constructor of the Rust client is a function named after it: `PassboltClientLogin`,
  `PassboltClientLoginWithConfig`; the records keep their Rust prefix: `FfiResource`,
  `FfiLoginOptions`.
- Acronyms are written as words: `Id`, `Url`, `GetResourcesByIds`, `BaseUrl()`.
- Optional arguments and fields are pointers, `nil` for none.
- The calls take no `context.Context`: a request stops at the login timeout. The client is safe
  to use from several goroutines.
- The bindings export their plumbing too (`FfiConverter…`, `FfiDestroyer…`, `RustBuffer…`):
  leave it aside. The `Destroy` method of a record does nothing worth calling.
