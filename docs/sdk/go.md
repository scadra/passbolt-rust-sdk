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
	"fmt"
	"log"
	"os"

	passbolt "github.com/scadra/passbolt-sdk-go"
)

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
	views, err := client.ListResourceViews(&search, false)
	if err != nil {
		log.Fatal(err)
	}
	for _, view := range views {
		fmt.Println(view.Id, view.Name, view.Username)
	}
}
```

`Close` makes the client an `io.Closer`; `Logout` and `Destroy` are the two halves of it.

## Pinning the server, MFA, TLS

The fields of `LoginOptions` left out keep their default: optional fields are pointers, `nil`
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
	passbolt.LoginOptions{
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

A `ResourceView` holds the fields every resource type shares, decrypted (`Name`, `Username`,
`Uris`, `Password`, `Totp`…); the others, custom fields and icon among them, are the JSON
objects `MetadataJson` and `SecretJson`. `NewResource` and `ResourceChanges` write the same
fields, the fields left out keep their default:

```go
view, err := client.GetResourceView(resourceID)
if err != nil {
	return err
}
fmt.Println(*view.Password)

username, password := "ada", "…"
created, err := client.CreateResource(passbolt.NewResource{
	Name:     "GitHub",
	Username: &username,
	Password: &password,
})
if err != nil {
	return err
}
newPassword := "new"
if _, err := client.UpdateResource(created.Id, passbolt.ResourceChanges{Password: &newPassword}); err != nil {
	return err
}
// 1 read, 7 update, 15 owner, -1 revokes.
if err := client.ShareResource(created.Id, 7, []string{userID}, nil); err != nil {
	return err
}
```

## Errors

Each call returns its failure as a `*passbolt.PassboltError` wrapping one variant per cause,
`PassboltErrorAuth`, `PassboltErrorApi` (with the HTTP `Status`), `PassboltErrorNotFound`…
each with its `Reason`. Match the variant with `errors.As`, or its kind with `errors.Is` and the
`ErrPassboltError…` values:

```go
_, err := client.GetResource(resourceID)
var apiErr *passbolt.PassboltErrorApi
switch {
case err == nil:
case errors.Is(err, passbolt.ErrPassboltErrorNotFound):
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
  `PassboltClientLoginWithConfig`.
- Acronyms are written as words: `Id`, `Url`, `GetResourcesByIds`, `BaseUrl()`.
- Optional arguments and fields are pointers, `nil` for none. Go has no default arguments: each
  call gives them all.
- The calls take no `context.Context`: a request stops at the login timeout. The client is safe
  to use from several goroutines.
- The bindings export their plumbing too (`FfiConverter…`, `FfiDestroyer…`, `RustBuffer…`):
  leave it aside. The `Destroy` method of a record does nothing worth calling.
