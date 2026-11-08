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

	views, err := client.ListResourceViews(&passbolt.ResourceViewListOptions{Search: "github"})
	if err != nil {
		log.Fatal(err)
	}
	for _, view := range views {
		fmt.Println(view.ID, view.Name, view.Username)
	}
}
```

`Close` makes the client an `io.Closer`; `Logout` and `Destroy` are the two halves of it. It
returns the error of the logout, and releases the client anyway.

## Options

Go has no default arguments: the calls with optional arguments take an option struct, whose
zero value asks for the defaults. A field left out keeps its default, an empty string is no
value, and the `List` methods take `nil` for no filter:

```go
all, err := client.ListResources(nil)
if err != nil {
	return err
}
mine, err := client.ListResources(&passbolt.ResourceListOptions{OwnedByMe: true})
if err != nil {
	return err
}
admins, err := client.ListUsers(&passbolt.UserListOptions{AdminOnly: true})
if err != nil {
	return err
}
fmt.Println(len(all), len(mine), len(admins))

group, err := client.UpdateGroup(groupID, passbolt.GroupChanges{
	Name:            "Ops",
	AddMemberIDs:    []string{userID},
	RemoveMemberIDs: []string{"1d5c2c55-0a1b-4c0e-9b8f-3f1a8b7f2a10"},
})
if err != nil {
	return err
}
fmt.Println(group.Name)
```

| Method | Options |
|---|---|
| `ListResources` | `*ResourceListOptions`: `Search`, `FavoritesOnly`, `OwnedByMe` |
| `ListResourceViews` | `*ResourceViewListOptions`: `Search`, `WithSecrets` |
| `ListFolders` | `*FolderListOptions`: `Search` |
| `ListUsers` | `*UserListOptions`: `Search`, `GroupID`, `AdminOnly` |
| `UpdateGroup` | `GroupChanges`: `Name`, `AddMemberIDs`, `AddManagerIDs`, `RemoveMemberIDs` |
| `UpdateUser` | `UserChanges`: `FirstName`, `LastName`, `Role` |
| `ShareResource` | `Share`: `Permission`, `UserIDs`, `GroupIDs` |
| `ShareFolder` | `FolderShare`: `Permission`, `UserIDs`, `GroupIDs`, `WithContent` |

The records (`LoginOptions`, `NewResource`, `ResourceChanges`…) keep pointers for their optional
fields, `nil` for none; so do the few calls with one optional argument, such as
`CreateFolder(name, nil)` for a folder at the root.

## Pinning the server, MFA, TLS

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
`URIs`, `Password`, `Totp`…); the others, custom fields and icon among them, are the JSON
objects `MetadataJSON` and `SecretJSON`. `NewResource` and `ResourceChanges` write the same
fields, the fields left out keep their default:

```go
view, err := client.GetResourceView(resourceID)
if err != nil {
	return err
}
if view.Password != nil {
	fmt.Println(*view.Password)
}

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
if _, err := client.UpdateResource(created.ID, passbolt.ResourceChanges{Password: &newPassword}); err != nil {
	return err
}
if err := client.ShareResource(created.ID, passbolt.Share{
	Permission: passbolt.PermissionUpdate, // PermissionRead, PermissionOwner, PermissionRevoke
	UserIDs:    []string{userID},
}); err != nil {
	return err
}
```

## Contexts

The calls take no `context.Context`: the Rust call they make cannot be interrupted, it stops
when the server answers or at the login timeout. `passbolt.Call` and `passbolt.Run` make a call
in a goroutine and stop *waiting* for it when the context ends, returning `ctx.Err()`, for a
server handler that must answer before its deadline:

```go
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()
views, err := passbolt.Call(ctx, func() ([]passbolt.ResourceView, error) {
	return client.ListResourceViews(nil)
})
if errors.Is(err, context.DeadlineExceeded) {
	return err // the request goes on in the background, its result is dropped
}
if err != nil {
	return err
}
fmt.Println(len(views))

if err := passbolt.Run(ctx, func() error { return client.DeleteResource(resourceID) }); err != nil {
	return err
}
```

The call abandoned still runs to its end: after a context error, a write may have happened,
read the state back rather than assume it did not. A context that has already ended makes no
call. To bound the call itself, set `LoginOptions.TimeoutSeconds`.

## Errors

Each call returns its failure as a `*passbolt.PassboltError` wrapping one variant per cause,
`PassboltErrorAuth`, `PassboltErrorAPI` (with the HTTP `Status`), `PassboltErrorNotFound`…
each with its `Reason`. Match the variant with `errors.As`, or its kind with `errors.Is` and the
`ErrPassboltError…` values:

```go
_, err := client.GetResource(resourceID)
var apiErr *passbolt.PassboltErrorAPI
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
- Initialisms are capitals, as in the standard library: `ID`, `URL`, `URIs`, `MetadataJSON`,
  `GetResourcesByIDs`, `BaseURL()`, `PassboltErrorAPI`.
- The calls with optional arguments take the option structs above; the others take every
  argument, `nil` for an optional one.
- The client is safe to use from several goroutines. Its methods are those of the type
  `*PassboltClient`: for a test double, declare the interface of the methods your code calls.
- The `Destroy` method of a record does nothing worth calling.
