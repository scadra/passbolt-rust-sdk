// The module links its static library, maps Rust errors to Go errors, and has the hand-written
// layer of packaging/go: option structs, Call and Run, Go names.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	passbolt "github.com/scadra/passbolt-sdk-go"
)

// The client releases itself with a `defer client.Close()`.
var _ io.Closer = (*passbolt.PassboltClient)(nil)

// The methods with optional arguments take option structs (checked by the compiler: the calls
// need a server).
var (
	_ func(*passbolt.ResourceListOptions) ([]passbolt.Resource, error)         = (*passbolt.PassboltClient)(nil).ListResources
	_ func(*passbolt.ResourceViewListOptions) ([]passbolt.ResourceView, error) = (*passbolt.PassboltClient)(nil).ListResourceViews
	_ func(*passbolt.FolderListOptions) ([]passbolt.Folder, error)             = (*passbolt.PassboltClient)(nil).ListFolders
	_ func(*passbolt.UserListOptions) ([]passbolt.User, error)                 = (*passbolt.PassboltClient)(nil).ListUsers
	_ func(string, passbolt.GroupChanges) (passbolt.Group, error)              = (*passbolt.PassboltClient)(nil).UpdateGroup
	_ func(string, passbolt.UserChanges) (passbolt.User, error)                = (*passbolt.PassboltClient)(nil).UpdateUser
	_ func(string, passbolt.Share) error                                       = (*passbolt.PassboltClient)(nil).ShareResource
	_ func(string, passbolt.FolderShare) error                                 = (*passbolt.PassboltClient)(nil).ShareFolder
	_ func(string, *string) (passbolt.Folder, error)                           = (*passbolt.PassboltClient)(nil).CreateFolder
	_ func([]string) ([]passbolt.Resource, error)                              = (*passbolt.PassboltClient)(nil).GetResourcesByIDs
)

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func main() {
	// A call through Call, its error matched with errors.As and errors.Is.
	_, err := passbolt.Call(context.Background(), func() (string, error) {
		return passbolt.GetKeyFingerprint("not a key")
	})
	var cryptoErr *passbolt.PassboltErrorCrypto
	if !errors.As(err, &cryptoErr) || !errors.Is(err, passbolt.ErrPassboltErrorCrypto) {
		fail("expected a crypto error, got: %v", err)
	}
	var apiErr *passbolt.PassboltErrorAPI
	if errors.As(err, &apiErr) || errors.Is(err, passbolt.ErrPassboltErrorAPI) {
		fail("a crypto error is not an API error: %v", err)
	}

	// A context that has ended makes no call.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if err := passbolt.Run(ctx, func() error { called = true; return nil }); !errors.Is(err, context.Canceled) || called {
		fail("expected context.Canceled without a call, got: %v (called: %v)", err, called)
	}

	// The generator of the extension, from the default policies: the zero value has no
	// character set.
	settings := passbolt.DefaultPasswordPolicies().PasswordGeneratorSettings
	settings.Length = 24
	password, err := passbolt.GeneratePassword(settings)
	if err != nil || len([]rune(password)) != 24 {
		fail("expected a password of 24 characters, got %q: %v", password, err)
	}
	if _, err := passbolt.GeneratePassword(passbolt.PasswordGeneratorSettings{}); !errors.Is(err, passbolt.ErrPassboltErrorInvalidArgument) {
		fail("expected an invalid argument without character set, got: %v", err)
	}
	if strength := passbolt.SecretStrength(password); strength != passbolt.StrengthVeryStrong {
		fail("expected a very strong password, got %v", strength)
	}

	// The records have Go names.
	view := passbolt.ResourceView{ID: "id", URIs: []string{"https://example.com"}}
	_ = passbolt.LoginOptions{TLSSkipVerify: false}
	fmt.Println("ok:", cryptoErr.Reason, view.ID)
}
