// Package passbolt is the Passbolt SDK for Go: log in to a Passbolt server, read, write and share
// its resources, folders, users and groups, with the OpenPGP encryption done by the Rust SDK.
//
//	client, err := passbolt.PassboltClientLogin(serverURL, privateKey, passphrase)
//	if err != nil { … }
//	defer client.Close()
//	views, err := client.ListResourceViews(&passbolt.ResourceViewListOptions{Search: "github"})
//
// The calls with optional arguments take an option struct whose zero value asks for the
// defaults (ResourceListOptions, UserListOptions, GroupChanges, Share…); the List methods take
// nil for no filter. The records returned keep pointers for their optional fields, nil for none.
//
// The calls block until the server answers (60 seconds at most by default, see
// LoginOptions.TimeoutSeconds) and are safe to make from several goroutines. They take no
// context.Context, since the Rust call cannot be interrupted; Call and Run stop waiting for one
// when a context ends.
//
// A failure is a *PassboltError wrapping one variant, to match with errors.As or errors.Is:
//
//	var apiErr *passbolt.PassboltErrorAPI
//	if errors.As(err, &apiErr) && apiErr.Status == 403 { … }
//	if errors.Is(err, passbolt.ErrPassboltErrorNotFound) { … }
//
// The module links a static library with cgo: CGO_ENABLED=1, on Linux or macOS.
package passbolt

// Close logs out and releases the client: it implements io.Closer, for a `defer client.Close()`.
// It returns the error of the logout, the client is released anyway; a second call does nothing.
func (client *PassboltClient) Close() error {
	if client.ffiObject.destroyed.Load() {
		return nil
	}
	err := client.Logout()
	client.Destroy()
	return err
}
