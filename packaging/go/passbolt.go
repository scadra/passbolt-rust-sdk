// Package passbolt is the Passbolt SDK for Go: log in to a Passbolt server, read, write and share
// its resources, folders, users and groups, with the OpenPGP encryption done by the Rust SDK.
//
// The calls block until the server answers (60 seconds at most by default, see
// FfiLoginOptions.TimeoutSeconds) and are safe to make from several goroutines. A failure is a
// *PassboltFfiError wrapping one variant, to match with errors.As or errors.Is:
//
//	var apiErr *passbolt.PassboltFfiErrorApi
//	if errors.As(err, &apiErr) && apiErr.Status == 403 { … }
//	if errors.Is(err, passbolt.ErrPassboltFfiErrorNotFound) { … }
//
// The module links a static library with cgo: CGO_ENABLED=1, on Linux or macOS.
package passbolt

// Close logs out and releases the client: it implements io.Closer, for a `defer client.Close()`.
// Logging out is best effort, Close always returns nil; a second call does nothing.
func (client *PassboltClient) Close() error {
	if client.ffiObject.destroyed.Load() {
		return nil
	}
	client.Logout()
	client.Destroy()
	return nil
}
