// The module links its static library and maps Rust errors to Go errors.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	passbolt "github.com/scadra/passbolt-sdk-go"
)

// The client releases itself with a `defer client.Close()`.
var _ io.Closer = (*passbolt.PassboltClient)(nil)

func main() {
	_, err := passbolt.GetKeyFingerprint("not a key")
	var cryptoErr *passbolt.PassboltErrorCrypto
	if !errors.As(err, &cryptoErr) || !errors.Is(err, passbolt.ErrPassboltErrorCrypto) {
		fmt.Fprintln(os.Stderr, "expected a crypto error, got:", err)
		os.Exit(1)
	}
	fmt.Println("ok:", cryptoErr.Reason)
}
