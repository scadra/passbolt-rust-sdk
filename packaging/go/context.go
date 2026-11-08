package passbolt

import "context"

// Call makes a call of the client in a goroutine and waits for it or for ctx, whichever ends
// first:
//
//	views, err := passbolt.Call(ctx, func() ([]passbolt.ResourceView, error) {
//		return client.ListResourceViews(nil)
//	})
//
// It does not cancel the call: when ctx ends first, Call returns ctx.Err() at once, while the
// request goes on in the background until the server answers or the login timeout
// (LoginOptions.TimeoutSeconds) stops it, and its result is dropped. A write may then still
// happen: after a context error, read the state back rather than assume nothing changed.
// A context that has already ended makes no call.
func Call[T any](ctx context.Context, call func() (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	type result struct {
		value T
		err   error
	}
	done := make(chan result, 1) // the goroutine never blocks, even when nobody waits
	go func() {
		value, err := call()
		done <- result{value, err}
	}()
	select {
	case r := <-done:
		return r.value, r.err
	case <-ctx.Done():
		// A call that ended at the same time keeps its result.
		select {
		case r := <-done:
			return r.value, r.err
		default:
			return zero, ctx.Err()
		}
	}
}

// Run is Call for the calls that return only an error:
//
//	err := passbolt.Run(ctx, func() error { return client.DeleteResource(id) })
func Run(ctx context.Context, call func() error) error {
	_, err := Call(ctx, func() (struct{}, error) { return struct{}{}, call() })
	return err
}
