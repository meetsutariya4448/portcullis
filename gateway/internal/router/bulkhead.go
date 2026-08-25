package router

import "context"

// bulkhead bounds concurrent in-flight requests to a single upstream,
// independent of connection pooling. This is what actually isolates a
// slow or overloaded upstream from starving goroutines/connections meant
// for the others: MaxIdleConnsPerHost only bounds connection *reuse*, not
// concurrency — a native upstream with no bulkhead can have unbounded
// concurrent dials under load.
//
// A buffered channel used as a semaphore, per the standard idiomatic Go
// pattern — no external dependency needed for something this small.
type bulkhead chan struct{}

// newBulkhead returns a bulkhead admitting up to size concurrent holders.
func newBulkhead(size int) bulkhead {
	if size <= 0 {
		size = 1
	}
	return make(bulkhead, size)
}

// Acquire blocks until a slot is free or ctx is done. Exported (unlike the
// bulkhead type itself) because callers outside this package hold a
// bulkhead value via Upstream.Bulkhead and need to call it directly —
// method visibility, not type visibility, is what gates that in Go.
func (b bulkhead) Acquire(ctx context.Context) error {
	select {
	case b <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release frees a slot previously obtained from Acquire. Must be called
// exactly once per successful Acquire.
func (b bulkhead) Release() {
	<-b
}
