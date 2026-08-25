package retry

import (
	"context"
	"net"
)

// connEstablishedKey is the context key WithConnProbe stashes its flag
// under. Unexported so only this package can read or write it — callers
// interact with it only through WithConnProbe and the accessor it returns.
type connEstablishedKey struct{}

// WithConnProbe returns a context carrying a fresh "TCP connection
// established" flag, and an accessor to read it back after a request
// using that context has completed. Pair it with ProbeDialContext on the
// http.Transport actually performing the dial.
//
// This is the mechanism behind the retry safety boundary for HTTP
// forwards: a request that failed WITHOUT ever establishing a connection
// failed before it could have reached the far side at all, so retrying it
// can't duplicate a side effect. A request that failed AFTER connecting
// may have already been partially or fully processed by the far side —
// that failure must not be retried automatically for a non-idempotent
// call. Sniffing net.OpError types/strings after the fact is fragile;
// recording the outcome at the one place that actually knows (the dial
// itself) is not.
func WithConnProbe(ctx context.Context) (context.Context, func() bool) {
	flag := new(bool)
	return context.WithValue(ctx, connEstablishedKey{}, flag), func() bool { return *flag }
}

// ProbeDialContext wraps a DialContext function (typically
// (&net.Dialer{}).DialContext) so that a successful dial sets the flag
// stashed by WithConnProbe on the context passed to that specific dial,
// if any. Requests made with a context that never went through
// WithConnProbe are unaffected — the flag lookup is a no-op.
func ProbeDialContext(dial func(ctx context.Context, network, addr string) (net.Conn, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dial(ctx, network, addr)
		if err == nil {
			if flag, ok := ctx.Value(connEstablishedKey{}).(*bool); ok {
				*flag = true
			}
		}
		return conn, err
	}
}
