// Package retry provides bounded exponential backoff with full jitter for
// operations that are only safe to repeat when the specific attempt that
// failed never reached the point of no return.
//
// This package has no idea what the wrapped function does, so it cannot
// enforce that boundary itself: it is the caller's responsibility to
// return a bare (retryable) error only for failures that happened before
// any side effect could have reached whatever is on the other end, and to
// wrap everything else in NonRetryable. See the call sites in
// internal/server and internal/translate for the actual safety-boundary
// reasoning (MCP tool calls are not guaranteed idempotent).
package retry

import (
	"context"
	"errors"
	"math/rand"
	"time"
)

// Config tunes retry behavior. The zero value is not directly usable as
// "no retries" — use MaxAttempts: 1 to disable retries explicitly, or
// leave a Config entirely unset and let Do substitute DefaultConfig.
type Config struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

// DefaultConfig is substituted for any zero field in a Config passed to Do.
var DefaultConfig = Config{
	MaxAttempts: 3,
	BaseDelay:   20 * time.Millisecond,
	MaxDelay:    200 * time.Millisecond,
}

// nonRetryable marks an error as unsafe to retry regardless of remaining
// attempts.
type nonRetryable struct{ err error }

func (n nonRetryable) Error() string { return n.err.Error() }
func (n nonRetryable) Unwrap() error { return n.err }

// NonRetryable wraps err to tell Do to return it immediately without
// consuming further attempts. Do unwraps it before returning, so callers
// downstream of Do never see the wrapper — errors.Is/As against the
// original error still works.
func NonRetryable(err error) error {
	if err == nil {
		return nil
	}
	return nonRetryable{err}
}

// Do calls fn up to cfg.MaxAttempts times (an unset or <1 MaxAttempts
// means exactly one attempt), waiting a full-jitter exponential backoff
// delay between attempts, until fn returns nil, returns an error wrapped
// by NonRetryable, or ctx is done. fn receives the 1-based attempt number.
func Do(ctx context.Context, cfg Config, fn func(attempt int) error) error {
	maxAttempts := cfg.MaxAttempts
	if maxAttempts < 1 {
		maxAttempts = DefaultConfig.MaxAttempts
	}
	baseDelay := cfg.BaseDelay
	if baseDelay <= 0 {
		baseDelay = DefaultConfig.BaseDelay
	}
	maxDelay := cfg.MaxDelay
	if maxDelay <= 0 {
		maxDelay = DefaultConfig.MaxDelay
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		err := fn(attempt)
		if err == nil {
			return nil
		}
		var nr nonRetryable
		if errors.As(err, &nr) {
			return nr.err
		}
		lastErr = err

		if attempt == maxAttempts {
			break
		}
		if err := sleep(ctx, backoffDelay(baseDelay, maxDelay, attempt)); err != nil {
			return err
		}
	}
	return lastErr
}

// backoffDelay returns a full-jitter exponential backoff delay for the
// given (1-based) attempt just completed: a random duration in
// [0, min(maxDelay, base*2^(attempt-1))].
func backoffDelay(base, maxDelay time.Duration, attempt int) time.Duration {
	d := base
	for i := 1; i < attempt; i++ {
		if d > maxDelay/2 {
			d = maxDelay
			break
		}
		d *= 2
	}
	if d > maxDelay {
		d = maxDelay
	}
	return time.Duration(rand.Int63n(int64(d) + 1))
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
