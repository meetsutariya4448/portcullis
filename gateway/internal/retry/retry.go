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
//
// A caller that layers failover on top of Do — retrying a DIFFERENT
// target after Do gives up on the current one — has a second, related
// question to answer: was this failure provably local (safe to attempt
// elsewhere), or did it possibly reach the far side (unsafe anywhere)?
// SkipTarget and SafeToRetryElsewhere answer that; see their doc comments.
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

// nonRetryable marks an error as unsafe to retry against the current
// target — Do stops immediately regardless of remaining attempts.
// unsafeElsewhere additionally distinguishes whether the underlying
// operation may have reached the far side (true — genuinely unsafe to
// attempt against ANY target, the original retry-safety boundary) from a
// failure that's provably local, such as an already-open circuit
// breaker (false — safe for a caller building failover on top of Do to
// try a different target). See NonRetryable vs SkipTarget.
type nonRetryable struct {
	err             error
	unsafeElsewhere bool
}

func (n nonRetryable) Error() string { return n.err.Error() }
func (n nonRetryable) Unwrap() error { return n.err }

// NonRetryable wraps err to tell Do to return it immediately without
// consuming further attempts, AND to tell a failover caller (one that
// tries a different target after Do gives up) that this failure may have
// reached the far side — the operation might have already executed, so
// no other target should be attempted either. errors.Is/As against the
// original err still works through the wrapper's Unwrap.
func NonRetryable(err error) error {
	if err == nil {
		return nil
	}
	return nonRetryable{err: err, unsafeElsewhere: true}
}

// SkipTarget wraps err the same way NonRetryable does for Do's purposes
// (stop immediately, no further attempts against the current target) but
// marks it as safe to attempt against a DIFFERENT target — for a failure
// that's provably local and never touched the network: a circuit breaker
// already open, or a request that failed to even build. Distinct from
// NonRetryable, which means the operation may have reached the far side
// and is therefore unsafe anywhere.
func SkipTarget(err error) error {
	if err == nil {
		return nil
	}
	return nonRetryable{err: err, unsafeElsewhere: false}
}

// SafeToRetryElsewhere reports whether err, as returned by Do, permits a
// caller to attempt a different target. True for a bare error (Do
// exhausted MaxAttempts on failures that were always safe to retry) or a
// SkipTarget error; false only for a NonRetryable error, since the
// underlying operation may have reached the far side.
func SafeToRetryElsewhere(err error) bool {
	var nr nonRetryable
	if errors.As(err, &nr) {
		return !nr.unsafeElsewhere
	}
	return true
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
			return nr
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
