// Package ratelimit implements Portcullis's per-client request-rate gate:
// a hand-rolled token bucket (not golang.org/x/time/rate — same
// deliberate own-the-primitive spirit as internal/router's bulkhead and
// internal/translate's circuit breaker), one per client, refilled lazily
// on each Allow() call rather than by a background goroutine.
package ratelimit

import (
	"sync"
	"time"
)

// TokenBucket allows up to burst requests instantly, then refills at
// ratePerSecond tokens/second. Refill is computed lazily from elapsed
// wall-clock time on each Allow() call — no ticker, no goroutine.
type TokenBucket struct {
	mu         sync.Mutex
	rate       float64 // tokens added per second
	burst      float64 // maximum tokens the bucket can hold
	tokens     float64
	lastRefill time.Time
}

// NewTokenBucket returns a bucket starting full (burst tokens available
// immediately), refilling at ratePerSecond tokens/second thereafter.
func NewTokenBucket(ratePerSecond float64, burst int) *TokenBucket {
	return &TokenBucket{
		rate:       ratePerSecond,
		burst:      float64(burst),
		tokens:     float64(burst),
		lastRefill: time.Now(),
	}
}

// Allow reports whether a request may proceed right now, consuming one
// token if so.
func (b *TokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.lastRefill = now

	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Limiter maps a client ID to its own TokenBucket, all sharing the same
// configured rate/burst — buckets are created lazily on first use so an
// operator doesn't need to pre-enumerate every client ID up front.
//
// State is process-local and in-memory: behind multiple gateway
// instances, a client's effective rate limit multiplies by the instance
// count. Same precedent as internal/translate.CircuitBreaker's
// process-local state — documented here rather than hidden.
type Limiter struct {
	rate  float64
	burst int

	mu      sync.Mutex
	buckets map[string]*TokenBucket
}

// NewLimiter returns a Limiter that hands every client the same
// ratePerSecond/burst configuration, each tracked independently.
func NewLimiter(ratePerSecond float64, burst int) *Limiter {
	return &Limiter{
		rate:    ratePerSecond,
		burst:   burst,
		buckets: make(map[string]*TokenBucket),
	}
}

// Allow reports whether clientID may make a request right now.
func (l *Limiter) Allow(clientID string) bool {
	l.mu.Lock()
	b, ok := l.buckets[clientID]
	if !ok {
		b = NewTokenBucket(l.rate, l.burst)
		l.buckets[clientID] = b
	}
	l.mu.Unlock()
	return b.Allow()
}
