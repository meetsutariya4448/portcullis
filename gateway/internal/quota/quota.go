// Package quota implements Portcullis's per-client request quota: a
// longer-horizon sibling to internal/ratelimit's token bucket, admitting
// at most N requests per client within a sliding window (typically hours
// or days, vs. rate limiting's per-second cadence).
package quota

import (
	"sync"
	"time"
)

// defaultBuckets is the sliding window's internal resolution — a fixed
// bucket count regardless of window length, same shape as
// internal/translate.CircuitBreaker's window (deliberately not shared
// code with it: different scale, and coupling that already-shipped,
// tested code to a new shared package isn't worth the risk for this).
const defaultBuckets = 60

type bucketEntry struct {
	start time.Time
	count int
}

// Counter is a bucketed sliding-window request counter for a single
// client: at most max requests may be admitted within the trailing
// window.
type Counter struct {
	mu         sync.Mutex
	window     time.Duration
	bucketWide time.Duration
	max        int
	buckets    []bucketEntry
}

// NewCounter returns a Counter admitting at most max requests within the
// trailing window.
func NewCounter(window time.Duration, max int) *Counter {
	return newCounter(window, defaultBuckets, max)
}

// newCounter lets tests use a small bucket count alongside a short
// window, rather than always paying defaultBuckets' resolution.
func newCounter(window time.Duration, buckets int, max int) *Counter {
	return &Counter{
		window:     window,
		bucketWide: window / time.Duration(buckets),
		max:        max,
		buckets:    make([]bucketEntry, buckets),
	}
}

// Allow reports whether one more request may proceed within the window.
// Unlike a token bucket, a rejected call consumes nothing — only an
// admitted request is recorded.
func (c *Counter) Allow() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if c.windowTotalLocked(now) >= c.max {
		return false
	}
	c.recordLocked(now)
	return true
}

func (c *Counter) windowTotalLocked(now time.Time) int {
	cutoff := now.Add(-c.window)
	total := 0
	for _, b := range c.buckets {
		if b.start.After(cutoff) {
			total += b.count
		}
	}
	return total
}

func (c *Counter) recordLocked(now time.Time) {
	idx := int(now.UnixNano()/int64(c.bucketWide)) % len(c.buckets)
	if idx < 0 {
		idx += len(c.buckets)
	}
	start := now.Truncate(c.bucketWide)
	if !c.buckets[idx].start.Equal(start) {
		c.buckets[idx] = bucketEntry{start: start}
	}
	c.buckets[idx].count++
}

// Tracker maps a client ID to its own Counter, all sharing the same
// configured window/max, created lazily on first use.
//
// State is process-local and in-memory: behind multiple gateway
// instances, a client's effective quota multiplies by instance count —
// same precedent, and same caveat, as internal/ratelimit.Limiter.
type Tracker struct {
	window time.Duration
	max    int

	mu       sync.Mutex
	counters map[string]*Counter
}

// NewTracker returns a Tracker admitting at most max requests per client
// within the trailing window.
func NewTracker(window time.Duration, max int) *Tracker {
	return &Tracker{
		window:   window,
		max:      max,
		counters: make(map[string]*Counter),
	}
}

// Allow reports whether clientID may make a request right now.
func (t *Tracker) Allow(clientID string) bool {
	t.mu.Lock()
	c, ok := t.counters[clientID]
	if !ok {
		c = NewCounter(t.window, t.max)
		t.counters[clientID] = c
	}
	t.mu.Unlock()
	return c.Allow()
}
