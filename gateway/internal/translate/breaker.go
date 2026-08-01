package translate

import (
	"sync"
	"time"
)

// Circuit breaker defaults. "Per-upstream circuit breaker: open at 50%
// error rate over a 10s window" (task requirements) — implemented as a
// 10-bucket sliding window with 1-second-resolution buckets.
const (
	defaultBreakerWindow  = 10 * time.Second
	defaultBreakerBuckets = 10
	// defaultBreakerMinSamples avoids tripping the breaker on a handful of
	// requests right after startup, before the window has enough signal.
	defaultBreakerMinSamples = 5
	defaultBreakerThreshold  = 0.5
	// defaultBreakerCooldown is how long the breaker stays open before
	// allowing a single half-open trial request.
	defaultBreakerCooldown = 5 * time.Second
)

type breakerState int

const (
	stateClosed breakerState = iota
	stateOpen
	stateHalfOpen
)

type bucket struct {
	start     time.Time
	successes int
	failures  int
}

// CircuitBreaker is a per-upstream sliding-window circuit breaker: it opens
// when the error rate over the trailing window crosses its threshold,
// fails fast while open, and probes recovery with a single half-open trial
// after its cooldown elapses.
type CircuitBreaker struct {
	window     time.Duration
	bucketWide time.Duration
	minSamples int
	threshold  float64
	cooldown   time.Duration

	mu               sync.Mutex
	buckets          []bucket
	state            breakerState
	openedAt         time.Time
	halfOpenInFlight bool
}

// NewCircuitBreaker returns a closed circuit breaker using the task's
// stated policy: 50% error rate over a 10s window.
func NewCircuitBreaker() *CircuitBreaker {
	return newCircuitBreaker(defaultBreakerWindow, defaultBreakerBuckets, defaultBreakerMinSamples, defaultBreakerThreshold, defaultBreakerCooldown)
}

// newCircuitBreaker builds a breaker with explicit tuning, letting tests
// use a short window/cooldown instead of the real 10s/5s defaults.
func newCircuitBreaker(window time.Duration, buckets int, minSamples int, threshold float64, cooldown time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		window:     window,
		bucketWide: window / time.Duration(buckets),
		minSamples: minSamples,
		threshold:  threshold,
		cooldown:   cooldown,
		buckets:    make([]bucket, buckets),
	}
}

// Allow reports whether a request may proceed. Every call to Allow that
// returns true MUST be paired with exactly one call to Record once the
// request completes.
func (b *CircuitBreaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case stateOpen:
		if time.Since(b.openedAt) < b.cooldown {
			return false
		}
		b.state = stateHalfOpen
		b.halfOpenInFlight = true
		return true
	case stateHalfOpen:
		if b.halfOpenInFlight {
			return false
		}
		b.halfOpenInFlight = true
		return true
	default:
		return true
	}
}

// Record reports the outcome of a request previously admitted by Allow.
func (b *CircuitBreaker) Record(success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	b.recordBucket(now, success)

	switch b.state {
	case stateHalfOpen:
		b.halfOpenInFlight = false
		if success {
			b.resetLocked()
			b.state = stateClosed
		} else {
			b.state = stateOpen
			b.openedAt = now
		}
	case stateClosed:
		successes, failures := b.windowLocked(now)
		total := successes + failures
		if total >= b.minSamples {
			rate := float64(failures) / float64(total)
			if rate >= b.threshold {
				b.state = stateOpen
				b.openedAt = now
			}
		}
	}
}

func (b *CircuitBreaker) recordBucket(now time.Time, success bool) {
	idx := int(now.UnixNano()/int64(b.bucketWide)) % len(b.buckets)
	if idx < 0 {
		idx += len(b.buckets)
	}
	start := now.Truncate(b.bucketWide)
	if !b.buckets[idx].start.Equal(start) {
		b.buckets[idx] = bucket{start: start}
	}
	if success {
		b.buckets[idx].successes++
	} else {
		b.buckets[idx].failures++
	}
}

func (b *CircuitBreaker) windowLocked(now time.Time) (successes, failures int) {
	cutoff := now.Add(-b.window)
	for _, bk := range b.buckets {
		if bk.start.After(cutoff) {
			successes += bk.successes
			failures += bk.failures
		}
	}
	return successes, failures
}

func (b *CircuitBreaker) resetLocked() {
	b.buckets = make([]bucket, len(b.buckets))
}
