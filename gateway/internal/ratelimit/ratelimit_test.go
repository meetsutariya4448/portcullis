package ratelimit

import (
	"testing"
	"time"
)

func TestTokenBucket_AllowsUpToBurstInstantly(t *testing.T) {
	b := NewTokenBucket(1, 3) // slow refill so only the initial burst matters
	for i := 0; i < 3; i++ {
		if !b.Allow() {
			t.Fatalf("expected request %d to be allowed within the initial burst of 3", i)
		}
	}
}

func TestTokenBucket_RejectsOnceBurstExhausted(t *testing.T) {
	b := NewTokenBucket(1, 2)
	b.Allow()
	b.Allow()
	if b.Allow() {
		t.Fatal("expected the 3rd immediate request to be rejected once burst is exhausted")
	}
}

// TestTokenBucket_RefillsOverTime proves tokens actually replenish from
// wall-clock elapsed time, not just at construction.
func TestTokenBucket_RefillsOverTime(t *testing.T) {
	b := NewTokenBucket(100, 1) // 100 tokens/sec, burst of 1
	if !b.Allow() {
		t.Fatal("expected the first request to be allowed")
	}
	if b.Allow() {
		t.Fatal("expected the immediate second request to be rejected (burst exhausted)")
	}
	time.Sleep(50 * time.Millisecond) // ~5 tokens' worth at 100/sec
	if !b.Allow() {
		t.Fatal("expected a request to be allowed after the bucket had time to refill")
	}
}

func TestTokenBucket_NeverExceedsBurstCapacity(t *testing.T) {
	b := NewTokenBucket(1000, 2) // fast refill, small burst
	time.Sleep(50 * time.Millisecond)
	allowed := 0
	for i := 0; i < 10; i++ {
		if b.Allow() {
			allowed++
		}
	}
	if allowed > 2 {
		t.Fatalf("expected refill to be capped at burst=2, got %d allowed requests", allowed)
	}
}

func TestLimiter_TracksClientsIndependently(t *testing.T) {
	l := NewLimiter(1, 1) // burst of 1 per client
	if !l.Allow("acme") {
		t.Fatal("expected acme's first request to be allowed")
	}
	if l.Allow("acme") {
		t.Fatal("expected acme's second immediate request to be rejected")
	}
	if !l.Allow("globex") {
		t.Fatal("expected globex to have its own independent bucket, unaffected by acme's usage")
	}
}

func TestLimiter_SameClientSharesBucketAcrossCalls(t *testing.T) {
	l := NewLimiter(1, 2)
	l.Allow("acme")
	l.Allow("acme")
	if l.Allow("acme") {
		t.Fatal("expected the 3rd call for the same client to reuse the same exhausted bucket")
	}
}
