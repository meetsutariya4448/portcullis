package quota

import (
	"testing"
	"time"
)

func TestCounter_AllowsUpToMaxWithinWindow(t *testing.T) {
	c := newCounter(time.Hour, 60, 3)
	for i := 0; i < 3; i++ {
		if !c.Allow() {
			t.Fatalf("expected request %d to be allowed within max=3", i)
		}
	}
}

func TestCounter_RejectsOnceMaxExhausted(t *testing.T) {
	c := newCounter(time.Hour, 60, 2)
	c.Allow()
	c.Allow()
	if c.Allow() {
		t.Fatal("expected the 3rd request to be rejected once max is exhausted")
	}
}

// TestCounter_RejectedCallDoesNotConsume proves a rejected Allow() call
// doesn't itself get counted -- rejecting doesn't make future admission
// even less likely.
func TestCounter_RejectedCallDoesNotConsume(t *testing.T) {
	c := newCounter(time.Hour, 60, 1)
	if !c.Allow() {
		t.Fatal("expected the first request to be allowed")
	}
	for i := 0; i < 5; i++ {
		if c.Allow() {
			t.Fatalf("call %d: expected rejection once max=1 is exhausted", i)
		}
	}
	// Still exactly 1 admitted request recorded -- repeated rejected
	// calls above didn't push the window total past max.
	if got := c.windowTotalLocked(time.Now()); got != 1 {
		t.Fatalf("expected exactly 1 recorded request, got %d", got)
	}
}

// TestCounter_OldRequestsFallOutOfWindow proves the window actually
// slides: once enough real time has passed, requests recorded before the
// window's start no longer count against max.
func TestCounter_OldRequestsFallOutOfWindow(t *testing.T) {
	window := 80 * time.Millisecond
	c := newCounter(window, 8, 1) // 8 buckets over 80ms = 10ms resolution
	if !c.Allow() {
		t.Fatal("expected the first request to be allowed")
	}
	if c.Allow() {
		t.Fatal("expected the second immediate request to be rejected (max=1 exhausted)")
	}
	time.Sleep(120 * time.Millisecond) // longer than the window
	if !c.Allow() {
		t.Fatal("expected a request to be allowed once the earlier one aged out of the window")
	}
}

func TestTracker_TracksClientsIndependently(t *testing.T) {
	tr := NewTracker(time.Hour, 1)
	if !tr.Allow("acme") {
		t.Fatal("expected acme's first request to be allowed")
	}
	if tr.Allow("acme") {
		t.Fatal("expected acme's second immediate request to be rejected")
	}
	if !tr.Allow("globex") {
		t.Fatal("expected globex to have its own independent counter, unaffected by acme's usage")
	}
}

func TestTracker_SameClientSharesCounterAcrossCalls(t *testing.T) {
	tr := NewTracker(time.Hour, 2)
	tr.Allow("acme")
	tr.Allow("acme")
	if tr.Allow("acme") {
		t.Fatal("expected the 3rd call for the same client to reuse the same exhausted counter")
	}
}
