package translate

import (
	"testing"
	"time"
)

// TestCircuitBreaker_AbortReleasesTheHalfOpenTrial is the regression test
// for a permanent wedge. Allow() reserves the single half-open trial and
// only Record() used to clear it, so a caller admitted in half-open that
// bailed out before touching the network -- pool exhaustion, a canceled
// bulkhead wait -- left the reservation set forever. Every subsequent
// Allow() then returned false for the life of the process, with no path
// back and no recorded outcome to justify it.
func TestCircuitBreaker_AbortReleasesTheHalfOpenTrial(t *testing.T) {
	b := newCircuitBreaker(time.Second, 10, 1, 0.5, 20*time.Millisecond)

	b.Allow()
	b.Record(false)
	if b.State() != StateOpen {
		t.Fatalf("precondition: want open, got %v", b.State())
	}
	time.Sleep(30 * time.Millisecond) // cooldown elapses

	if !b.Allow() {
		t.Fatal("the half-open trial was not admitted after the cooldown")
	}
	// The caller never reached the upstream, so there is no outcome to
	// record -- it hands the reservation back instead.
	b.Abort()

	if !b.Allow() {
		t.Fatal("breaker is wedged: Abort did not release the half-open trial")
	}
}

func TestCircuitBreaker_WithoutAbortTheTrialStaysReserved(t *testing.T) {
	// Pins the mechanism the fix addresses: an admitted trial that is
	// neither recorded nor aborted must still block, or Abort would be
	// papering over nothing.
	b := newCircuitBreaker(time.Second, 10, 1, 0.5, 10*time.Millisecond)
	b.Allow()
	b.Record(false)
	time.Sleep(20 * time.Millisecond)

	if !b.Allow() {
		t.Fatal("precondition: the trial should have been admitted")
	}
	if b.Allow() {
		t.Fatal("a second concurrent trial was admitted while one was in flight")
	}
}

func TestCircuitBreaker_AbortIsANoOpWhenClosed(t *testing.T) {
	b := newCircuitBreaker(time.Second, 10, 5, 0.5, time.Second)
	b.Abort()
	if !b.Allow() {
		t.Fatal("Abort disturbed a closed breaker")
	}
	if b.State() != StateClosed {
		t.Fatalf("state = %v, want closed", b.State())
	}
}

// TestHealthyStatus_TreatsServerErrorsAsUnhealthy covers the defect where
// an upstream that was up but answering 500 to everything never tripped its
// breaker: only transport errors counted, so 30 consecutive 500s left it
// closed with no failover.
func TestHealthyStatus_TreatsServerErrorsAsUnhealthy(t *testing.T) {
	for _, tc := range []struct {
		code    int
		healthy bool
		why     string
	}{
		{200, true, "success"},
		{204, true, "success"},
		{400, true, "the upstream correctly rejected this request"},
		{404, true, "not found is about the request, not the server"},
		{429, true, "rate limited is a healthy server saying no"},
		{500, false, "server error"},
		{502, false, "bad gateway"},
		{503, false, "unavailable"},
		{504, false, "gateway timeout"},
		{501, true, "not implemented is a stable answer about the request"},
		{505, true, "version not supported is a stable answer about the request"},
	} {
		if got := HealthyStatus(tc.code); got != tc.healthy {
			t.Errorf("HealthyStatus(%d) = %v, want %v (%s)", tc.code, got, tc.healthy, tc.why)
		}
	}
}

func TestHealthyStatus_ClientErrorsCannotTripASharedBreaker(t *testing.T) {
	// A client sending malformed requests must not be able to open a
	// breaker shared with every other client of that upstream -- that would
	// be a denial-of-service handed to the least trusted party.
	b := newCircuitBreaker(time.Second, 10, 2, 0.5, time.Second)
	for i := 0; i < 20; i++ {
		b.Allow()
		b.Record(HealthyStatus(400))
	}
	if b.State() != StateClosed {
		t.Fatalf("client errors opened the breaker (state %v)", b.State())
	}
}

func TestHealthyStatus_ServerErrorsDoOpenTheBreaker(t *testing.T) {
	b := newCircuitBreaker(time.Second, 10, 2, 0.5, time.Second)
	for i := 0; i < 10; i++ {
		b.Allow()
		b.Record(HealthyStatus(500))
	}
	if b.State() != StateOpen {
		t.Fatalf("10 consecutive 500s left the breaker %v; it should be open", b.State())
	}
}
