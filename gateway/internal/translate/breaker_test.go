package translate

import (
	"testing"
	"time"
)

// testBreaker builds a breaker with a short window/cooldown so tests don't
// need to sleep for the real 10s/5s defaults.
func testBreaker() *CircuitBreaker {
	return newCircuitBreaker(200*time.Millisecond, 10, 4, 0.5, 80*time.Millisecond)
}

func TestCircuitBreaker_ClosedByDefault(t *testing.T) {
	b := testBreaker()
	if !b.Allow() {
		t.Fatal("expected a fresh breaker to allow requests")
	}
}

func TestCircuitBreaker_OpensAtErrorThreshold(t *testing.T) {
	b := testBreaker()

	// 2 successes, 2 failures: 50% error rate at the minSamples floor.
	for _, ok := range []bool{true, true, false, false} {
		if !b.Allow() {
			t.Fatal("breaker should still be closed while recording the sample")
		}
		b.Record(ok)
	}

	if b.Allow() {
		t.Fatal("expected breaker to be open after a 50% error rate over minSamples requests")
	}
}

func TestCircuitBreaker_StaysClosedBelowThreshold(t *testing.T) {
	b := testBreaker()

	// 3 successes, 1 failure: 25% error rate, below the 50% threshold.
	for _, ok := range []bool{true, true, true, false} {
		b.Allow()
		b.Record(ok)
	}

	if !b.Allow() {
		t.Fatal("expected breaker to stay closed below the error threshold")
	}
}

func TestCircuitBreaker_FailsFastDuringCooldown(t *testing.T) {
	b := testBreaker()
	trip(b)

	if b.Allow() {
		t.Fatal("expected breaker to fail fast immediately after opening")
	}
}

func TestCircuitBreaker_HalfOpenTrialAfterCooldown(t *testing.T) {
	b := testBreaker()
	trip(b)

	time.Sleep(100 * time.Millisecond) // > cooldown (80ms)

	if !b.Allow() {
		t.Fatal("expected exactly one half-open trial to be allowed after cooldown")
	}
	if b.Allow() {
		t.Fatal("expected a second concurrent request to be rejected while a half-open trial is in flight")
	}
}

func TestCircuitBreaker_HalfOpenSuccessCloses(t *testing.T) {
	b := testBreaker()
	trip(b)
	time.Sleep(100 * time.Millisecond)

	if !b.Allow() {
		t.Fatal("expected the half-open trial to be allowed")
	}
	b.Record(true)

	if !b.Allow() {
		t.Fatal("expected breaker to be closed again after a successful half-open trial")
	}
}

func TestCircuitBreaker_HalfOpenFailureReopens(t *testing.T) {
	b := testBreaker()
	trip(b)
	time.Sleep(100 * time.Millisecond)

	if !b.Allow() {
		t.Fatal("expected the half-open trial to be allowed")
	}
	b.Record(false)

	if b.Allow() {
		t.Fatal("expected breaker to reopen immediately after a failed half-open trial")
	}
}

// trip forces the breaker open via a 100% error rate over minSamples requests.
func trip(b *CircuitBreaker) {
	for i := 0; i < b.minSamples; i++ {
		b.Allow()
		b.Record(false)
	}
}
