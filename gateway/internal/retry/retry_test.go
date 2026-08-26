package retry

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var errBoom = errors.New("boom")

func fastConfig() Config {
	return Config{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}
}

func TestDo_SucceedsFirstAttempt_NoRetry(t *testing.T) {
	calls := 0
	err := Do(context.Background(), fastConfig(), func(attempt int) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected exactly 1 call, got %d", calls)
	}
}

func TestDo_RetriesBareErrorsUntilSuccess(t *testing.T) {
	calls := 0
	err := Do(context.Background(), fastConfig(), func(attempt int) error {
		calls++
		if attempt < 3 {
			return errBoom
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls (2 failures + 1 success), got %d", calls)
	}
}

func TestDo_ExhaustsAttemptsAndReturnsLastError(t *testing.T) {
	calls := 0
	err := Do(context.Background(), fastConfig(), func(attempt int) error {
		calls++
		return errBoom
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected errBoom, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected exactly MaxAttempts=3 calls, got %d", calls)
	}
}

func TestDo_NonRetryableStopsImmediately(t *testing.T) {
	calls := 0
	err := Do(context.Background(), fastConfig(), func(attempt int) error {
		calls++
		return NonRetryable(errBoom)
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected errBoom (unwrapped), got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected exactly 1 call for a non-retryable error, got %d", calls)
	}
}

func TestDo_SkipTargetStopsImmediately(t *testing.T) {
	calls := 0
	err := Do(context.Background(), fastConfig(), func(attempt int) error {
		calls++
		return SkipTarget(errBoom)
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected errBoom (unwrapped via errors.Is), got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected exactly 1 call for a SkipTarget error, got %d", calls)
	}
}

func TestSafeToRetryElsewhere(t *testing.T) {
	if !SafeToRetryElsewhere(errBoom) {
		t.Error("expected a bare error to be safe to retry elsewhere")
	}
	if !SafeToRetryElsewhere(SkipTarget(errBoom)) {
		t.Error("expected a SkipTarget error to be safe to retry elsewhere")
	}
	if SafeToRetryElsewhere(NonRetryable(errBoom)) {
		t.Error("expected a NonRetryable error to NOT be safe to retry elsewhere")
	}
}

// TestSafeToRetryElsewhere_SeesThroughDosReturnValue proves the property
// SafeToRetryElsewhere actually needs to hold: after a NonRetryable
// failure propagates all the way through Do, the wrapper survives (Do no
// longer manually unwraps it) so a failover caller can still classify it
// correctly, while errors.Is against the original cause keeps working
// for everyone else.
func TestSafeToRetryElsewhere_SeesThroughDosReturnValue(t *testing.T) {
	err := Do(context.Background(), fastConfig(), func(attempt int) error {
		return NonRetryable(errBoom)
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected errors.Is to still see errBoom through Do's return value, got %v", err)
	}
	if SafeToRetryElsewhere(err) {
		t.Fatal("expected Do's returned NonRetryable error to still read as unsafe elsewhere")
	}

	skipErr := Do(context.Background(), fastConfig(), func(attempt int) error {
		return SkipTarget(errBoom)
	})
	if !SafeToRetryElsewhere(skipErr) {
		t.Fatal("expected Do's returned SkipTarget error to still read as safe elsewhere")
	}
}

func TestDo_MaxAttemptsOneNeverRetries(t *testing.T) {
	calls := 0
	err := Do(context.Background(), Config{MaxAttempts: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}, func(attempt int) error {
		calls++
		return errBoom
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected errBoom, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected exactly 1 call with MaxAttempts=1, got %d", calls)
	}
}

func TestDo_ZeroConfigUsesDefaults(t *testing.T) {
	calls := 0
	err := Do(context.Background(), Config{}, func(attempt int) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
}

func TestDo_RespectsContextCancellationDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	cfg := Config{MaxAttempts: 5, BaseDelay: 50 * time.Millisecond, MaxDelay: 50 * time.Millisecond}

	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	err := Do(ctx, cfg, func(attempt int) error {
		calls++
		return errBoom
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if calls >= 5 {
		t.Fatalf("expected cancellation to cut the retry loop short, got %d calls", calls)
	}
}

func TestBackoffDelay_NeverExceedsMaxDelay(t *testing.T) {
	base := time.Millisecond
	maxDelay := 10 * time.Millisecond
	for attempt := 1; attempt <= 20; attempt++ {
		for i := 0; i < 50; i++ { // jitter is random; sample repeatedly
			d := backoffDelay(base, maxDelay, attempt)
			if d > maxDelay {
				t.Fatalf("attempt %d: backoffDelay returned %v > maxDelay %v", attempt, d, maxDelay)
			}
			if d < 0 {
				t.Fatalf("attempt %d: backoffDelay returned negative duration %v", attempt, d)
			}
		}
	}
}

func TestDialProbe_SuccessfulDialSetsFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dialer := &net.Dialer{}
	transport := &http.Transport{DialContext: ProbeDialContext(dialer.DialContext)}
	client := &http.Client{Transport: transport}

	ctx, connEstablished := WithConnProbe(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if !connEstablished() {
		t.Fatal("expected connEstablished() to be true after a successful round trip")
	}
}

func TestDialProbe_FailedDialLeavesFlagFalse(t *testing.T) {
	dialer := &net.Dialer{Timeout: 50 * time.Millisecond}
	transport := &http.Transport{DialContext: ProbeDialContext(dialer.DialContext)}
	client := &http.Client{Transport: transport, Timeout: time.Second}

	ctx, connEstablished := WithConnProbe(context.Background())
	// Port 0 on localhost should refuse the connection immediately.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}

	_, err = client.Do(req)
	if err == nil {
		t.Fatal("expected the request to fail to connect")
	}
	if connEstablished() {
		t.Fatal("expected connEstablished() to stay false after a dial failure")
	}
}

func TestDialProbe_NoProbeContextIsANoop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dialer := &net.Dialer{}
	transport := &http.Transport{DialContext: ProbeDialContext(dialer.DialContext)}
	client := &http.Client{Transport: transport}

	// No WithConnProbe on this context -- ProbeDialContext must not panic
	// or otherwise misbehave when there's nothing to record into.
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
}
