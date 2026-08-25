package router

import (
	"context"
	"testing"
	"time"
)

func TestBulkhead_AllowsUpToSizeConcurrentHolders(t *testing.T) {
	b := newBulkhead(2)
	ctx := context.Background()

	if err := b.Acquire(ctx); err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	if err := b.Acquire(ctx); err != nil {
		t.Fatalf("acquire 2: %v", err)
	}

	acquired := make(chan struct{})
	go func() {
		_ = b.Acquire(context.Background())
		close(acquired)
	}()

	select {
	case <-acquired:
		t.Fatal("expected a 3rd acquire to block while the bulkhead is full")
	case <-time.After(50 * time.Millisecond):
	}

	b.Release()

	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("expected the 3rd acquire to unblock after a release")
	}
}

func TestBulkhead_AcquireRespectsContextCancellation(t *testing.T) {
	b := newBulkhead(1)
	if err := b.Acquire(context.Background()); err != nil {
		t.Fatalf("acquire: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err := b.Acquire(ctx)
	if err == nil {
		t.Fatal("expected acquire to fail once ctx is done")
	}
}

func TestBulkhead_ZeroSizeDefaultsToOne(t *testing.T) {
	b := newBulkhead(0)
	if cap(b) != 1 {
		t.Fatalf("expected zero size to default to capacity 1, got %d", cap(b))
	}
}
