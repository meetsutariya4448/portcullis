package admission

import (
	"context"
	"errors"
	"sync"
)

// MemoryStore is an in-memory VerdictStore.
//
// It exists for tests and for a single-instance deployment that has no
// Postgres yet -- verdicts seeded at startup still enforce. It is not a
// substitute for the real store: nothing persists across a restart and
// nothing is shared between gateway instances, so a scan performed by the
// control plane never reaches it.
type MemoryStore struct {
	mu       sync.RWMutex
	verdicts map[string]Record
	queued   []CatalogEntry
	// failWith, when set, makes every Verdict call return it. Lets a test
	// exercise the store-unavailable path without a real outage.
	failWith error
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{verdicts: make(map[string]Record)}
}

// Put stores a verdict.
func (s *MemoryStore) Put(record Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verdicts[cacheKey(record.Namespace, record.ToolName, record.ContentHash)] = record
}

// SetFailure makes subsequent lookups fail with err (nil to restore).
func (s *MemoryStore) SetFailure(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWith = err
}

func (s *MemoryStore) Verdict(_ context.Context, namespace, toolName, contentHash string) (Record, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.failWith != nil {
		return Record{}, false, s.failWith
	}
	record, ok := s.verdicts[cacheKey(namespace, toolName, contentHash)]
	return record, ok, nil
}

func (s *MemoryStore) EnqueueScan(_ context.Context, entry CatalogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, queued := range s.queued {
		if queued.Namespace == entry.Namespace &&
			queued.ToolName == entry.ToolName &&
			queued.ContentHash == entry.ContentHash {
			return nil // idempotent, as the interface requires
		}
	}
	s.queued = append(s.queued, entry)
	return nil
}

// Queued returns the scan queue's contents, for assertions.
func (s *MemoryStore) Queued() []CatalogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CatalogEntry, len(s.queued))
	copy(out, s.queued)
	return out
}

// ErrStoreUnavailable is a convenient failure for SetFailure.
var ErrStoreUnavailable = errors.New("admission: verdict store unavailable")
