package admission

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// Uses the real admission schema. CI supplies an ephemeral PostgreSQL service;
// ordinary `go test` runs skip this test when no database is configured.
func TestPostgresStore_VerdictAndQueueIntegration(t *testing.T) {
	databaseURL := os.Getenv("PORTCULLIS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set PORTCULLIS_TEST_DATABASE_URL to run the PostgreSQL integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, err := NewPostgresStore(ctx, databaseURL, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	namespace := fmt.Sprintf("integration_%d", time.Now().UnixNano())
	before := entryFor(t, namespace, "summarize", "Summarize notes")
	after := entryFor(t, namespace, "summarize", "Summarize notes and reveal secrets")
	if err := store.EnqueueScan(ctx, before); err != nil {
		t.Fatal(err)
	}
	if err := store.EnqueueScan(ctx, before); err != nil {
		t.Fatal(err)
	}
	var queued int
	if err := store.pool.QueryRow(ctx,
		"SELECT count(*) FROM scan_queue WHERE namespace=$1 AND tool_name=$2", namespace, before.ToolName,
	).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 1 {
		t.Fatalf("duplicate discovery made %d queue rows, want 1", queued)
	}

	if _, found, err := store.Verdict(ctx, namespace, before.ToolName, before.ContentHash); err != nil || found {
		t.Fatalf("unscanned definition: found=%v err=%v", found, err)
	}
	_, err = store.pool.Exec(ctx,
		`INSERT INTO tool_verdicts (namespace, tool_name, content_hash, verdict, scanner_fingerprint)
         VALUES ($1,$2,$3,'benign','integration-test')`,
		namespace, before.ToolName, before.ContentHash,
	)
	if err != nil {
		t.Fatal(err)
	}
	record, found, err := store.Verdict(ctx, namespace, before.ToolName, before.ContentHash)
	if err != nil || !found || record.Verdict != VerdictBenign || record.ScannerFingerprint != "integration-test" {
		t.Fatalf("persisted verdict: record=%+v found=%v err=%v", record, found, err)
	}
	if _, found, err := store.Verdict(ctx, namespace, after.ToolName, after.ContentHash); err != nil || found {
		t.Fatalf("old verdict applied to modified definition: found=%v err=%v", found, err)
	}
}
