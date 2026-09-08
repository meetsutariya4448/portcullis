package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore reads verdicts from, and enqueues scans into, the database
// the Python control plane writes. See control/migrations/001_admission.sql.
//
// Adding a database driver to the data plane is a deliberate departure from
// the gateway's stdlib-only posture (CLAUDE.md). The alternative -- an HTTP
// hop to the control plane on the request path -- would put a Python
// process's availability and latency in front of every proxied call, which
// is exactly what this design exists to avoid. A pooled, indexed,
// primary-key SELECT behind a TTL cache is the cheaper dependency.
type PostgresStore struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

// NewPostgresStore connects to databaseURL and verifies the connection.
//
// Fails fast rather than lazily: a gateway configured to enforce verdicts
// but unable to reach the verdict store is misconfigured, and finding that
// out at startup is much better than discovering it as a stream of
// fail-open decisions under load.
func NewPostgresStore(ctx context.Context, databaseURL string, log *slog.Logger) (*PostgresStore, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("admission: parsing database_url: %w", err)
	}
	// The request path holds a connection only for a single indexed lookup,
	// and misses are absorbed by the cache, so a small pool is ample.
	cfg.MaxConns = 8
	cfg.MinConns = 1
	cfg.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("admission: connecting to the verdict store: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("admission: verdict store unreachable: %w", err)
	}
	return &PostgresStore{pool: pool, log: log}, nil
}

// Close releases the connection pool.
func (s *PostgresStore) Close() { s.pool.Close() }

const verdictQuery = `
SELECT verdict, COALESCE(attack_class, ''), COALESCE(confidence, 0),
       COALESCE(evidence_span, ''), COALESCE(produced_by, ''),
       scanner_fingerprint, scanned_at
  FROM tool_verdicts
 WHERE namespace = $1 AND tool_name = $2 AND content_hash = $3`

func (s *PostgresStore) Verdict(ctx context.Context, namespace, toolName, contentHash string) (Record, bool, error) {
	row := s.pool.QueryRow(ctx, verdictQuery, namespace, toolName, contentHash)

	record := Record{Namespace: namespace, ToolName: toolName, ContentHash: contentHash}
	var verdict string
	err := row.Scan(&verdict, &record.AttackClass, &record.Confidence,
		&record.EvidenceSpan, &record.ProducedBy, &record.ScannerFingerprint, &record.ScannedAt)
	if err != nil {
		if isNoRows(err) {
			// A miss is not an error: it means this exact definition has
			// not been scanned, which the policy has a defined answer for.
			return Record{}, false, nil
		}
		return Record{}, false, err
	}
	record.Verdict = Verdict(verdict)
	return record, true, nil
}

const enqueueScanStatement = `
INSERT INTO scan_queue (namespace, tool_name, content_hash, upstream_name,
                        tool_json_name, description, input_schema, canonical)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (namespace, tool_name, content_hash) DO NOTHING`

func (s *PostgresStore) EnqueueScan(ctx context.Context, entry CatalogEntry) error {
	schema := entry.InputSchema
	if len(schema) == 0 {
		schema = json.RawMessage("{}")
	}
	// ON CONFLICT DO NOTHING supplies the idempotency the interface
	// requires: the discoverer re-offers every unscanned definition on
	// every refresh, and that must stay free.
	_, err := s.pool.Exec(ctx, enqueueScanStatement,
		entry.Namespace, entry.ToolName, entry.ContentHash, entry.UpstreamName,
		entry.ToolName, entry.Description, string(schema), string(entry.Canonical))
	return err
}

func isNoRows(err error) bool {
	return err != nil && err.Error() == "no rows in result set"
}

// --- decision log -----------------------------------------------------------

// PostgresDecisionSink persists admission decisions asynchronously.
//
// Asynchronous on purpose: an audit write must never add latency to a
// proxied request, and must never be able to fail one. The cost is that a
// crash can lose the tail of the buffer, which is the right trade for an
// audit log of a gate whose decisions are also in the structured request
// log. When the buffer is full, decisions are dropped and counted rather
// than blocking the request path -- backpressure from an audit sink is not
// a reason to stop serving traffic.
type PostgresDecisionSink struct {
	pool    *pgxpool.Pool
	log     *slog.Logger
	entries chan decisionRow
	done    chan struct{}
	dropped uint64
}

type decisionRow struct {
	clientID string
	point    Point
	entry    CatalogEntry
	decision Decision
}

// NewPostgresDecisionSink starts the background writer. Stop it with Close.
func NewPostgresDecisionSink(store *PostgresStore, log *slog.Logger, bufferSize int) *PostgresDecisionSink {
	if bufferSize <= 0 {
		bufferSize = 2048
	}
	sink := &PostgresDecisionSink{
		pool:    store.pool,
		log:     log,
		entries: make(chan decisionRow, bufferSize),
		done:    make(chan struct{}),
	}
	go sink.run()
	return sink
}

func (s *PostgresDecisionSink) Record(clientID string, point Point, entry CatalogEntry, decision Decision) {
	select {
	case s.entries <- decisionRow{clientID: clientID, point: point, entry: entry, decision: decision}:
	default:
		s.dropped++
		if s.dropped%1000 == 1 {
			s.log.Warn("admission: decision log buffer full, dropping audit rows",
				"dropped_total", s.dropped)
		}
	}
}

const insertDecisionStatement = `
INSERT INTO decision_log (client_id, enforcement_point, namespace, tool_name,
                          content_hash, decision, reason, verdict, attack_class,
                          produced_by, scanner_fingerprint, stale)
VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), NULLIF($9, ''), NULLIF($10, ''), $11, $12)`

func (s *PostgresDecisionSink) run() {
	defer close(s.done)
	for row := range s.entries {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := s.pool.Exec(ctx, insertDecisionStatement,
			row.clientID, string(row.point), row.entry.Namespace, row.entry.ToolName,
			row.decision.ContentHash, string(row.decision.Outcome), string(row.decision.Reason),
			string(row.decision.Verdict), row.decision.AttackClass, row.decision.ProducedBy,
			row.decision.ScannerFingerprint, row.decision.Stale)
		cancel()
		if err != nil {
			s.log.Error("admission: failed to persist a decision-log row", "error", err)
		}
	}
}

// Close stops the writer and waits for the buffer to drain.
func (s *PostgresDecisionSink) Close() {
	close(s.entries)
	<-s.done
}
