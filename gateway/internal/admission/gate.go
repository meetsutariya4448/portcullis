package admission

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// VerdictStore is the gateway's read side of the verdict store. Implemented
// over Postgres in store_pg.go; the in-memory implementation in
// store_mem.go backs the tests.
//
// Deliberately read-only plus an enqueue: the data plane never scans, never
// writes a verdict, and never calls the control plane synchronously.
type VerdictStore interface {
	// Verdict returns the stored verdict for one exact tool definition.
	// A miss is (Record{}, false, nil) -- not an error.
	Verdict(ctx context.Context, namespace, toolName, contentHash string) (Record, bool, error)
	// EnqueueScan records that a tool definition needs scanning. Must be
	// idempotent on (namespace, tool, hash): the discoverer will re-offer
	// the same entry on every refresh until a verdict exists.
	EnqueueScan(ctx context.Context, entry CatalogEntry) error
}

// DecisionSink receives every admission decision for audit. Implemented
// over Postgres; nil disables persistent decision logging (the structured
// slog line is emitted either way).
type DecisionSink interface {
	Record(clientID string, point Point, entry CatalogEntry, decision Decision)
}

// Gate is the request-path entry point: catalog lookup, verdict lookup,
// policy evaluation. No network call, no model call.
type Gate struct {
	catalog *Catalog
	store   VerdictStore
	policy  Policy
	log     *slog.Logger
	sink    DecisionSink

	cache *verdictCache

	// lookupTimeout bounds the verdict lookup so a wedged database cannot
	// hold a request open. On expiry the request takes the unavailable
	// path, which is a decision, not a hang.
	lookupTimeout time.Duration
}

// GateOptions configures a Gate.
type GateOptions struct {
	Catalog       *Catalog
	Store         VerdictStore
	Policy        Policy
	Log           *slog.Logger
	Sink          DecisionSink
	CacheTTL      time.Duration
	CacheMaxSize  int
	LookupTimeout time.Duration
}

const (
	defaultCacheTTL      = 30 * time.Second
	defaultCacheMaxSize  = 8192
	defaultLookupTimeout = 250 * time.Millisecond
)

func NewGate(opts GateOptions) *Gate {
	if opts.CacheTTL <= 0 {
		opts.CacheTTL = defaultCacheTTL
	}
	if opts.CacheMaxSize <= 0 {
		opts.CacheMaxSize = defaultCacheMaxSize
	}
	if opts.LookupTimeout <= 0 {
		opts.LookupTimeout = defaultLookupTimeout
	}
	if opts.Catalog == nil {
		opts.Catalog = NewCatalog()
	}
	return &Gate{
		catalog:       opts.Catalog,
		store:         opts.Store,
		policy:        NewPolicy(opts.Policy),
		log:           opts.Log,
		sink:          opts.Sink,
		cache:         newVerdictCache(opts.CacheMaxSize, opts.CacheTTL),
		lookupTimeout: opts.LookupTimeout,
	}
}

// Catalog exposes the gate's catalog so the discoverer can refresh it and
// the listing path can enumerate it.
func (g *Gate) Catalog() *Catalog { return g.catalog }

// Policy exposes the resolved policy, for startup logging.
func (g *Gate) Policy() Policy { return g.policy }

// AdmitCall decides whether clientID may call qualifiedName.
func (g *Gate) AdmitCall(ctx context.Context, clientID, qualifiedName string) Decision {
	entry, lookup := g.lookup(ctx, qualifiedName)
	decision := g.policy.Decide(PointCall, lookup)
	g.record(clientID, PointCall, entry, decision)
	return decision
}

// AdmitListing filters entries down to those a client may be shown,
// returning the survivors and the decisions for everything considered.
//
// Withheld tools are dropped silently from the client's perspective: a
// listing that named the tools it was hiding would hand the model the
// pointer it was denied. The decision log is where the withholding is
// visible.
func (g *Gate) AdmitListing(ctx context.Context, clientID string, entries []CatalogEntry) (allowed []CatalogEntry, decisions []Decision) {
	allowed = make([]CatalogEntry, 0, len(entries))
	decisions = make([]Decision, 0, len(entries))
	for _, entry := range entries {
		lookup := g.lookupEntry(ctx, entry)
		decision := g.policy.Decide(PointList, lookup)
		g.record(clientID, PointList, entry, decision)
		decisions = append(decisions, decision)
		if !decision.Denied() {
			allowed = append(allowed, entry)
		}
	}
	return allowed, decisions
}

func (g *Gate) lookup(ctx context.Context, qualifiedName string) (CatalogEntry, Lookup) {
	entry, ok := g.catalog.Lookup(qualifiedName)
	if !ok {
		return CatalogEntry{QualifiedName: qualifiedName}, Lookup{Discovered: false}
	}
	return entry, g.lookupEntry(ctx, entry)
}

func (g *Gate) lookupEntry(ctx context.Context, entry CatalogEntry) Lookup {
	l := Lookup{Discovered: true, ContentHash: entry.ContentHash}

	key := cacheKey(entry.Namespace, entry.ToolName, entry.ContentHash)
	if cached, ok := g.cache.get(key); ok {
		l.Found = cached.found
		l.Record = cached.record
		return l
	}

	if g.store == nil {
		l.Unavailable = true
		return l
	}

	lookupCtx, cancel := context.WithTimeout(ctx, g.lookupTimeout)
	defer cancel()

	record, found, err := g.store.Verdict(lookupCtx, entry.Namespace, entry.ToolName, entry.ContentHash)
	if err != nil {
		// Fall back to the last answer we had for this exact definition,
		// even if its TTL has lapsed: a stale verdict about the right bytes
		// is strictly better than no verdict, and the staleness is surfaced
		// rather than hidden.
		if stale, ok := g.cache.getStale(key); ok {
			l.Found = stale.found
			l.Record = stale.record
			l.Stale = true
			l.Unavailable = true
			return l
		}
		l.Unavailable = true
		return l
	}

	g.cache.put(key, cachedVerdict{found: found, record: record})
	l.Found = found
	l.Record = record
	return l
}

// EnqueueScans queues the given entries for the control plane to scan.
// Called by the discoverer, off the request path; failures are logged, not
// returned, because a queue write failing must not stop discovery.
func (g *Gate) EnqueueScans(ctx context.Context, entries []CatalogEntry) {
	if g.store == nil {
		return
	}
	for _, entry := range entries {
		if err := g.store.EnqueueScan(ctx, entry); err != nil && g.log != nil {
			g.log.Error("admission: failed to enqueue a tool for scanning",
				"namespace", entry.Namespace, "tool", entry.ToolName,
				"content_hash", entry.ContentHash, "error", err)
		}
	}
}

// InvalidateCache drops cached verdicts. Called after a discovery refresh
// so a verdict that landed while an entry was cached takes effect promptly
// rather than at TTL expiry.
func (g *Gate) InvalidateCache() { g.cache.clear() }

// record emits the structured decision log and, when configured, persists
// the decision.
//
// Denials log at warn with the full evidence -- which tool, which exact
// content hash, which verdict, which attack class, and which scanner
// configuration produced it -- because "the gateway blocked something" is
// the line an operator will actually have to act on. Allows are not logged
// individually; they are counted in metrics and persisted to the sink,
// which keeps a busy gateway's logs readable.
func (g *Gate) record(clientID string, point Point, entry CatalogEntry, decision Decision) {
	if g.sink != nil {
		g.sink.Record(clientID, point, entry, decision)
	}
	if g.log == nil {
		return
	}

	args := []any{
		"decision", string(decision.Outcome),
		"reason", string(decision.Reason),
		"point", string(point),
		"client", clientID,
		"tool", entry.QualifiedName,
		"namespace", entry.Namespace,
		"content_hash", decision.ContentHash,
	}
	if decision.Verdict != "" {
		args = append(args, "verdict", string(decision.Verdict))
	}
	if decision.AttackClass != "" {
		args = append(args, "attack_class", decision.AttackClass)
	}
	if decision.ProducedBy != "" {
		args = append(args, "produced_by", decision.ProducedBy)
	}
	if decision.ScannerFingerprint != "" {
		args = append(args, "scanner_fingerprint", decision.ScannerFingerprint)
	}
	if decision.Stale {
		args = append(args, "stale", true)
	}

	switch {
	case decision.Reason == ReasonUnavailable:
		// Not a denial, but the security control is not functioning. That
		// is an operational event and belongs at error level.
		g.log.Error("admission: verdict unavailable, applied the configured fallback", args...)
	case decision.Denied():
		g.log.Warn("admission: tool withheld", args...)
	case decision.Reason == ReasonUnknownHash || decision.Reason == ReasonUndiscovered:
		g.log.Warn("admission: allowed a tool with no verdict for its current definition", args...)
	}
}

// --- verdict cache ----------------------------------------------------------

type cachedVerdict struct {
	found  bool
	record Record
}

type cacheEntry struct {
	value     cachedVerdict
	expiresAt time.Time
}

// verdictCache is a bounded TTL cache keyed by (namespace, tool, hash).
//
// Bounded, unlike quota.Tracker's unbounded per-client map, because these
// keys come from upstream servers rather than from a fixed config-derived
// client list: an upstream that mutates a description on every refresh
// would otherwise grow this map without limit. Eviction is a random-ish
// sweep rather than true LRU -- a verdict is cheap to re-fetch, so the
// bound matters and the recency ordering does not.
type verdictCache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	maxSize int
	ttl     time.Duration
}

func newVerdictCache(maxSize int, ttl time.Duration) *verdictCache {
	return &verdictCache{entries: make(map[string]cacheEntry), maxSize: maxSize, ttl: ttl}
}

func cacheKey(namespace, tool, hash string) string {
	return namespace + "\x00" + tool + "\x00" + hash
}

func (c *verdictCache) get(key string) (cachedVerdict, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return cachedVerdict{}, false
	}
	return entry.value, true
}

// getStale returns a cached value regardless of expiry, for the
// store-unavailable fallback.
func (c *verdictCache) getStale(key string) (cachedVerdict, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	return entry.value, ok
}

func (c *verdictCache) put(key string, value cachedVerdict) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxSize {
		c.evictLocked()
	}
	c.entries[key] = cacheEntry{value: value, expiresAt: time.Now().Add(c.ttl)}
}

// evictLocked drops expired entries, and if that frees nothing, a slice of
// arbitrary ones -- enough to keep the map under its bound.
func (c *verdictCache) evictLocked() {
	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
	if len(c.entries) < c.maxSize {
		return
	}
	target := c.maxSize / 4
	for key := range c.entries {
		if target <= 0 {
			return
		}
		delete(c.entries, key)
		target--
	}
}

func (c *verdictCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cacheEntry)
}

func (c *verdictCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
