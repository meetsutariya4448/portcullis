package admission

import (
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// Record is a stored verdict about one exact tool definition.
//
// Rows are keyed by content hash and never updated in place, so the verdict
// history for a tool is the set of rows sharing its (namespace, tool_name).
// That is what makes "this description was cleared, then the server changed
// it" a fact you can read out of the store rather than an event you had to
// have been watching for.
type Record struct {
	Namespace          string
	ToolName           string
	ContentHash        string
	Verdict            Verdict
	AttackClass        string
	Confidence         float64
	EvidenceSpan       string
	ProducedBy         string
	ScannerFingerprint string
	ScannedAt          time.Time
}

// CatalogEntry is one tool as the gateway currently understands it: the
// definition an upstream most recently advertised, plus the hash that
// verdicts for it are keyed by.
type CatalogEntry struct {
	Namespace    string
	ToolName     string
	UpstreamName string
	// QualifiedName is "{namespace}.{tool}" -- the name a client uses.
	QualifiedName string
	Description   string
	InputSchema   json.RawMessage
	ContentHash   string
	// Canonical is the exact byte sequence the hash was taken over. Shipped
	// verbatim to the scan queue so the control plane verifies rather than
	// re-derives it (see hash.go).
	Canonical []byte
	FirstSeen time.Time
	LastSeen  time.Time
}

// Catalog holds the tools discovered from upstream listings.
//
// Population is deliberately out-of-band: a background discoverer refreshes
// it, and the request path only reads. That is what keeps admission a map
// lookup instead of an upstream round trip, and it is why a tools/call --
// whose request body carries no description at all (SPEC-NOTES.md §3) --
// can be judged on the tool's actual text.
type Catalog struct {
	mu sync.RWMutex
	// byQualifiedName is the request-path index: "{namespace}.{tool}".
	byQualifiedName map[string]CatalogEntry
	// byNamespace preserves per-upstream grouping for building listings.
	byNamespace map[string][]string
	updatedAt   time.Time
}

func NewCatalog() *Catalog {
	return &Catalog{
		byQualifiedName: make(map[string]CatalogEntry),
		byNamespace:     make(map[string][]string),
	}
}

// Lookup returns the current entry for a qualified tool name.
func (c *Catalog) Lookup(qualifiedName string) (CatalogEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.byQualifiedName[qualifiedName]
	return entry, ok
}

// ReplaceNamespace swaps in the full set of tools for one namespace,
// returning the entries whose content hash is new or changed since the last
// refresh.
//
// Replacing wholesale (rather than merging) is what makes a tool
// *disappearing* from an upstream listing take effect: a stale entry left
// behind would keep answering calls for a tool the upstream no longer
// offers. The returned changed set is what gets queued for scanning -- a
// changed hash on an existing tool is the rug-pull signal.
func (c *Catalog) ReplaceNamespace(namespace string, entries []CatalogEntry) (changed []CatalogEntry) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	previous := make(map[string]CatalogEntry, len(c.byNamespace[namespace]))
	for _, name := range c.byNamespace[namespace] {
		previous[name] = c.byQualifiedName[name]
		delete(c.byQualifiedName, name)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		entry.LastSeen = now
		entry.FirstSeen = now
		if prior, ok := previous[entry.QualifiedName]; ok {
			if prior.ContentHash == entry.ContentHash {
				// Same definition: keep the original first-seen so the
				// store can tell how long this exact text has been served.
				entry.FirstSeen = prior.FirstSeen
			} else {
				changed = append(changed, entry)
			}
		} else {
			changed = append(changed, entry)
		}
		c.byQualifiedName[entry.QualifiedName] = entry
		names = append(names, entry.QualifiedName)
	}
	sort.Strings(names)
	c.byNamespace[namespace] = names
	c.updatedAt = now
	return changed
}

// Entries returns every catalog entry, ordered by qualified name so a
// listing built from it is stable between calls.
func (c *Catalog) Entries() []CatalogEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]CatalogEntry, 0, len(c.byQualifiedName))
	for _, entry := range c.byQualifiedName {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].QualifiedName < out[j].QualifiedName })
	return out
}

// Len reports how many tools are currently known.
func (c *Catalog) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.byQualifiedName)
}

// UpdatedAt reports when the catalog last changed, for staleness reporting.
func (c *Catalog) UpdatedAt() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.updatedAt
}
