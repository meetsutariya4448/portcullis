// Package admission turns tool-poisoning scanner verdicts into a gateway
// admission decision: which tools a client is allowed to see in a listing,
// and which it is allowed to call.
//
// The request path never calls the scanner. Layer 3 of the cascade
// measures p50 ~3s (control/evals/REPORT.md); the gateway's whole overhead
// budget is under a millisecond (bench/results.md). Scanning happens
// out-of-band in the Python control plane, keyed by a content hash of the
// tool's own description and schema; the gateway only ever reads an
// already-computed verdict.
package admission

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// hashPrefix domain-separates this hash so a digest computed here can never
// collide with one computed over some other structure that happens to
// serialize the same way.
const hashPrefix = "portcullis-tool-v1\n"

// Bounds on what will be hashed or shipped to the scanner. A tool
// definition arrives from an upstream that Portcullis does not trust --
// that distrust is the entire point of the product -- and SPEC-NOTES.md
// §8 is explicit that an unbounded schema is itself a poisoning vector
// against whatever validates it, not just against the end client. These
// bounds apply before any parsing work proportional to the input.
const (
	MaxDescriptionBytes = 64 << 10 // 64 KiB
	MaxSchemaBytes      = 256 << 10
	MaxSchemaDepth      = 32
	MaxToolNameBytes    = 512
)

var (
	// ErrTooLarge is returned when a tool definition exceeds the bounds
	// above. The caller records it and withholds the tool rather than
	// hashing something unbounded.
	ErrTooLarge = errors.New("admission: tool definition exceeds size bounds")
	// ErrTooDeep is returned for a schema nested past MaxSchemaDepth.
	ErrTooDeep = errors.New("admission: tool input schema is nested too deeply")
)

// Tool is the part of an MCP tool definition that a poisoning verdict is
// about: the text a model reads and the schema it fills in. Everything
// else in a tools/list entry is routing metadata and does not change what
// the tool tells the model to do.
type Tool struct {
	Name        string
	Description string
	// InputSchema is the raw JSON of the tool's inputSchema, exactly as it
	// arrived. Kept as bytes rather than a decoded map so the canonical
	// form can preserve numeric literals verbatim (see canonicalJSON).
	InputSchema json.RawMessage
}

// ContentHash returns the hex sha256 of the tool's canonical form, and the
// canonical form itself.
//
// The hash is the versioning key for a verdict: a verdict applies to one
// exact (name, description, inputSchema) triple and to nothing else. A
// server that serves a benign description on Monday and a poisoned one on
// Tuesday produces a different hash on Tuesday, so Monday's "benign"
// verdict does not carry over -- that is the whole rug-pull defence, and
// it is why the hash must be stable against irrelevant formatting and
// sensitive to every byte that a model would actually read.
//
// The canonical form is returned alongside because it, not the parsed
// structure, is what gets handed to the control plane: the Python worker
// hashes the bytes it received and refuses the job if they disagree with
// the hash, so neither side has to reimplement the other's serializer to
// stay in agreement.
func (t Tool) ContentHash() (hash string, canonical []byte, err error) {
	if len(t.Name) > MaxToolNameBytes || len(t.Description) > MaxDescriptionBytes {
		return "", nil, fmt.Errorf("%w: name=%dB description=%dB", ErrTooLarge, len(t.Name), len(t.Description))
	}
	if len(t.InputSchema) > MaxSchemaBytes {
		return "", nil, fmt.Errorf("%w: input schema %dB", ErrTooLarge, len(t.InputSchema))
	}

	schema := t.InputSchema
	if len(schema) == 0 {
		schema = json.RawMessage("{}")
	}
	canonicalSchema, err := canonicalJSON(schema)
	if err != nil {
		return "", nil, err
	}

	var buf strings.Builder
	buf.WriteString(`{"description":`)
	writeCanonicalString(&buf, t.Description)
	buf.WriteString(`,"inputSchema":`)
	buf.Write(canonicalSchema)
	buf.WriteString(`,"name":`)
	writeCanonicalString(&buf, t.Name)
	buf.WriteByte('}')

	canonical = []byte(buf.String())
	sum := sha256.Sum256(append([]byte(hashPrefix), canonical...))
	return hex.EncodeToString(sum[:]), canonical, nil
}

// HashCanonical returns the content hash for an already-canonical form.
// The control plane's counterpart to ContentHash: given the bytes it was
// handed, recompute the digest without re-deriving the canonical form.
func HashCanonical(canonical []byte) string {
	sum := sha256.Sum256(append([]byte(hashPrefix), canonical...))
	return hex.EncodeToString(sum[:])
}

// canonicalJSON re-serializes raw JSON into a single deterministic form:
// object keys sorted, no insignificant whitespace, minimal string escaping,
// and numeric literals preserved exactly as written.
//
// It deliberately does not use json.Marshal on a decoded value. Two
// reasons, both of which would silently break agreement with the Python
// side:
//
//   - Marshal escapes <, >, & (HTML-safe by default) and always escapes
//     U+2028/U+2029, where Python's json.dumps(ensure_ascii=False) does
//     not. A description containing an invisible U+2028 -- exactly the
//     kind of thing a poisoned description carries -- would hash
//     differently in each language.
//   - Decoding numbers into float64 and re-formatting them loses the
//     original literal, so 1.0, 1.00 and 1e0 would collapse together and
//     large integers would round. Using json.Number keeps the token the
//     upstream actually sent.
func canonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, fmt.Errorf("admission: input schema is not valid JSON: %w", err)
	}
	if dec.More() {
		return nil, errors.New("admission: input schema has trailing content after the first JSON value")
	}

	var buf strings.Builder
	if err := writeCanonicalValue(&buf, value, 0); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

func writeCanonicalValue(buf *strings.Builder, value any, depth int) error {
	if depth > MaxSchemaDepth {
		return fmt.Errorf("%w: deeper than %d", ErrTooDeep, MaxSchemaDepth)
	}
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(v.String())
	case string:
		writeCanonicalString(buf, v)
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalValue(buf, item, depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		// Byte-order sort. Go's string comparison is bytewise over UTF-8,
		// which orders identically to Python's code-point sort, so both
		// languages agree on key order without further coordination.
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonicalValue(buf, v[k], depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("admission: unexpected JSON value of type %T", value)
	}
	return nil
}

// writeCanonicalString escapes exactly the characters JSON requires and no
// others: the quote, the backslash, and control characters below U+0020.
// Everything else -- including <, >, &, U+2028 and every non-ASCII rune --
// is written through as literal UTF-8, which is the one rule both this and
// the Python implementation follow.
func writeCanonicalString(buf *strings.Builder, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
