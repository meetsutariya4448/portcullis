package translate

import "errors"

var (
	// ErrCircuitOpen is returned by Pool.Forward when the upstream's
	// circuit breaker has tripped and is fast-failing requests.
	ErrCircuitOpen = errors.New("translate: circuit breaker open for upstream")

	// ErrPoolExhausted is returned by Pool.Forward when the session pool is
	// already at its bound and has no idle session to reuse.
	ErrPoolExhausted = errors.New("translate: legacy session pool exhausted")

	// ErrUnsupportedMRTR is returned by Pool.Forward when the legacy
	// upstream responds with what looks like a server-initiated request
	// (sampling/createMessage, elicitation/create, roots/list) rather than
	// an ordinary result. Bridging that into a 2026-07-28
	// InputRequiredResult is out of scope: SPEC-NOTES.md's "Translating"
	// section (item 9) documents why that bridge is effectively impossible
	// to do statelessly, and it was explicitly descoped for this pass.
	ErrUnsupportedMRTR = errors.New("translate: legacy upstream requires a multi-round-trip flow this gateway does not bridge")
)
