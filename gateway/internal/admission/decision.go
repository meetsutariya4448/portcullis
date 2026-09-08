package admission

import "fmt"

// Verdict is what the scanner concluded about one exact tool definition.
// These are the four values control/scanner/cascade.py's CascadeVerdict can
// carry -- including layer3_failure, which README.md's summary omits but
// which a gateway must still have a defined behaviour for. Anything not
// listed here is treated as VerdictUnknown rather than silently allowed.
type Verdict string

const (
	VerdictBenign        Verdict = "benign"
	VerdictMalicious     Verdict = "malicious"
	VerdictUncertain     Verdict = "uncertain"
	VerdictLayer3Failure Verdict = "layer3_failure"
)

// Outcome is the binary result of an admission decision.
type Outcome string

const (
	Allow Outcome = "allow"
	Deny  Outcome = "deny"
)

// Point is where in the request path a decision is being made. The two
// differ because the risk differs: a listing puts the tool's description
// in front of the model (which IS the tool-poisoning attack), whereas a
// call names a tool the client already knows about.
type Point string

const (
	// PointList is building a tools/list response.
	PointList Point = "list"
	// PointCall is admitting a tools/call.
	PointCall Point = "call"
)

// Reason is a stable, low-cardinality label explaining a decision. It is
// safe as a Prometheus label value and is the primary field an operator
// greps the decision log for. Deliberately not derived from tool names,
// which are upstream-controlled and unbounded.
type Reason string

const (
	ReasonBenign       Reason = "benign"
	ReasonMalicious    Reason = "malicious"
	ReasonUncertain    Reason = "uncertain"
	ReasonScanFailed   Reason = "scan_failed"
	ReasonUnknownHash  Reason = "unknown_hash"
	ReasonUndiscovered Reason = "undiscovered"
	ReasonUnavailable  Reason = "unavailable"
)

// Decision is the result of evaluating one tool at one enforcement point.
type Decision struct {
	Outcome Outcome
	Reason  Reason
	// Verdict is the stored verdict this decision was based on, empty when
	// there wasn't one (unknown hash, undiscovered tool, store outage).
	Verdict Verdict
	// ContentHash identifies which exact tool definition was judged. Logged
	// on every decision so an operator can tie a denial back to the precise
	// description text that earned it.
	ContentHash string
	AttackClass string
	ProducedBy  string
	// ScannerFingerprint ties the verdict back to the eval run that
	// characterized the scanner's quality (control/evals/results/<fp>/), so
	// "why was this denied" and "how good is that judgement" are answerable
	// from the same record.
	ScannerFingerprint string
	// Stale is true when the decision came from a cached verdict because
	// the store could not be reached. The decision still stands; the flag
	// is what tells an operator the security control is degraded.
	Stale bool
}

// Denied reports whether the decision blocks the tool.
func (d Decision) Denied() bool { return d.Outcome == Deny }

// Policy maps verdicts to outcomes. The zero value is not usable; build one
// with NewPolicy so the defaults are applied.
//
// Only the genuinely contestable cases are configurable. `malicious` always
// denies and `benign` always allows -- an operator who wants to run in
// monitor mode turns the whole gate off rather than configuring it into
// something that reports enforcement it isn't doing.
type Policy struct {
	// OnUncertain covers both `uncertain` and `layer3_failure`: the scanner
	// looked and could not conclude. Defaults to Deny.
	OnUncertain Outcome
	// OnUnknown covers a tool whose current content hash has no verdict --
	// never scanned, or scanned under a description it has since changed.
	// Applies to tools/call only. Defaults to Allow.
	//
	// Allowing calls here is what keeps a fresh deployment usable before
	// the first scan lands, and what keeps a description change from
	// instantly breaking a working integration. The listing side is where
	// the bypass is closed: see Decide.
	OnUnknown Outcome
	// OnUnavailable covers the verdict store being unreachable with no
	// cached verdict to fall back on. Applies to tools/call only. Defaults
	// to Allow -- a database outage should not take the data plane down --
	// and every such decision is counted and logged at error level, because
	// "we are not enforcing right now" is an operational event, not a
	// routine one.
	OnUnavailable Outcome
}

// NewPolicy returns a Policy with any unset field filled from the defaults
// documented above.
func NewPolicy(p Policy) Policy {
	if p.OnUncertain == "" {
		p.OnUncertain = Deny
	}
	if p.OnUnknown == "" {
		p.OnUnknown = Allow
	}
	if p.OnUnavailable == "" {
		p.OnUnavailable = Allow
	}
	return p
}

// ValidateOutcome rejects an outcome string that is neither allow nor deny.
// Used by config validation so a typo in `on_uncertain: dney` fails at
// startup rather than silently falling back to a default the operator
// didn't choose.
func ValidateOutcome(field, value string) (Outcome, error) {
	switch Outcome(value) {
	case "":
		return "", nil
	case Allow:
		return Allow, nil
	case Deny:
		return Deny, nil
	default:
		return "", fmt.Errorf("%s must be %q or %q, got %q", field, Allow, Deny, value)
	}
}

// Lookup is what a Store returns for one tool: the verdict if it has one,
// plus whether the answer is authoritative.
type Lookup struct {
	// Found is true when a verdict exists for the tool's current content
	// hash.
	Found bool
	// Record is the stored verdict, valid only when Found.
	Record Record
	// ContentHash is the hash that was looked up, whether or not a verdict
	// was found -- it identifies the tool definition currently on offer.
	ContentHash string
	// Discovered is false when the gateway has never seen this tool in any
	// upstream listing, so there is not even a content hash to judge.
	Discovered bool
	// Unavailable is true when the verdict could not be determined because
	// the store errored. Stale may still carry a cached answer.
	Unavailable bool
	// Stale is true when Record came from cache during an outage.
	Stale bool
}

// Decide turns a Lookup into an admission Decision at one enforcement
// point.
//
// The asymmetry between the two points is the heart of the design. A
// listing hands the tool's description to the model, so a description the
// scanner has not cleared is withheld: that is what stops an upstream from
// mutating its description on every listing to keep the content hash
// perpetually new and thereby never being judged. A call names a tool the
// client already has, where blocking on an unproven verdict mostly breaks
// working integrations without preventing the description from having
// already been read -- so calls fail open by default, loudly.
func (p Policy) Decide(point Point, l Lookup) Decision {
	d := Decision{ContentHash: l.ContentHash}

	if !l.Discovered {
		// The gateway has never seen this tool in a listing. On the listing
		// side this cannot arise (the catalog is what builds the listing);
		// on the call side it means the client is naming something we have
		// no definition for at all.
		d.Reason = ReasonUndiscovered
		d.Outcome = p.OnUnknown
		if point == PointList {
			d.Outcome = Deny
		}
		return d
	}

	if l.Unavailable && !l.Found {
		d.Reason = ReasonUnavailable
		d.Stale = l.Stale
		if point == PointList {
			// Cannot vouch for the description, so do not show it.
			d.Outcome = Deny
			return d
		}
		d.Outcome = p.OnUnavailable
		return d
	}

	if !l.Found {
		d.Reason = ReasonUnknownHash
		if point == PointList {
			d.Outcome = Deny
			return d
		}
		d.Outcome = p.OnUnknown
		return d
	}

	d.Verdict = l.Record.Verdict
	d.AttackClass = l.Record.AttackClass
	d.ProducedBy = l.Record.ProducedBy
	d.ScannerFingerprint = l.Record.ScannerFingerprint
	d.Stale = l.Stale

	switch l.Record.Verdict {
	case VerdictBenign:
		d.Reason = ReasonBenign
		d.Outcome = Allow
	case VerdictMalicious:
		d.Reason = ReasonMalicious
		d.Outcome = Deny
	case VerdictUncertain:
		d.Reason = ReasonUncertain
		d.Outcome = p.OnUncertain
	case VerdictLayer3Failure:
		// The scanner ran and could not produce a checkable answer -- an
		// evidence span that wasn't a literal substring, or no parsed
		// output at all. That is a non-answer, not a clean bill of health,
		// so it follows the uncertain policy rather than falling through.
		d.Reason = ReasonScanFailed
		d.Outcome = p.OnUncertain
	default:
		// An unrecognized verdict string, e.g. written by a newer control
		// plane than this gateway knows about. Treated as unknown rather
		// than allowed: an unreadable verdict is not a benign one.
		d.Reason = ReasonUnknownHash
		d.Verdict = ""
		if point == PointList {
			d.Outcome = Deny
		} else {
			d.Outcome = p.OnUnknown
		}
	}
	return d
}
