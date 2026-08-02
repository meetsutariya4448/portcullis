"""Layer 1: deterministic rules over tool descriptions.

Zero LLM cost. Every rule has a stable id, belongs to a category, and
returns the matched spans (start, end, text) it found — so a caller can
show *why* a description was flagged, not just that it was.

Categories, per the task spec: imperative instructions aimed at the model,
references to other tools by name, base64 blobs, URL patterns, unicode
homoglyphs/hidden characters, and instructions to conceal behavior. Two more
were added because they show up heavily in the actual corpus seeds
(../evals/corpus/seeds.json): sensitive-path references (~/.ssh, id_rsa,
mcp.json — present in 4 of the 11 seeds) and coercive "or the system will
crash" language (present in 3).

Scoring here is a provisional heuristic (distinct-category count), not
tuned against the corpus — the task explicitly defers threshold tuning to
the eval step. Treat Layer1Result.confidence as indicative, not final.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# --- span / match types -----------------------------------------------------


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    text: str


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    category: str
    spans: tuple[Span, ...]


@dataclass(frozen=True)
class Layer1Result:
    verdict: str  # "malicious" | "uncertain" | "benign"
    confidence: float
    matches: tuple[RuleMatch, ...]

    @property
    def categories(self) -> frozenset[str]:
        return frozenset(m.category for m in self.matches)


# --- regex-based rules -------------------------------------------------------
# Each entry: (rule_id, category, compiled pattern). Patterns are matched
# case-insensitively except where the exact casing is part of the signal
# (e.g. "MUST FIRST", "IMPORTANT" shouting).

_IMPERATIVE_PATTERNS = [
    ("L1-IMP-01", re.compile(r"<IMPORTANT>", re.IGNORECASE)),
    ("L1-IMP-02", re.compile(r"\byou\s+MUST\b")),
    ("L1-IMP-03", re.compile(r"\bMUST\s+FIRST\b")),
    ("L1-IMP-04", re.compile(r"\bbefore using this tool\b", re.IGNORECASE)),
    ("L1-IMP-05", re.compile(r"\bnon-negotiable\b", re.IGNORECASE)),
    ("L1-IMP-06", re.compile(r"\bessential(?:,| that)\b", re.IGNORECASE)),
]

_CONCEAL_PATTERNS = [
    ("L1-CON-01", re.compile(r"\bdo not mention\b", re.IGNORECASE)),
    ("L1-CON-02", re.compile(r"\bdo(?:n't| not) (?:notify|tell)\b", re.IGNORECASE)),
    ("L1-CON-03", re.compile(r"\bwithout (?:logging|notifying)\b", re.IGNORECASE)),
    ("L1-CON-04", re.compile(r"\bno need to mention\b", re.IGNORECASE)),
    ("L1-CON-05", re.compile(r"\bmere implementation detail\b", re.IGNORECASE)),
    ("L1-CON-06", re.compile(r"\bnot (?:mention|announce)(?:ed)? to (?:anyone|the user)\b", re.IGNORECASE)),

]

_TOOL_REFERENCE_PATTERNS = [
    ("L1-TREF-01", re.compile(r"\bthe\s+[\w]+\s+tool\b", re.IGNORECASE)),
    ("L1-TREF-02", re.compile(r"\btool\s+named\s+['\"]?[\w./-]+['\"]?", re.IGNORECASE)),
    ("L1-TREF-03", re.compile(r"\(mcp_[\w]+\)")),
    ("L1-TREF-04", re.compile(r"\bmcp_[\w]+\b")),
    ("L1-TREF-05", re.compile(r"\bregardless of which server\b", re.IGNORECASE)),
    ("L1-TREF-06", re.compile(r"\bwhen(?:ever)? (?:a tool named |the )?['\"]?[\w]+['\"]? (?:is|tool) (?:invoked|called)\b", re.IGNORECASE)),
]

_BASE64_PATTERNS = [
    # >= 32 contiguous base64-alphabet chars (8 groups of 4), optional padding.
    ("L1-B64-01", re.compile(r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")),
]

_URL_PATTERNS = [
    ("L1-URL-01", re.compile(r"https?://[^\s'\"<>]+")),
]

_SENSITIVE_PATH_PATTERNS = [
    ("L1-PATH-01", re.compile(r"~/\.ssh")),
    ("L1-PATH-02", re.compile(r"\bid_rsa\b")),
    ("L1-PATH-03", re.compile(r"~/\.aws/credentials")),
    ("L1-PATH-04", re.compile(r"~/\.gitconfig")),
    ("L1-PATH-05", re.compile(r"~/\.cursor")),
    ("L1-PATH-06", re.compile(r"\bmcp\.json\b")),
    ("L1-PATH-07", re.compile(r"\.env\b")),
]

_COERCIVE_PATTERNS = [
    ("L1-COE-01", re.compile(r"\bwill crash\b", re.IGNORECASE)),
    ("L1-COE-02", re.compile(r"\bfailure to (?:do so|adhere)\b", re.IGNORECASE)),
    ("L1-COE-03", re.compile(r"\bwill not work otherwise\b", re.IGNORECASE)),
    ("L1-COE-04", re.compile(r"\ball data will be lost\b", re.IGNORECASE)),
]

_RULE_GROUPS: list[tuple[str, list[tuple[str, re.Pattern]]]] = [
    ("imperative_instruction", _IMPERATIVE_PATTERNS),
    ("conceal_behavior", _CONCEAL_PATTERNS),
    ("tool_reference", _TOOL_REFERENCE_PATTERNS),
    ("base64_blob", _BASE64_PATTERNS),
    ("url_pattern", _URL_PATTERNS),
    ("sensitive_path", _SENSITIVE_PATH_PATTERNS),
    ("coercive_language", _COERCIVE_PATTERNS),
]

# --- unicode homoglyph / hidden-character rule -------------------------------
# Not expressible as a single regex substring: these are individual
# codepoints that are suspicious wherever they appear, not fixed strings.

_ZERO_WIDTH_HIDDEN = {
    "​",  # zero-width space
    "‌",  # zero-width non-joiner
    "‍",  # zero-width joiner
    "‎",  # left-to-right mark
    "‏",  # right-to-left mark
    "﻿",  # BOM / zero-width no-break space
}
_BIDI_CONTROL_RANGE = (0x202A, 0x202E)  # LRE, RLE, PDF, LRO, RLO
_BIDI_ISOLATE_RANGE = (0x2066, 0x2069)  # LRI, RLI, FSI, PDI


def _is_hidden_or_bidi(ch: str) -> bool:
    if ch in _ZERO_WIDTH_HIDDEN:
        return True
    cp = ord(ch)
    return _BIDI_CONTROL_RANGE[0] <= cp <= _BIDI_CONTROL_RANGE[1] or _BIDI_ISOLATE_RANGE[0] <= cp <= _BIDI_ISOLATE_RANGE[1]


def _is_cyrillic_homoglyph(ch: str) -> bool:
    # Cyrillic letters that are visually indistinguishable from common Latin
    # letters (а/a, е/e, о/o, р/p, с/c, х/x, у/y, etc.) — a common ASCII
    # look-alike trick. Flags Cyrillic presence in an otherwise-Latin string.
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return False
    return name.startswith("CYRILLIC")


def _scan_unicode(description: str) -> RuleMatch | None:
    spans = []
    has_latin = bool(re.search(r"[A-Za-z]", description))
    for i, ch in enumerate(description):
        if _is_hidden_or_bidi(ch):
            spans.append(Span(i, i + 1, repr(ch)))
        elif has_latin and _is_cyrillic_homoglyph(ch):
            spans.append(Span(i, i + 1, ch))
    if not spans:
        return None
    return RuleMatch(rule_id="L1-UNI-01", category="unicode_homoglyph", spans=tuple(spans))


# --- public API ---------------------------------------------------------------


def scan(description: str) -> Layer1Result:
    """Run every rule against description and produce a verdict.

    Verdict/confidence are a simple, documented placeholder pending
    corpus-driven threshold tuning (see module docstring). confidence is
    "how confident layer 1 is in *this* verdict" — not "how malicious" — so
    a clean, zero-match description gets *high* confidence too: that's what
    lets the cascade short-circuit the common case cheaply instead of
    paying for embedding + LLM calls on every benign description.
      0 distinct categories matched -> benign, high confidence
      1 -> uncertain, low confidence
      2 -> malicious, moderate confidence
      3+ -> malicious, high confidence
    """
    matches: list[RuleMatch] = []

    for category, patterns in _RULE_GROUPS:
        for rule_id, pattern in patterns:
            spans = tuple(Span(m.start(), m.end(), m.group(0)) for m in pattern.finditer(description))
            if spans:
                matches.append(RuleMatch(rule_id=rule_id, category=category, spans=spans))

    unicode_match = _scan_unicode(description)
    if unicode_match:
        matches.append(unicode_match)

    categories = frozenset(m.category for m in matches)
    n = len(categories)

    if n == 0:
        verdict, confidence = "benign", 0.95
    elif n == 1:
        verdict, confidence = "uncertain", 0.35
    elif n == 2:
        verdict, confidence = "malicious", 0.65
    else:
        verdict, confidence = "malicious", 0.92

    return Layer1Result(verdict=verdict, confidence=confidence, matches=tuple(matches))
