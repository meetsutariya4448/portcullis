"""Content hashing for tool definitions -- the Python half of a
cross-language contract with `gateway/internal/admission/hash.go`.

A verdict is keyed by the hash of the exact tool text it was formed about.
If the two languages ever disagree about that hash, the worker's verdicts
land under keys the gateway never looks up: scanning appears to work,
enforcement silently does nothing, and no test that exercises only one side
would notice. `testdata/tool_hash_vectors.json` is asserted from both.

Division of labour
------------------
The gateway is authoritative: it sees the upstream's bytes, derives the
canonical form, and ships that form verbatim to the scan queue. The worker
normally only needs `hash_canonical` to verify the bytes it was handed.
`canonical_form` is implemented here as well so a human (or a test, or the
one-shot CLI) can compute a hash without running the gateway.

Why not json.dumps
------------------
Two divergences from Go would break agreement silently:

  * escaping -- Go's Marshal escapes <, >, & and always escapes
    U+2028/U+2029; Python's dumps(ensure_ascii=False) escapes none of them.
    A description carrying an invisible U+2028, exactly the sort of thing a
    poisoned description does carry, would hash differently in each.
  * numbers -- decoding to float and re-formatting collapses 1.0/1.00/1e0
    and rounds large integers. Both sides preserve the literal token the
    upstream actually sent.
"""

from __future__ import annotations

import hashlib
import json

HASH_PREFIX = b"portcullis-tool-v1\n"

# Mirrors the constants in hash.go. Kept in sync by
# tests/test_hashing.py::test_bounds_match_the_go_implementation.
MAX_DESCRIPTION_BYTES = 64 * 1024
MAX_SCHEMA_BYTES = 256 * 1024
MAX_SCHEMA_DEPTH = 32
MAX_TOOL_NAME_BYTES = 512

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


class ToolTooLarge(ValueError):
    """A tool definition exceeded the bounds above; hash nothing and
    withhold the tool rather than doing unbounded work on untrusted input.
    """


class SchemaTooDeep(ValueError):
    """Schema nested past MAX_SCHEMA_DEPTH."""


def _canonical_string(s: str) -> str:
    out = ['"']
    for ch in s:
        escape = _ESCAPES.get(ch)
        if escape is not None:
            out.append(escape)
        elif ch < " ":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


class _RawNumber(str):
    """A JSON number kept as its original literal token."""


def _canonical_value(value, depth: int = 0) -> str:
    if depth > MAX_SCHEMA_DEPTH:
        raise SchemaTooDeep(f"deeper than {MAX_SCHEMA_DEPTH}")
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, _RawNumber):
        return str(value)
    if isinstance(value, str):
        return _canonical_string(value)
    if isinstance(value, (int, float)):
        # Reached only when a caller passes already-parsed Python numbers
        # (e.g. a dict built in a test) rather than raw JSON. Integers are
        # exact; floats use repr, which is the shortest round-tripping form.
        return str(value) if isinstance(value, int) else repr(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical_value(v, depth + 1) for v in value) + "]"
    if isinstance(value, dict):
        # Sorted by code point, which matches Go's bytewise sort over UTF-8.
        parts = [
            _canonical_string(k) + ":" + _canonical_value(v, depth + 1)
            for k, v in sorted(value.items())
        ]
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"unexpected JSON value of type {type(value).__name__}")


def _parse_preserving_numbers(raw: str):
    return json.loads(raw, parse_float=_RawNumber, parse_int=_RawNumber)


def canonical_form(name: str, description: str, input_schema) -> bytes:
    """The exact bytes both languages hash.

    `input_schema` may be raw JSON (str/bytes, whose numeric literals are
    preserved) or an already-parsed Python object.
    """
    if len(name.encode()) > MAX_TOOL_NAME_BYTES:
        raise ToolTooLarge(f"tool name {len(name.encode())}B")
    if len(description.encode()) > MAX_DESCRIPTION_BYTES:
        raise ToolTooLarge(f"description {len(description.encode())}B")

    if isinstance(input_schema, (str, bytes)):
        raw = input_schema.decode() if isinstance(input_schema, bytes) else input_schema
        if len(raw.encode()) > MAX_SCHEMA_BYTES:
            raise ToolTooLarge(f"input schema {len(raw.encode())}B")
        schema = _parse_preserving_numbers(raw or "{}")
    else:
        schema = {} if input_schema is None else input_schema

    body = (
        '{"description":'
        + _canonical_string(description)
        + ',"inputSchema":'
        + _canonical_value(schema)
        + ',"name":'
        + _canonical_string(name)
        + "}"
    )
    return body.encode()


def hash_canonical(canonical: bytes) -> str:
    """Digest of an already-canonical form -- the worker's normal path."""
    return hashlib.sha256(HASH_PREFIX + canonical).hexdigest()


def content_hash(name: str, description: str, input_schema) -> str:
    return hash_canonical(canonical_form(name, description, input_schema))
