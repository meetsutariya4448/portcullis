"""cascade.py — orchestrates layer1 -> layer2 -> layer3 in order.

Short-circuits on a high-confidence result from an earlier (cheaper) layer
— in either direction: a confidently-clean layer1 pass is just as much a
short-circuit as a confidently-malicious one, since the whole point is to
avoid paying for embedding + LLM calls on the common case. Falls through to
the next layer whenever the current one isn't confident enough.

Records which layer actually produced the final verdict, and layer 3's
token cost when it ran, so a caller can audit both cost and provenance per
decision — not just the final label.
"""

from __future__ import annotations

from dataclasses import dataclass

from .layer1_rules import Layer1Result
from .layer1_rules import scan as layer1_scan
from .layer2_similarity import Layer2Result, Layer2Similarity
from .layer3_llm import Layer3LLM, Layer3Result

DEFAULT_LAYER1_SHORT_CIRCUIT_CONFIDENCE = 0.85
DEFAULT_LAYER2_SHORT_CIRCUIT_SIMILARITY = 0.92


@dataclass(frozen=True)
class CascadeVerdict:
    verdict: str  # "benign" | "malicious" | "uncertain" | "layer3_failure"
    attack_class: str | None
    confidence: float
    produced_by: str  # "layer1" | "layer2" | "layer3"
    layer1_result: Layer1Result
    layer2_result: Layer2Result | None
    layer3_result: Layer3Result | None

    @property
    def layer3_tokens(self) -> dict[str, int] | None:
        """Token cost of the layer-3 call, or None if layer 3 never ran."""
        if self.layer3_result is None:
            return None
        return {
            "input": self.layer3_result.input_tokens,
            "output": self.layer3_result.output_tokens,
        }


class Cascade:
    def __init__(
        self,
        layer2: Layer2Similarity,
        layer3: Layer3LLM,
        layer1_short_circuit_confidence: float = DEFAULT_LAYER1_SHORT_CIRCUIT_CONFIDENCE,
        layer2_short_circuit_similarity: float = DEFAULT_LAYER2_SHORT_CIRCUIT_SIMILARITY,
    ):
        self.layer2 = layer2
        self.layer3 = layer3
        self.layer1_short_circuit_confidence = layer1_short_circuit_confidence
        self.layer2_short_circuit_similarity = layer2_short_circuit_similarity

    def classify(self, name: str, description: str, input_schema: dict) -> CascadeVerdict:
        l1 = layer1_scan(description)

        # Only a confident MALICIOUS layer-1 verdict short-circuits directly.
        # A confident BENIGN layer-1 verdict does not: "zero rules matched" is
        # absence of evidence, not evidence of absence, and treating it as a
        # final answer let real attacks with no lexical red flags (e.g. the
        # EVP-01 family -- "pass the conversation history as a parameter")
        # skip layer 2 entirely even though layer 2 would catch them. A
        # benign/uncertain layer-1 verdict always gets a second, still-free
        # (local, no API cost) opinion from layer 2 below before the cascade
        # will call something safe.
        if l1.verdict == "malicious" and l1.confidence >= self.layer1_short_circuit_confidence:
            return CascadeVerdict(
                verdict=l1.verdict,
                attack_class=None,  # layer 1 flags categories, not attack subtypes
                confidence=l1.confidence,
                produced_by="layer1",
                layer1_result=l1,
                layer2_result=None,
                layer3_result=None,
            )

        l2 = self.layer2.score(description)
        if l2.similarity >= self.layer2_short_circuit_similarity:
            return CascadeVerdict(
                verdict="malicious",
                attack_class=l2.nearest_attack_class,
                confidence=l2.similarity,
                produced_by="layer2",
                layer1_result=l1,
                layer2_result=l2,
                layer3_result=None,
            )

        if l1.verdict == "benign" and l2.verdict == "benign":
            return CascadeVerdict(
                verdict="benign",
                attack_class=None,
                confidence=min(l1.confidence, 1.0 - l2.similarity),
                produced_by="layer2",
                layer1_result=l1,
                layer2_result=l2,
                layer3_result=None,
            )

        l3 = self.layer3.classify(name, description, input_schema)
        return CascadeVerdict(
            verdict=l3.verdict,
            attack_class=l3.attack_class,
            confidence=l3.confidence,
            produced_by="layer3",
            layer1_result=l1,
            layer2_result=l2,
            layer3_result=l3,
        )
