"""Cascade orchestration tests. Layer 2 and layer 3 are fakes here (not the
real Layer2Similarity/Layer3LLM) so these tests isolate cascade.py's own
logic -- short-circuit thresholds, fallthrough, and call counts -- from
embedding math or LLM parsing, which are already covered in
test_layer2_similarity.py and test_layer3_llm.py.
"""

from __future__ import annotations

from scanner.cascade import Cascade
from scanner.layer2_similarity import Layer2Result
from scanner.layer3_llm import Layer3Result


class FakeLayer2:
    def __init__(self, result: Layer2Result):
        self.result = result
        self.calls = 0

    def score(self, description: str) -> Layer2Result:
        self.calls += 1
        return self.result


class FakeLayer3:
    def __init__(self, result: Layer3Result):
        self.result = result
        self.calls = 0

    def classify(self, name: str, description: str, input_schema: dict) -> Layer3Result:
        self.calls += 1
        return self.result


def _layer2_result(similarity: float, nearest_id="ATK-01", nearest_class="instruction_injection", threshold=0.92) -> Layer2Result:
    return Layer2Result(
        verdict="malicious" if similarity >= threshold else "benign",
        similarity=similarity,
        nearest_id=nearest_id,
        nearest_attack_class=nearest_class,
        threshold=threshold,
    )


def _layer3_result(verdict="malicious", attack_class="tool_shadowing", confidence=0.8) -> Layer3Result:
    return Layer3Result(
        verdict=verdict,
        attack_class=attack_class,
        evidence_span="some evidence" if verdict == "malicious" else None,
        confidence=confidence,
        input_tokens=123,
        output_tokens=45,
    )


def test_layer1_short_circuits_on_confident_benign(instruction_injection_row):
    layer2 = FakeLayer2(_layer2_result(0.1))
    layer3 = FakeLayer3(_layer3_result())
    cascade = Cascade(layer2=layer2, layer3=layer3)

    verdict = cascade.classify("resolve_name", "Return the current weather for a city.", {"type": "object"})

    assert verdict.produced_by == "layer1"
    assert verdict.verdict == "benign"
    assert verdict.layer2_result is None
    assert verdict.layer3_result is None
    assert verdict.layer3_tokens is None
    assert layer2.calls == 0
    assert layer3.calls == 0


def test_layer1_short_circuits_on_confident_malicious(instruction_injection_row):
    # IJ-01's description trips imperative_instruction, conceal_behavior, and
    # sensitive_path -- 3+ categories -> layer1 confidence 0.92, above the
    # default 0.85 short-circuit threshold.
    layer2 = FakeLayer2(_layer2_result(0.1))
    layer3 = FakeLayer3(_layer3_result())
    cascade = Cascade(layer2=layer2, layer3=layer3)

    verdict = cascade.classify("add", instruction_injection_row["description"], instruction_injection_row["input_schema"])

    assert verdict.produced_by == "layer1"
    assert verdict.verdict == "malicious"
    assert layer2.calls == 0
    assert layer3.calls == 0


def test_falls_through_to_layer2_then_layer3_when_layer1_uncertain():
    # A single-category match (just a URL) -> layer1 verdict "uncertain",
    # confidence 0.35 -- below the short-circuit threshold, so it must fall
    # through.
    layer2 = FakeLayer2(_layer2_result(0.3))  # below layer2's own short-circuit
    layer3 = FakeLayer3(_layer3_result(verdict="malicious", attack_class="tool_shadowing"))
    cascade = Cascade(layer2=layer2, layer3=layer3)

    description = "Fetch data from https://api.example.com/weather and return it."
    verdict = cascade.classify("get_weather", description, {"type": "object"})

    assert layer2.calls == 1
    assert layer3.calls == 1
    assert verdict.produced_by == "layer3"
    assert verdict.verdict == "malicious"
    assert verdict.attack_class == "tool_shadowing"
    assert verdict.layer2_result is not None
    assert verdict.layer3_result is not None
    assert verdict.layer3_tokens == {"input": 123, "output": 45}


def test_layer2_short_circuits_on_high_similarity_without_calling_layer3():
    layer2 = FakeLayer2(_layer2_result(0.97, nearest_id="TS-01", nearest_class="tool_shadowing"))
    layer3 = FakeLayer3(_layer3_result())
    cascade = Cascade(layer2=layer2, layer3=layer3)

    description = "Fetch data from https://api.example.com/weather and return it."
    verdict = cascade.classify("get_weather", description, {"type": "object"})

    assert layer2.calls == 1
    assert layer3.calls == 0
    assert verdict.produced_by == "layer2"
    assert verdict.verdict == "malicious"
    assert verdict.attack_class == "tool_shadowing"
    assert verdict.confidence == 0.97
    assert verdict.layer3_result is None
    assert verdict.layer3_tokens is None


def test_layer3_failure_propagates_as_the_final_verdict():
    layer2 = FakeLayer2(_layer2_result(0.3))
    layer3 = FakeLayer3(_layer3_result(verdict="layer3_failure", attack_class=None, confidence=0.0))
    cascade = Cascade(layer2=layer2, layer3=layer3)

    description = "Fetch data from https://api.example.com/weather and return it."
    verdict = cascade.classify("get_weather", description, {"type": "object"})

    assert verdict.produced_by == "layer3"
    assert verdict.verdict == "layer3_failure"


def test_custom_short_circuit_thresholds_are_respected():
    layer2 = FakeLayer2(_layer2_result(0.3))
    layer3 = FakeLayer3(_layer3_result(verdict="benign", attack_class=None, confidence=0.6))
    # Raise layer1's threshold above what even a clean description scores, so
    # a normally-short-circuited benign case is forced to fall all the way
    # through to layer3 instead.
    cascade = Cascade(layer2=layer2, layer3=layer3, layer1_short_circuit_confidence=0.999)

    verdict = cascade.classify("resolve_name", "Return the current weather for a city.", {"type": "object"})

    assert verdict.produced_by == "layer3"
    assert layer2.calls == 1
    assert layer3.calls == 1
