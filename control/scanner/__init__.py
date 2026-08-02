"""Three-layer tool-poisoning detection cascade.

See corpus/README.md for what this detects and how the labeled corpus that
backs layer2/layer3 evaluation was built.

  layer1_rules      - deterministic regex/heuristics, zero LLM cost
  layer2_similarity - embedding similarity against the known-attack corpus
  layer3_llm        - Claude structured-output classifier, verified evidence
  cascade           - orchestrates all three, short-circuiting on confidence
"""
