"""RedBlueAI Safeguard — autonomous, safety-gated red-team agent.

This package implements the Safeguard loop: a non-destructive, human-in-the-loop
breach-and-attack-simulation engine. Phase 0 (safety rails) and Phase 1 (tool
adapter framework) are implemented here.

Golden rule enforced throughout: *the LLM proposes, deterministic code disposes.*
No tool ever runs except through the safety pipeline in ``safeguard.safety.pipeline``.
"""

__version__ = "0.1.0"
