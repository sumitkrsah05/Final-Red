"""Phase 4 — LLM Planner & orchestration.

A typed ``AgentState`` driven by a LangGraph-style ``StateGraph``: the planner
node decides the next phase, passive phases run straight through, and any active
step parks at an approval interrupt until a named approver signs off. State is
checkpointed after every node for resumability and replay.

The engine here mirrors the LangGraph API (``add_node`` / ``add_conditional_edges``
/ ``interrupt`` / checkpointer) so it runs offline and deterministically in this
build; LangGraph is the drop-in production backend.
"""

from safeguard.graph.state import AgentState, PlanDecision
from safeguard.graph.engine import (
    END,
    START,
    CompiledGraph,
    GraphInterrupt,
    StateGraph,
)
from safeguard.graph.checkpoint import InMemoryCheckpointer, SqliteCheckpointer
from safeguard.graph.build import build_engagement_graph

__all__ = [
    "AgentState",
    "PlanDecision",
    "END",
    "START",
    "CompiledGraph",
    "GraphInterrupt",
    "StateGraph",
    "InMemoryCheckpointer",
    "SqliteCheckpointer",
    "build_engagement_graph",
]
