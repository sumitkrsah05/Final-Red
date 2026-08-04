"""A minimal, LangGraph-shaped state-machine engine.

Supports the pieces the design needs: named nodes, static and conditional
edges, an ``interrupt`` that parks the run, a checkpointer for resume/replay,
and deterministic execution. Node functions mutate the shared ``AgentState``.

This mirrors LangGraph's ``StateGraph`` API closely enough that swapping in the
real library later is mechanical; it exists so the engagement graph runs offline
and is unit-testable without the heavy dependency or a live checkpoint DB.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from safeguard.graph.checkpoint import Checkpointer, InMemoryCheckpointer
from safeguard.graph.state import AgentState

START = "__start__"
END = "__end__"

NodeFn = Callable[[AgentState], None]
Router = Callable[[AgentState], str]


class GraphInterrupt(Exception):
    """Raised by a node to park the run pending external input (approval)."""

    def __init__(self, payload: dict) -> None:
        super().__init__("graph interrupted")
        self.payload = payload


@dataclass
class InvokeResult:
    status: str  # "complete" | "interrupted"
    state: AgentState
    node: str


class StateGraph:
    def __init__(self) -> None:
        self._nodes: dict[str, NodeFn] = {}
        self._edges: dict[str, str] = {}
        self._routers: dict[str, Router] = {}
        self._entry: Optional[str] = None

    def add_node(self, name: str, fn: NodeFn) -> "StateGraph":
        if name in (START, END):
            raise ValueError(f"reserved node name: {name}")
        self._nodes[name] = fn
        return self

    def add_edge(self, src: str, dst: str) -> "StateGraph":
        self._edges[src] = dst
        return self

    def add_conditional_edges(self, src: str, router: Router) -> "StateGraph":
        self._routers[src] = router
        return self

    def set_entry(self, name: str) -> "StateGraph":
        self._entry = name
        return self

    def compile(self, checkpointer: Optional[Checkpointer] = None) -> "CompiledGraph":
        if self._entry is None:
            raise ValueError("no entry node set")
        missing = set(self._edges.values()) - set(self._nodes) - {END}
        if missing:
            raise ValueError(f"edges point to undefined nodes: {missing}")
        return CompiledGraph(self, checkpointer or InMemoryCheckpointer())


class CompiledGraph:
    def __init__(self, graph: StateGraph, checkpointer: Checkpointer) -> None:
        self._g = graph
        self.checkpointer = checkpointer

    def _next(self, node: str, state: AgentState) -> str:
        if node in self._g._routers:
            return self._g._routers[node](state)
        return self._g._edges.get(node, END)

    def invoke(self, state: AgentState, *, thread_id: str,
               start_node: Optional[str] = None) -> InvokeResult:
        node = start_node or self._g._entry
        step = len(self.checkpointer.history(thread_id))
        while True:
            fn = self._g._nodes[node]
            try:
                fn(state)
            except GraphInterrupt as gi:
                state.pending_approval = state.pending_approval or gi.payload
                self.checkpointer.put(thread_id, step, node, state.to_checkpoint())
                return InvokeResult("interrupted", state, node)
            self.checkpointer.put(thread_id, step, node, state.to_checkpoint())
            step += 1
            nxt = self._next(node, state)
            if nxt == END:
                state.done = True
                self.checkpointer.put(thread_id, step, END, state.to_checkpoint())
                return InvokeResult("complete", state, END)
            node = nxt

    def resume(self, *, thread_id: str) -> InvokeResult:
        """Resume a parked run: reload the latest checkpoint and re-enter the
        interrupted node (which now re-evaluates external state, e.g. approval)."""
        history = self.checkpointer.history(thread_id)
        if not history:
            raise ValueError(f"no checkpoint for thread {thread_id!r}")
        last = history[-1]
        state = AgentState.from_checkpoint(last["state"])
        return self.invoke(state, thread_id=thread_id, start_node=last["node"])
