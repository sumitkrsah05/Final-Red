"""Tool registry — binds tools.yaml specs to adapter implementations.

The safety class is a property of this binding, loaded from tools.yaml. The LLM
cannot assert or change it. Tools declared in YAML but without an implemented
adapter are held as "declared, not runnable" so the planner can see intent
without being able to execute them.
"""

from __future__ import annotations

from typing import Optional

from safeguard.config.loader import load_tool_registry
from safeguard.config.models import ToolSpec
from safeguard.tools.adapter import ToolAdapter
from safeguard.tools.adapters import ADAPTERS


class ToolRegistry:
    def __init__(self, specs: dict[str, ToolSpec]) -> None:
        self._specs = specs
        self._adapters: dict[str, ToolAdapter] = {}
        for name, spec in specs.items():
            adapter_cls = ADAPTERS.get(name)
            if adapter_cls is not None:
                self._adapters[name] = adapter_cls(spec)

    @classmethod
    def from_yaml(cls, path: str) -> "ToolRegistry":
        return cls(load_tool_registry(path))

    def spec(self, name: str) -> Optional[ToolSpec]:
        return self._specs.get(name)

    def adapter(self, name: str) -> Optional[ToolAdapter]:
        return self._adapters.get(name)

    def runnable(self) -> list[str]:
        return sorted(self._adapters)

    def declared(self) -> list[str]:
        return sorted(self._specs)
