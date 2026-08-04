"""Checkpointers — persist AgentState per node for resumability and replay.

An in-memory store (dev/tests) and a SQLite store (stdlib, sovereign/local).
Both keep the full history of checkpoints per ``thread_id`` so a run can be
replayed step by step, not just resumed from the head.
"""

from __future__ import annotations

import json
import sqlite3
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional


class Checkpointer(ABC):
    @abstractmethod
    def put(self, thread_id: str, step: int, node: str, state: dict) -> None:
        ...

    @abstractmethod
    def latest(self, thread_id: str) -> Optional[dict]:
        ...

    @abstractmethod
    def history(self, thread_id: str) -> list[dict]:
        ...


class InMemoryCheckpointer(Checkpointer):
    def __init__(self) -> None:
        self._store: dict[str, list[dict]] = {}

    def put(self, thread_id: str, step: int, node: str, state: dict) -> None:
        self._store.setdefault(thread_id, []).append(
            {"step": step, "node": node, "state": state})

    def latest(self, thread_id: str) -> Optional[dict]:
        entries = self._store.get(thread_id)
        return entries[-1]["state"] if entries else None

    def history(self, thread_id: str) -> list[dict]:
        return list(self._store.get(thread_id, []))


class SqliteCheckpointer(Checkpointer):
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS checkpoints ("
                "thread_id TEXT, step INTEGER, node TEXT, state TEXT, "
                "PRIMARY KEY (thread_id, step))"
            )

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def put(self, thread_id: str, step: int, node: str, state: dict) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO checkpoints VALUES (?,?,?,?)",
                (thread_id, step, node, json.dumps(state)),
            )

    def latest(self, thread_id: str) -> Optional[dict]:
        with self._conn() as c:
            row = c.execute(
                "SELECT state FROM checkpoints WHERE thread_id=? "
                "ORDER BY step DESC LIMIT 1", (thread_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def history(self, thread_id: str) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT step, node, state FROM checkpoints WHERE thread_id=? "
                "ORDER BY step ASC", (thread_id,)
            ).fetchall()
        return [{"step": s, "node": n, "state": json.loads(st)} for s, n, st in rows]
