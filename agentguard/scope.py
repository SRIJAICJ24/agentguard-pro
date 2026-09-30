"""Declared task scope - Stage 7C.

The gateway sees tool calls, never the agent's reasoning, so "is the agent still
doing what it was asked?" has to be answered from the tool trace. The
deterministic version of that question is a scope: the set of tools this task is
expected to need, declared by the *human* before or during the session.

  * Set per session from the CLI (`agentguard scope set --session ...`), or as a
    per-role default in the policy YAML (`roles.<role>.scope`).
  * A call outside the scope is not refused - it is REVIEWed, with signal
    `scope:outside`. Scopes are a statement of intent, and intent is fuzzy.
  * The scope is stored in the gateway's local SQLite file, which only the CLI
    writes. Nothing on the MCP channel can reach it: the gateway exposes no tool
    that changes it, and any call to a reserved control-plane name
    (`agentguard*` by default) is refused and logged as `scope:tamper_attempt` -
    an upstream server advertising such a tool is itself a red flag.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from agentguard.db import connect
from agentguard.policy import Policy


@dataclass
class TaskScope:
    tools: list[str]
    goal: str | None = None
    source: str = "session"          # "session" (CLI) or "role:<name>" (policy)
    set_by: str | None = None
    set_at: str | None = None

    def allows(self, tool: str) -> bool:
        return any(fnmatch(tool, p) for p in self.tools)

    def to_dict(self) -> dict[str, Any]:
        return {"tools": self.tools, "goal": self.goal, "source": self.source,
                "set_by": self.set_by, "set_at": self.set_at}


def parse_tools(text: str) -> list[str]:
    return [t.strip() for t in text.split(",") if t.strip()]


class ScopeStore:
    def __init__(self, db_path: str | Path | None = None,
                 policy: Policy | None = None) -> None:
        self.db_path = db_path
        self.policy = policy

    @property
    def conn(self):  # type: ignore[no-untyped-def]
        return connect(self.db_path)

    # --- written only by the CLI ------------------------------------------
    def set(self, session_id: str, tools: list[str], goal: str | None = None,
            set_by: str = "human") -> TaskScope:
        if not tools:
            raise ValueError("a scope needs at least one tool pattern")
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.conn.execute(
            """INSERT INTO task_scope (session_id, tools, goal, set_by, set_at)
               VALUES (?,?,?,?,?)
               ON CONFLICT(session_id) DO UPDATE SET
                 tools=excluded.tools, goal=excluded.goal,
                 set_by=excluded.set_by, set_at=excluded.set_at""",
            (session_id, json.dumps(tools), goal, set_by, now),
        )
        self.conn.commit()
        return TaskScope(tools, goal, "session", set_by, now)

    def clear(self, session_id: str) -> bool:
        cur = self.conn.execute("DELETE FROM task_scope WHERE session_id = ?", (session_id,))
        self.conn.commit()
        return cur.rowcount > 0

    # --- read by the gateway ----------------------------------------------
    def get(self, session_id: str) -> TaskScope | None:
        row = self.conn.execute(
            "SELECT * FROM task_scope WHERE session_id = ?", (session_id,)
        ).fetchone()
        if row is None:
            return None
        return TaskScope(json.loads(row["tools"]), row["goal"], "session",
                         row["set_by"], row["set_at"])

    def all(self) -> dict[str, TaskScope]:
        rows = self.conn.execute("SELECT * FROM task_scope ORDER BY set_at DESC").fetchall()
        return {r["session_id"]: TaskScope(json.loads(r["tools"]), r["goal"], "session",
                                           r["set_by"], r["set_at"]) for r in rows}

    def effective(self, session_id: str, role: str | None) -> TaskScope | None:
        """The session's own scope, else the role default, else None (no scope)."""
        if self.policy is not None and not self.policy.scope.enabled:
            return None
        scope = self.get(session_id)
        if scope is not None:
            return scope
        if self.policy is not None and role:
            rule = self.policy.roles.get(role)
            if rule is not None and rule.scope:
                return TaskScope(list(rule.scope), None, f"role:{role}")
        return None

    def is_reserved(self, tool: str) -> bool:
        patterns = self.policy.scope.reserved_tools if self.policy else ["agentguard*"]
        return any(fnmatch(tool.lower(), p.lower()) for p in patterns)
