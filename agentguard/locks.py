"""Locks that reach every running gateway - Stage 7D.

The Stage 3 kill switch lives inside one gateway process, so a human at a
terminal had no way to use it. Locks are written to the gateway's local SQLite
file by the CLI and checked by the gateway at the top of every call:

  agentguard lock --all              every session, every gateway on this database
  agentguard lock --session <id>     one session
  agentguard unlock --all | --session <id>

A lock is a human command, not a detector, so it is absolute: it stops calls in
observe mode too.

What a lock cannot do, stated plainly: it stops traffic *through the gateway*.
It does not revoke credentials held by upstream MCP servers, sessions those
servers opened elsewhere, or anything the agent can reach without going through
AgentGuard. Rotate the credentials themselves if they may be compromised.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from agentguard.db import connect

ALL = "*"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Lock:
    id: int
    scope: str
    reason: str | None
    locked_by: str | None
    locked_at: str

    @property
    def is_global(self) -> bool:
        return self.scope == ALL


class LockStore:
    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = db_path

    @property
    def conn(self):  # type: ignore[no-untyped-def]
        return connect(self.db_path)

    def _lock(self, scope: str, reason: str, by: str) -> Lock:
        cur = self.conn.execute(
            "INSERT INTO locks (scope, reason, locked_by, locked_at) VALUES (?,?,?,?)",
            (scope, reason, by, _now()),
        )
        self.conn.commit()
        return Lock(int(cur.lastrowid), scope, reason, by, _now())

    def lock_all(self, reason: str = "manual lock", by: str = "human") -> Lock:
        return self._lock(ALL, reason, by)

    def lock_session(self, session_id: str, reason: str = "manual lock",
                     by: str = "human") -> Lock:
        return self._lock(session_id, reason, by)

    def release(self, scope: str, by: str = "human") -> int:
        cur = self.conn.execute(
            "UPDATE locks SET released_at=?, released_by=? "
            "WHERE scope=? AND released_at IS NULL",
            (_now(), by, scope),
        )
        self.conn.commit()
        return cur.rowcount

    def active(self) -> list[Lock]:
        rows = self.conn.execute(
            "SELECT * FROM locks WHERE released_at IS NULL ORDER BY id ASC"
        ).fetchall()
        return [Lock(int(r["id"]), r["scope"], r["reason"], r["locked_by"], r["locked_at"])
                for r in rows]

    def active_for(self, session_id: str) -> Lock | None:
        """The lock that applies to this session - a global lock first."""
        row = self.conn.execute(
            "SELECT * FROM locks WHERE released_at IS NULL AND scope IN (?, ?) "
            "ORDER BY (scope = ?) DESC, id ASC LIMIT 1",
            (ALL, session_id, ALL),
        ).fetchone()
        if row is None:
            return None
        return Lock(int(row["id"]), row["scope"], row["reason"], row["locked_by"],
                    row["locked_at"])
