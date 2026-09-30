"""Human-in-the-loop review queue.

A REVIEW verdict must not silently fail: the call is held, an entry is queued, and
a human approves or denies it. One queue handles both kinds of pending decision -
risky tool calls and memory-promotion requests - because from the reviewer's side
they are the same job.

Approval is single-use. An approved entry authorises exactly the call that was
queued (same tool, same arguments digest), so an approval cannot be replayed to
wave through a different call later.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentguard.audit import digest_args
from agentguard.db import connect

KIND_TOOL_CALL = "tool_call"
KIND_MEMORY_PROMOTION = "memory_promotion"

STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_DENIED = "denied"
STATUS_CONSUMED = "consumed"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ReviewItem:
    id: int
    ts: str
    session_id: str | None
    agent: str | None
    kind: str
    tool: str | None
    payload: dict[str, Any]
    score: float | None
    reason: str | None
    status: str
    resolved_at: str | None = None
    resolved_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "ts": self.ts, "session_id": self.session_id,
            "agent": self.agent, "kind": self.kind, "tool": self.tool,
            "payload": self.payload, "score": self.score, "reason": self.reason,
            "status": self.status, "resolved_at": self.resolved_at,
            "resolved_by": self.resolved_by,
        }


def _row(r: Any) -> ReviewItem:
    return ReviewItem(
        id=int(r["id"]), ts=r["ts"], session_id=r["session_id"], agent=r["agent"],
        kind=r["kind"], tool=r["tool"], payload=json.loads(r["payload"] or "{}"),
        score=r["score"], reason=r["reason"], status=r["status"],
        resolved_at=r["resolved_at"], resolved_by=r["resolved_by"],
    )


class ReviewQueue:
    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = db_path

    @property
    def conn(self):  # type: ignore[no-untyped-def]
        return connect(self.db_path)

    def enqueue(self, *, kind: str, tool: str | None, payload: dict[str, Any],
                score: float | None = None, reason: str | None = None,
                session_id: str | None = None, agent: str | None = None) -> int:
        cur = self.conn.execute(
            """INSERT INTO review_queue (ts, session_id, agent, kind, tool, payload,
                                         score, reason, status)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (_now(), session_id, agent, kind, tool, json.dumps(payload, default=str),
             score, reason, STATUS_PENDING),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def get(self, item_id: int) -> ReviewItem | None:
        r = self.conn.execute("SELECT * FROM review_queue WHERE id = ?", (item_id,)).fetchone()
        return _row(r) if r else None

    def list(self, status: str | None = STATUS_PENDING) -> list[ReviewItem]:
        if status:
            rows = self.conn.execute(
                "SELECT * FROM review_queue WHERE status = ? ORDER BY id DESC", (status,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM review_queue ORDER BY id DESC").fetchall()
        return [_row(r) for r in rows]

    def _resolve(self, item_id: int, status: str, by: str) -> ReviewItem | None:
        if self.get(item_id) is None:
            return None
        self.conn.execute(
            "UPDATE review_queue SET status=?, resolved_at=?, resolved_by=? WHERE id=?",
            (status, _now(), by, item_id),
        )
        self.conn.commit()
        return self.get(item_id)

    def approve(self, item_id: int, by: str = "human") -> ReviewItem | None:
        return self._resolve(item_id, STATUS_APPROVED, by)

    def deny(self, item_id: int, by: str = "human") -> ReviewItem | None:
        return self._resolve(item_id, STATUS_DENIED, by)

    # --- single-use approval lookup ---------------------------------------
    def find_approval(self, tool: str, arguments: Any,
                      session_id: str | None = None) -> ReviewItem | None:
        """Find an unconsumed approval matching exactly this call.

        Matching on the arguments digest is what makes an approval single-use and
        non-transferable: approving `filesystem.read(report.txt)` does not approve
        `filesystem.read(~/.ssh/id_rsa)`.
        """
        want = digest_args(arguments)
        rows = self.conn.execute(
            """SELECT * FROM review_queue
               WHERE tool = ? AND kind = ? AND status = ?
               ORDER BY id ASC""",
            (tool, KIND_TOOL_CALL, STATUS_APPROVED),
        ).fetchall()
        for r in rows:
            item = _row(r)
            if item.payload.get("args_digest") != want:
                continue
            if session_id and item.session_id and item.session_id != session_id:
                continue
            return item
        return None

    def consume(self, item_id: int) -> None:
        """Burn an approval so it cannot authorise a second call."""
        self.conn.execute(
            "UPDATE review_queue SET status=? WHERE id=?", (STATUS_CONSUMED, item_id)
        )
        self.conn.commit()

    def pending_count(self) -> int:
        return int(self.conn.execute(
            "SELECT COUNT(*) FROM review_queue WHERE status=?", (STATUS_PENDING,)
        ).fetchone()[0])
