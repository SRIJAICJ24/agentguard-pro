"""The Quarantined Memory Ledger.

The problem this solves: an agent reads a poisoned web page, decides the content
is worth remembering, and writes it to durable memory. Every later session then
treats attacker-authored text as its own trusted knowledge. Blocking the write
outright is wrong (it breaks legitimate memory), and allowing it is worse.

So a persistence-tier write carrying untrusted taint is neither blocked nor
trusted - it is *quarantined*:

  * stored separately from trusted memory, never returned as trusted knowledge
  * kept with full provenance: source tool, fingerprints, session, timestamp
  * given a TTL, so unreviewed attacker text expires instead of accumulating
  * on recall, its taint labels are RE-ATTACHED to the returned content

That last property is the one that makes the ledger work rather than just being
another quarantine folder. Taint has to survive the memory boundary, otherwise an
attacker only needs to wait one session for the label to fall off - write in
session A, recall in session B, exfiltrate as "trusted" content. Because recall
re-taints, the exfiltration attempt in session B is still caught.

Promotion to trusted memory requires an explicit human decision and logs the full
provenance alongside it.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentguard.db import connect

STATUS_QUARANTINED = "quarantined"
STATUS_PROMOTED = "promoted"
STATUS_DENIED = "denied"
STATUS_EXPIRED = "expired"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


@dataclass
class QuarantinedItem:
    """One held memory write."""

    id: int
    ts: str
    session_id: str | None
    tool: str | None
    content: str
    source_tools: list[str]
    fingerprints: list[str]
    expires_at: str | None
    status: str
    provenance: dict[str, Any]

    @property
    def expired(self) -> bool:
        if not self.expires_at:
            return False
        try:
            return _now() > datetime.fromisoformat(self.expires_at)
        except ValueError:
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "ts": self.ts, "session_id": self.session_id,
            "tool": self.tool, "content": self.content,
            "source_tools": self.source_tools,
            "fingerprint_count": len(self.fingerprints),
            "expires_at": self.expires_at, "status": self.status,
            "expired": self.expired, "provenance": self.provenance,
        }


def _row_to_item(row: Any) -> QuarantinedItem:
    return QuarantinedItem(
        id=int(row["id"]), ts=row["ts"], session_id=row["session_id"],
        tool=row["tool"], content=row["content"],
        source_tools=json.loads(row["source_tools"] or "[]"),
        fingerprints=json.loads(row["fingerprints"] or "[]"),
        expires_at=row["expires_at"], status=row["status"],
        provenance=json.loads(row["provenance"] or "{}"),
    )


class QuarantinedMemoryLedger:
    """Storage and lifecycle for quarantined memory writes."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = db_path

    @property
    def conn(self):  # type: ignore[no-untyped-def]
        return connect(self.db_path)

    # --- writing ----------------------------------------------------------
    def quarantine(
        self,
        *,
        content: str,
        tool: str,
        session_id: str | None,
        source_tools: list[str],
        fingerprints: set[str] | list[str],
        ttl_hours: int = 24,
        extra_provenance: dict[str, Any] | None = None,
    ) -> int:
        """Hold a memory write instead of forwarding it upstream.

        ttl_hours of 0 means indefinite-but-flagged (used for already-reviewed
        content) - the item never auto-expires but stays visibly quarantined.
        """
        expires_at = _iso(_now() + timedelta(hours=ttl_hours)) if ttl_hours > 0 else None
        provenance = {
            "captured_at": _iso(_now()),
            "source_tools": source_tools,
            "sink_tool": tool,
            "session_id": session_id,
            "reason": "persistence-tier write carrying untrusted taint",
            **(extra_provenance or {}),
        }
        cur = self.conn.execute(
            """INSERT INTO quarantine
               (ts, session_id, tool, content, source_tools, fingerprints,
                expires_at, status, provenance)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (_iso(_now()), session_id, tool, content,
             json.dumps(sorted(source_tools)), json.dumps(sorted(fingerprints)),
             expires_at, STATUS_QUARANTINED, json.dumps(provenance)),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def save_trusted(self, content: str, session_id: str | None,
                     origin: str = "direct") -> int:
        """Record a clean write as trusted memory (the untainted path)."""
        cur = self.conn.execute(
            "INSERT INTO trusted_memory (ts, session_id, content, origin) VALUES (?,?,?,?)",
            (_iso(_now()), session_id, content, origin),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    # --- reading ----------------------------------------------------------
    def get(self, item_id: int) -> QuarantinedItem | None:
        row = self.conn.execute("SELECT * FROM quarantine WHERE id = ?", (item_id,)).fetchone()
        return _row_to_item(row) if row else None

    def list(self, status: str | None = STATUS_QUARANTINED,
             include_expired: bool = False) -> list[QuarantinedItem]:
        if status:
            rows = self.conn.execute(
                "SELECT * FROM quarantine WHERE status = ? ORDER BY id DESC", (status,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM quarantine ORDER BY id DESC").fetchall()
        items = [_row_to_item(r) for r in rows]
        if not include_expired:
            items = [i for i in items if not i.expired]
        return items

    def find_by_content(self, content: str) -> list[QuarantinedItem]:
        """Exact-content lookup, used by the recall hook."""
        rows = self.conn.execute(
            "SELECT * FROM quarantine WHERE content = ? ORDER BY id DESC", (content,)
        ).fetchall()
        return [_row_to_item(r) for r in rows]

    def trusted_memory(self) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM trusted_memory ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

    # --- the recall hook --------------------------------------------------
    def recall_taint(self, content: str) -> QuarantinedItem | None:
        """If recalled content matches a quarantined item, return it so its taint
        can be re-attached before the content reaches the agent.

        Matching is exact-content first, then a shingle-overlap fallback so that a
        memory tool which reformats or truncates stored text is still recognised.
        """
        exact = self.find_by_content(content)
        if exact:
            return exact[0]

        from agentguard.taint import shingles

        target = shingles(content)
        if not target:
            return None
        best: tuple[float, QuarantinedItem] | None = None
        for item in self.list(status=None, include_expired=True):
            if item.status == STATUS_PROMOTED:
                continue   # promoted items are trusted memory now, by human decision
            stored = shingles(item.content)
            if not stored:
                continue
            shared = target & stored
            if not shared:
                continue
            ratio = len(shared) / min(len(target), len(stored))
            if ratio >= 0.3 and (best is None or ratio > best[0]):
                best = (ratio, item)
        return best[1] if best else None

    # --- lifecycle --------------------------------------------------------
    def promote(self, item_id: int, approved_by: str = "human") -> QuarantinedItem | None:
        """Move a quarantined item into trusted memory. Human action only.

        Provenance is preserved on the promoted record - a promoted memory should
        still be traceable to the untrusted page it came from.
        """
        item = self.get(item_id)
        if item is None:
            return None
        provenance = {**item.provenance, "promoted_by": approved_by,
                      "promoted_at": _iso(_now()),
                      "original_status": item.status}
        self.conn.execute(
            "UPDATE quarantine SET status=?, promoted_at=?, provenance=? WHERE id=?",
            (STATUS_PROMOTED, _iso(_now()), json.dumps(provenance), item_id),
        )
        self.conn.execute(
            "INSERT INTO trusted_memory (ts, session_id, content, origin) VALUES (?,?,?,?)",
            (_iso(_now()), item.session_id, item.content,
             f"promoted_from_quarantine:{item_id}"),
        )
        self.conn.commit()
        return self.get(item_id)

    def deny(self, item_id: int, denied_by: str = "human") -> QuarantinedItem | None:
        item = self.get(item_id)
        if item is None:
            return None
        provenance = {**item.provenance, "denied_by": denied_by, "denied_at": _iso(_now())}
        self.conn.execute(
            "UPDATE quarantine SET status=?, provenance=? WHERE id=?",
            (STATUS_DENIED, json.dumps(provenance), item_id),
        )
        self.conn.commit()
        return self.get(item_id)

    def expire_due(self) -> int:
        """Mark TTL-expired items. Returns how many were expired."""
        count = 0
        for item in self.list(status=STATUS_QUARANTINED, include_expired=True):
            if item.expired:
                self.conn.execute(
                    "UPDATE quarantine SET status=? WHERE id=?", (STATUS_EXPIRED, item.id)
                )
                count += 1
        if count:
            self.conn.commit()
        return count
