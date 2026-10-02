"""Tamper-evident audit log.

Every decision is appended with `entry_hash = sha256(prev_hash || canonical(entry))`,
so removing or editing any row breaks the chain from that point forward and
`verify_chain()` reports exactly where. This is what makes the log evidence
rather than just output.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentguard.db import connect
from agentguard.decision import Decision

GENESIS = "0" * 64


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


#: Every field that is covered by the hash chain, in one place.
HASHED_FIELDS = ("ts", "session_id", "agent", "role", "stage", "tool",
                 "args_digest", "score", "verdict", "reason", "signals", "detail")

#: Hash-chain format versions. Version 1 is every row written before the
#: `source` column existed; version 2 also covers `source`. Each row stores its
#: version, so old rows keep verifying unchanged after the migration, and a row
#: whose version is flipped to dodge coverage no longer matches its stored hash.
HASH_VERSION = 3
_FIELDS_BY_VERSION: dict[int, tuple[str, ...]] = {
    1: HASHED_FIELDS,
    2: HASHED_FIELDS + ("source",),
    # Phase E: which detector/policy made the decision, and in which mode.
    3: HASHED_FIELDS + ("source", "policy_version", "detector_version", "mode"),
}

SOURCE_MCP = "mcp"
SOURCE_HOOK = "hook"


def _normalise(fields: dict[str, Any], keys: tuple[str, ...] = HASHED_FIELDS) -> dict[str, Any]:
    """Coerce field types to what SQLite will hand back on read.

    This exists because of a real bug: an empty signal list made `score` a Python
    int `0`, which canonicalised to `0` on write, while the REAL column returned
    `0.0` on read - so a perfectly intact chain failed verification. Normalising
    both paths through one function makes write and read agree by construction
    rather than by coincidence.
    """
    out: dict[str, Any] = {}
    for key in keys:
        value = fields.get(key)
        if key == "score":
            out[key] = None if value is None else float(value)
        else:
            out[key] = None if value is None else str(value)
    return out


def _canonical(fields: dict[str, Any]) -> str:
    """Stable serialisation - key order must never vary or hashes won't reproduce."""
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str)


def _entry_hash(prev_hash: str, fields: dict[str, Any], version: int = 1) -> str:
    keys = _FIELDS_BY_VERSION.get(int(version))
    if keys is None:
        # An unknown version can't be verified; make it fail rather than pass.
        return "unknown-hash-version"
    return hashlib.sha256(
        (prev_hash + _canonical(_normalise(fields, keys))).encode()
    ).hexdigest()


def digest_args(arguments: Any, limit: int = 300) -> str:
    """Summarise tool arguments for the log.

    Redacted first, then truncated. The audit log has to be readable enough to
    review an incident, without becoming the place the caught credentials pile up -
    so detected secret values are replaced by a type marker before they are stored.
    """
    from agentguard.scanner import redact_arguments

    try:
        text = json.dumps(redact_arguments(arguments), sort_keys=True, default=str)
    except (TypeError, ValueError):
        text = str(redact_arguments(arguments))
    if len(text) > limit:
        return text[:limit] + f"...(+{len(text) - limit} chars)"
    return text


def record(
    *,
    stage: str,
    decision: Decision,
    tool: str | None = None,
    arguments: Any = None,
    session_id: str | None = None,
    agent: str | None = None,
    role: str | None = None,
    detail: str | None = None,
    db_path: str | Path | None = None,
    source: str = SOURCE_MCP,
    policy_version: str | None = None,
    detector_version: str | None = None,
    mode: str | None = None,
) -> int:
    """Append one decision. Returns the new row id.

    `source` says which surface saw the call: the MCP gateway (`mcp`) or a
    Claude Code hook (`hook`). `policy_version` / `detector_version` / `mode`
    (observe | enforce) say which rules and which detection code decided it;
    `detector_version` defaults to the running code's DETECTOR_VERSION. All of
    them are covered by the hash chain.
    """
    from agentguard.versions import DETECTOR_VERSION

    if detector_version is None:
        detector_version = DETECTOR_VERSION
    conn = connect(db_path)
    row = conn.execute("SELECT entry_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = row["entry_hash"] if row else GENESIS

    entry = {
        "ts": _now(),
        "session_id": session_id,
        "agent": agent,
        "role": role,
        "stage": stage,
        "tool": tool,
        "args_digest": digest_args(arguments) if arguments is not None else None,
        "score": round(float(decision.score), 4),
        "verdict": decision.verdict.value,
        "reason": decision.reason,
        "signals": _canonical([s.to_dict() for s in decision.signals]),
        "detail": detail,
        "source": source,
        "policy_version": policy_version,
        "detector_version": detector_version,
        "mode": mode,
    }
    entry_hash = _entry_hash(prev_hash, entry, HASH_VERSION)

    cur = conn.execute(
        """INSERT INTO audit (ts, session_id, agent, role, stage, tool, args_digest,
                              score, verdict, reason, signals, detail, prev_hash,
                              entry_hash, source, hash_v, policy_version,
                              detector_version, mode)
           VALUES (:ts,:session_id,:agent,:role,:stage,:tool,:args_digest,
                   :score,:verdict,:reason,:signals,:detail,:prev_hash,:entry_hash,
                   :source,:hash_v,:policy_version,:detector_version,:mode)""",
        {**entry, "prev_hash": prev_hash, "entry_hash": entry_hash,
         "hash_v": HASH_VERSION},
    )
    conn.commit()
    return int(cur.lastrowid)


def last(n: int = 20, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    conn = connect(db_path)
    rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (n,)).fetchall()
    return [dict(r) for r in rows]


def session_timeline(session_id: str, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    """All events for one session, oldest first - the attack-chain view."""
    conn = connect(db_path)
    rows = conn.execute(
        "SELECT * FROM audit WHERE session_id = ? ORDER BY id ASC", (session_id,)
    ).fetchall()
    return [dict(r) for r in rows]


def verify_chain(db_path: str | Path | None = None) -> tuple[bool, int | None]:
    """Recompute every hash. Returns (intact, first_broken_row_id)."""
    conn = connect(db_path)
    prev_hash = GENESIS
    for r in conn.execute("SELECT * FROM audit ORDER BY id ASC"):
        version = r["hash_v"]
        entry = {key: r[key] for key in _FIELDS_BY_VERSION.get(version, HASHED_FIELDS)}
        expect = _entry_hash(prev_hash, entry, version)
        if r["prev_hash"] != prev_hash or r["entry_hash"] != expect:
            return False, int(r["id"])
        prev_hash = r["entry_hash"]
    return True, None


def stats(db_path: str | Path | None = None) -> dict[str, int]:
    """Counters for the dashboard header."""
    conn = connect(db_path)
    def one(sql: str, *a: Any) -> int:
        return int(conn.execute(sql, a).fetchone()[0])
    return {
        "total": one("SELECT COUNT(*) FROM audit"),
        "blocked": one("SELECT COUNT(*) FROM audit WHERE verdict='BLOCK'"),
        "review": one("SELECT COUNT(*) FROM audit WHERE verdict='REVIEW'"),
        "allowed": one("SELECT COUNT(*) FROM audit WHERE verdict='ALLOW'"),
        "today": one("SELECT COUNT(*) FROM audit WHERE substr(ts,1,10)=?",
                     datetime.now(timezone.utc).date().isoformat()),
        "pending_reviews": one("SELECT COUNT(*) FROM review_queue WHERE status='pending'"),
        "quarantined": one("SELECT COUNT(*) FROM quarantine WHERE status='quarantined'"),
        "agents": one("SELECT COUNT(DISTINCT agent) FROM audit WHERE agent IS NOT NULL"),
    }
