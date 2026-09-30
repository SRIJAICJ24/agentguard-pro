"""SQLite storage. One file, one schema, all stages.

AgentGuard is local-first: everything lives in a single SQLite file under
`~/.agentguard/` (overridable, which is what the tests use). Tables are created
lazily so no migration step is needed between stages.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

_LOCAL = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    session_id  TEXT,
    agent       TEXT,
    role        TEXT,
    stage       TEXT    NOT NULL,
    tool        TEXT,
    args_digest TEXT,
    score       REAL,
    verdict     TEXT    NOT NULL,
    reason      TEXT,
    signals     TEXT,
    detail      TEXT,
    prev_hash   TEXT    NOT NULL,
    entry_hash  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_pins (
    tool         TEXT PRIMARY KEY,
    schema_hash  TEXT NOT NULL,
    description  TEXT,
    pinned_at    TEXT NOT NULL,
    approved     INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS review_queue (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    session_id  TEXT,
    agent       TEXT,
    kind        TEXT    NOT NULL,
    tool        TEXT,
    payload     TEXT,
    score       REAL,
    reason      TEXT,
    status      TEXT    NOT NULL DEFAULT 'pending',
    resolved_at TEXT,
    resolved_by TEXT
);

CREATE TABLE IF NOT EXISTS quarantine (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT    NOT NULL,
    session_id    TEXT,
    tool          TEXT,
    content       TEXT    NOT NULL,
    source_tools  TEXT,
    fingerprints  TEXT,
    expires_at    TEXT,
    status        TEXT    NOT NULL DEFAULT 'quarantined',
    promoted_at   TEXT,
    provenance    TEXT
);

CREATE TABLE IF NOT EXISTS trusted_memory (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    session_id  TEXT,
    content     TEXT NOT NULL,
    origin      TEXT NOT NULL DEFAULT 'direct'
);

-- Stage 7C: per-session task scope, written only by the human-facing CLI.
CREATE TABLE IF NOT EXISTS task_scope (
    session_id  TEXT PRIMARY KEY,
    tools       TEXT NOT NULL,
    goal        TEXT,
    set_by      TEXT,
    set_at      TEXT NOT NULL
);

-- Stage 7D: locks set from the CLI and honoured by every running gateway.
-- scope is '*' for a global lock, otherwise a session id.
CREATE TABLE IF NOT EXISTS locks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scope        TEXT NOT NULL,
    reason       TEXT,
    locked_by    TEXT,
    locked_at    TEXT NOT NULL,
    released_at  TEXT,
    released_by  TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
CREATE INDEX IF NOT EXISTS idx_locks_active ON locks(released_at, scope);
CREATE INDEX IF NOT EXISTS idx_review_status ON review_queue(status);
CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status);
"""


def default_db_path() -> Path:
    """Honour AGENTGUARD_HOME so tests and parallel instances stay isolated.

    Resolved through `config.agentguard_home()` so there is exactly one definition
    of where local state lives.
    """
    from agentguard.config import agentguard_home

    return agentguard_home() / "agentguard.db"


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    """Return a per-thread connection, creating the schema on first use.

    Cached per (thread, path) because SQLite connections are not shareable
    across threads and the dashboard runs in a different thread to the gateway.
    """
    p = Path(path) if path is not None else default_db_path()
    cache: dict[str, sqlite3.Connection] = getattr(_LOCAL, "conns", None) or {}
    key = str(p)
    if key in cache:
        return cache[key]

    if str(p) != ":memory:":
        p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    cache[key] = conn
    _LOCAL.conns = cache
    return conn


def reset(path: str | Path | None = None) -> None:
    """Drop every row. Used by tests and `agentguard reset`."""
    conn = connect(path)
    for table in ("audit", "tool_pins", "review_queue", "quarantine", "trusted_memory",
                  "task_scope", "locks"):
        conn.execute(f"DELETE FROM {table}")
    conn.commit()
