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
    entry_hash  TEXT    NOT NULL,
    source      TEXT    NOT NULL DEFAULT 'mcp',
    hash_v      INTEGER NOT NULL DEFAULT 1,
    policy_version   TEXT,
    detector_version TEXT,
    mode        TEXT,
    workspace   TEXT
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

-- Phase E: human labels for REVIEW/BLOCK decisions. Deliberately a separate
-- table keyed by audit row id: labelling happens after the fact and must never
-- touch the hash-chained audit log.
CREATE TABLE IF NOT EXISTS fp_labels (
    audit_id    INTEGER PRIMARY KEY,
    label       TEXT NOT NULL CHECK (label IN ('tp', 'fp', 'unsure')),
    labeled_at  TEXT NOT NULL,
    labeled_by  TEXT
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
    migrate(conn)
    conn.commit()
    cache[key] = conn
    _LOCAL.conns = cache
    return conn


#: Columns added after the first release, with the SQL that adds them to an
#: existing database. `CREATE TABLE IF NOT EXISTS` never alters a table that
#: already exists, so databases created before a column was introduced get it
#: here.
_AUDIT_MIGRATIONS: tuple[tuple[str, str], ...] = (
    # Where the decision came from: the MCP gateway or a Claude Code hook. Every
    # row written before hooks existed came from the gateway, so 'mcp' is the
    # true value for them, not a guess.
    ("source", "ALTER TABLE audit ADD COLUMN source TEXT NOT NULL DEFAULT 'mcp'"),
    # Hash-chain format version. Version 1 rows were hashed without `source`, so
    # they keep verifying under the version-1 field set; new rows are version 2
    # and cover `source` too (see audit.py).
    ("hash_v", "ALTER TABLE audit ADD COLUMN hash_v INTEGER NOT NULL DEFAULT 1"),
    # Phase E: which detector and policy made the decision, and in which mode.
    # NULL for rows written before this existed - they genuinely weren't
    # recorded, and report shows them as "unversioned" rather than guessing.
    ("policy_version", "ALTER TABLE audit ADD COLUMN policy_version TEXT"),
    ("detector_version", "ALTER TABLE audit ADD COLUMN detector_version TEXT"),
    ("mode", "ALTER TABLE audit ADD COLUMN mode TEXT"),
    # F2: short workspace label for hook rows (never a full path). NULL for
    # gateway rows and for rows written before it existed.
    ("workspace", "ALTER TABLE audit ADD COLUMN workspace TEXT"),
)


def migrate(conn: sqlite3.Connection) -> list[str]:
    """Bring an existing database up to the current schema. Idempotent."""
    have = {row[1] for row in conn.execute("PRAGMA table_info(audit)")}
    added: list[str] = []
    for column, sql in _AUDIT_MIGRATIONS:
        if column not in have:
            conn.execute(sql)
            added.append(column)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_source ON audit(source)")
    return added


def reset(path: str | Path | None = None) -> None:
    """Drop every row. Used by tests and `agentguard reset`."""
    conn = connect(path)
    for table in ("audit", "tool_pins", "review_queue", "quarantine", "trusted_memory",
                  "task_scope", "locks", "fp_labels"):
        conn.execute(f"DELETE FROM {table}")
    conn.commit()
