"""`agentguard report` - turn the audit log into a false-positive number.

Every false-positive figure quoted for this project so far has been synthetic: the
simulator's six benign controls and the scanner's prose tests. Those are a floor,
not a measurement. This module exists so that a week of real observe-mode traffic
produces an actual number instead of an impression.

What counts as a false-positive candidate
-----------------------------------------
A decision is a candidate when both hold:

  1. The gateway did not allow it - it was REVIEW'd or BLOCK'd and landed in the
     review queue.
  2. A human then cleared it: the queue entry was approved (or approved and
     consumed by the retried call), or a quarantined memory item was promoted.

That is a human overruling the gateway, which is the closest observable proxy for
"the gateway was wrong".

The "without any follow-up incident" qualifier matters, and is applied rather than
assumed: if a BLOCK follows the clearance in the same session, the approval may have
been one step of a real attack chain that was caught downstream, so counting it as a
false positive would be wrong. Those are reported separately as "cleared, but
followed by a block" for manual reading rather than folded into either bucket.

That check is bounded in time (INCIDENT_WINDOW), and the bound is load-bearing. An
MCP session is the whole client connection, which for Claude Code can stay open for
hours; "any block later in the same session" would therefore disqualify almost every
genuine false positive, biasing the headline number toward zero - the worst failure
mode for the one figure this stage exists to produce. Only a block close enough in
time to plausibly be downstream of the clearance counts as an incident.

They are called *candidates* throughout, never "confirmed false positives". This
module can only see that a human disagreed with the gateway - it cannot see whether
the human was right.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agentguard.db import connect

# Only TOOL_PREPARE rows gate a call. TOOL_RESULT rows are taint bookkeeping and are
# always ALLOW, so counting them would inflate the allow rate and understate the
# block rate - the exact number this report exists to get right.
CALL_STAGE = "TOOL_PREPARE"
RESULT_STAGE = "TOOL_RESULT"

CLEARED_STATUSES = ("approved", "consumed")

# How soon after a clearance a BLOCK still counts as downstream of it. See the module
# docstring: an unbounded "same session" test would swallow nearly every real false
# positive, because one MCP session can span hours of unrelated work.
INCIDENT_WINDOW = timedelta(minutes=15)

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhdw]?)\s*$", re.I)
_DURATION_UNITS = {
    "s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks",
}

DEFAULT_SINCE = "7d"


def parse_duration(text: str) -> timedelta:
    """Parse '7d', '24h', '90m', '2w'. A bare number means days."""
    match = _DURATION_RE.match(str(text))
    if not match:
        raise ValueError(
            f"could not read duration {text!r}; use forms like 7d, 24h, 90m, 2w"
        )
    amount, unit = float(match.group(1)), (match.group(2) or "d").lower()
    if amount <= 0:
        raise ValueError(f"duration must be positive, got {text!r}")
    return timedelta(**{_DURATION_UNITS[unit]: amount})


def _parse_ts(value: str | None) -> datetime | None:
    """Parse a stored ISO timestamp, tolerating both precisions used in the schema."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass
class FPCandidate:
    """One decision a human overruled."""

    review_id: int
    kind: str
    tool: str | None
    ts: str
    resolved_at: str | None
    resolved_by: str | None
    score: float | None
    reason: str | None
    session_id: str | None
    followed_by_block: bool = False
    signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "review_id": self.review_id, "kind": self.kind, "tool": self.tool,
            "ts": self.ts, "resolved_at": self.resolved_at,
            "resolved_by": self.resolved_by, "score": self.score,
            "reason": self.reason, "session_id": self.session_id,
            "followed_by_block": self.followed_by_block, "signals": self.signals,
        }


@dataclass
class Report:
    since: datetime
    until: datetime
    window: str

    total_calls: int = 0
    allow: int = 0
    review: int = 0
    block: int = 0
    taint_events: int = 0

    signal_counts: list[tuple[str, int]] = field(default_factory=list)

    reviews_total: int = 0
    reviews_pending: int = 0
    reviews_cleared: int = 0
    reviews_denied: int = 0

    fp_candidates: list[FPCandidate] = field(default_factory=list)
    cleared_with_incident: list[FPCandidate] = field(default_factory=list)

    agents: list[tuple[str, int]] = field(default_factory=list)

    # Per surface: {"mcp": {...}, "hook": {...}} - calls, verdict counts, top
    # signals, and false-positive candidates (hook asks cleared at Claude Code's
    # prompt count for the hook surface).
    by_source: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Phase E: (detector_version, policy_version, calls) for the gated calls in
    # the window. More than one entry means the numbers mix detection logic or
    # rules, and the report says so.
    versions: list[tuple[str, str, int]] = field(default_factory=list)
    # Phase E: human labels -> precision (agentguard.labels.Precision).
    precision: Any = None
    # (rule, count) for calls refused by a hard-enforced rule - these were
    # actually stopped, even in observe mode, so they're reported apart.
    hard_enforced: list[tuple[str, int]] = field(default_factory=list)

    @property
    def mixed_versions(self) -> bool:
        return len(self.versions) > 1

    # --- derived ----------------------------------------------------------
    def _pct(self, n: int) -> float:
        return (n / self.total_calls * 100) if self.total_calls else 0.0

    @property
    def allow_pct(self) -> float:
        return self._pct(self.allow)

    @property
    def review_pct(self) -> float:
        return self._pct(self.review)

    @property
    def block_pct(self) -> float:
        return self._pct(self.block)

    @property
    def interrupted(self) -> int:
        """Calls the gateway did not simply allow."""
        return self.review + self.block

    @property
    def fp_rate(self) -> float:
        """Candidates as a share of all calls - the headline number.

        Reported against total calls, not against interrupted calls, because the
        question being answered is "how often does this get in my way per unit of
        work", not "how often is an interruption wrong".
        """
        return self._pct(len(self.fp_candidates))

    @property
    def overrule_rate(self) -> float:
        """Share of interruptions a human overruled."""
        return (len(self.fp_candidates) / self.interrupted * 100) if self.interrupted else 0.0

    @property
    def enough_data(self) -> bool:
        """Whether the window holds enough traffic for the rate to mean anything."""
        return self.total_calls >= 100

    def to_dict(self) -> dict[str, Any]:
        return {
            "window": self.window,
            "since": self.since.isoformat(),
            "until": self.until.isoformat(),
            "total_calls": self.total_calls,
            "allow": self.allow, "review": self.review, "block": self.block,
            "allow_pct": round(self.allow_pct, 2),
            "review_pct": round(self.review_pct, 2),
            "block_pct": round(self.block_pct, 2),
            "taint_events": self.taint_events,
            "signal_counts": [{"signal": s, "count": c} for s, c in self.signal_counts],
            "reviews": {
                "total": self.reviews_total, "pending": self.reviews_pending,
                "cleared": self.reviews_cleared, "denied": self.reviews_denied,
            },
            "false_positive_candidates": [c.to_dict() for c in self.fp_candidates],
            "cleared_with_incident": [c.to_dict() for c in self.cleared_with_incident],
            "fp_rate_pct": round(self.fp_rate, 3),
            "overrule_rate_pct": round(self.overrule_rate, 2),
            "enough_data": self.enough_data,
            "agents": [{"agent": a, "calls": n} for a, n in self.agents],
            "by_source": self.by_source,
            "versions": [{"detector_version": d, "policy_version": p, "calls": n}
                         for d, p, n in self.versions],
            "mixed_versions": self.mixed_versions,
            "precision": self.precision.to_dict() if self.precision is not None else None,
            "hard_enforced": [{"rule": r, "count": n} for r, n in self.hard_enforced],
        }


def build(since: str | timedelta = DEFAULT_SINCE,
          db_path: str | Path | None = None,
          now: datetime | None = None,
          incident_window: timedelta = INCIDENT_WINDOW) -> Report:
    """Read the audit log and review queue, and compute the report."""
    delta = since if isinstance(since, timedelta) else parse_duration(since)
    until = now or datetime.now(timezone.utc)
    start = until - delta
    window = since if isinstance(since, str) else str(delta)

    conn = connect(db_path)
    report = Report(since=start, until=until, window=window)
    start_iso = start.isoformat()

    # --- verdict counts over gating decisions only ------------------------
    rows = conn.execute(
        "SELECT verdict, COUNT(*) AS n FROM audit "
        "WHERE stage = ? AND ts >= ? GROUP BY verdict",
        (CALL_STAGE, start_iso),
    ).fetchall()
    for row in rows:
        count = int(row["n"])
        report.total_calls += count
        if row["verdict"] == "ALLOW":
            report.allow += count
        elif row["verdict"] == "REVIEW":
            report.review += count
        elif row["verdict"] == "BLOCK":
            report.block += count

    report.taint_events = int(conn.execute(
        "SELECT COUNT(*) FROM audit WHERE stage = ? AND ts >= ?",
        (RESULT_STAGE, start_iso),
    ).fetchone()[0])

    report.agents = [
        (r["agent"], int(r["n"])) for r in conn.execute(
            "SELECT agent, COUNT(*) AS n FROM audit "
            "WHERE stage = ? AND ts >= ? AND agent IS NOT NULL "
            "GROUP BY agent ORDER BY n DESC",
            (CALL_STAGE, start_iso),
        ).fetchall()
    ]

    # --- which signals actually fire --------------------------------------
    counts: dict[str, int] = {}
    for row in conn.execute(
        "SELECT signals FROM audit WHERE stage = ? AND ts >= ? AND signals IS NOT NULL",
        (CALL_STAGE, start_iso),
    ):
        try:
            signals = json.loads(row["signals"] or "[]")
        except (ValueError, TypeError):
            continue
        # Count each signal name once per decision, so one noisy call cannot
        # dominate the ranking.
        for name in {s.get("name") for s in signals if isinstance(s, dict)}:
            if name:
                counts[name] = counts.get(name, 0) + 1
    report.signal_counts = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))

    # --- review queue outcomes --------------------------------------------
    queue_rows = conn.execute(
        "SELECT * FROM review_queue WHERE ts >= ? ORDER BY id ASC", (start_iso,)
    ).fetchall()

    # Every BLOCK, indexed by session, so the follow-up check is one pass not N queries.
    blocks_by_session: dict[str, list[datetime]] = {}
    for row in conn.execute(
        "SELECT session_id, ts FROM audit WHERE verdict = 'BLOCK' AND ts >= ?",
        (start_iso,),
    ):
        parsed = _parse_ts(row["ts"])
        if row["session_id"] and parsed:
            blocks_by_session.setdefault(row["session_id"], []).append(parsed)

    for row in queue_rows:
        report.reviews_total += 1
        status = row["status"]
        if status == "pending":
            report.reviews_pending += 1
            continue
        if status == "denied":
            report.reviews_denied += 1
            continue
        if status not in CLEARED_STATUSES:
            continue

        report.reviews_cleared += 1
        try:
            payload = json.loads(row["payload"] or "{}")
        except (ValueError, TypeError):
            payload = {}
        signals = [s.get("name") for s in payload.get("signals", [])
                   if isinstance(s, dict) and s.get("name")]

        resolved = _parse_ts(row["resolved_at"])
        followed = False
        if resolved and row["session_id"]:
            deadline = resolved + incident_window
            followed = any(resolved < ts <= deadline
                           for ts in blocks_by_session.get(row["session_id"], []))

        candidate = FPCandidate(
            review_id=int(row["id"]), kind=row["kind"], tool=row["tool"],
            ts=row["ts"], resolved_at=row["resolved_at"],
            resolved_by=row["resolved_by"], score=row["score"],
            reason=row["reason"], session_id=row["session_id"],
            followed_by_block=followed, signals=signals,
        )
        if followed:
            report.cleared_with_incident.append(candidate)
        else:
            report.fp_candidates.append(candidate)

    report.by_source = _by_source(conn, start_iso, report)
    report.versions = version_mix(conn, start_iso)
    hard: dict[str, int] = {}
    for name, count in report.signal_counts:
        if name.startswith("hard_enforce:"):
            hard[name[len("hard_enforce:"):]] = count
    report.hard_enforced = sorted(hard.items(), key=lambda kv: (-kv[1], kv[0]))

    from agentguard.labels import precision as label_precision

    report.precision = label_precision(start_iso, db_path)
    return report


UNVERSIONED = "unversioned"


def version_mix(conn: Any, start_iso: str) -> list[tuple[str, str, int]]:
    """(detector_version, policy_version, calls) for gated calls since start.

    Rows written before versions were recorded show as "unversioned": they may or
    may not match the current code, and the report can't tell, so they count as a
    version of their own rather than being assumed to match.
    """
    rows = conn.execute(
        "SELECT detector_version, policy_version, COUNT(*) AS n FROM audit "
        "WHERE stage = ? AND ts >= ? GROUP BY detector_version, policy_version "
        "ORDER BY n DESC",
        (CALL_STAGE, start_iso),
    ).fetchall()
    return [(r["detector_version"] or UNVERSIONED, r["policy_version"] or UNVERSIONED,
             int(r["n"])) for r in rows]


def render_versions(report: Report, colorize: Any = None) -> str:
    def paint(text: str, key: str) -> str:
        return colorize(text, key) if colorize else text

    if not report.versions:
        return ""
    lines = ["  versions        : " + "; ".join(
        f"detector {d} / policy {p}: {n} calls" for d, p, n in report.versions)]
    if report.mixed_versions:
        lines.append(paint(
            f"  WARNING: {len(report.versions)} detector/policy versions in this window. "
            f"These numbers mix different detection logic or rules - compare the "
            f"periods separately (narrow --since) before trusting a single figure.",
            "REVIEW"))
    return "\n".join(lines)


#: Review-queue kinds that come from the Claude Code hook surface.
HOOK_REVIEW_KINDS = ("hook_ask",)


def _by_source(conn: Any, start_iso: str, report: Report) -> dict[str, dict[str, Any]]:
    """Verdicts, top signals and FP candidates per surface (mcp gateway / hook)."""
    out: dict[str, dict[str, Any]] = {}
    for row in conn.execute(
        "SELECT source, verdict, COUNT(*) AS n FROM audit "
        "WHERE stage = ? AND ts >= ? GROUP BY source, verdict",
        (CALL_STAGE, start_iso),
    ):
        bucket = out.setdefault(row["source"] or "mcp", {
            "calls": 0, "allow": 0, "review": 0, "block": 0, "signals": {},
            "fp_candidates": 0,
        })
        n = int(row["n"])
        bucket["calls"] += n
        key = str(row["verdict"]).lower()
        if key in ("allow", "review", "block"):
            bucket[key] += n
    for row in conn.execute(
        "SELECT source, signals FROM audit WHERE stage = ? AND ts >= ? AND signals IS NOT NULL",
        (CALL_STAGE, start_iso),
    ):
        bucket = out.get(row["source"] or "mcp")
        if bucket is None:
            continue
        try:
            names = {s.get("name") for s in json.loads(row["signals"] or "[]")
                     if isinstance(s, dict)}
        except (ValueError, TypeError):
            continue
        for name in names:
            if name:
                bucket["signals"][name] = bucket["signals"].get(name, 0) + 1
    for c in report.fp_candidates:
        src = "hook" if c.kind in HOOK_REVIEW_KINDS else "mcp"
        out.setdefault(src, {"calls": 0, "allow": 0, "review": 0, "block": 0,
                             "signals": {}, "fp_candidates": 0})["fp_candidates"] += 1
    for bucket in out.values():
        bucket["top_signals"] = sorted(bucket.pop("signals").items(),
                                       key=lambda kv: (-kv[1], kv[0]))[:10]
    return out


def render_by_source(report: Report, colorize: Any = None) -> str:
    def paint(text: str, key: str) -> str:
        return colorize(text, key) if colorize else text

    lines = [paint("  BY SOURCE", "bold"),
             "  (mcp = through the MCP gateway, hook = Claude Code's own tools)"]
    if not report.by_source:
        lines.append("    no gated calls in this window")
        return "\n".join(lines)
    for source in sorted(report.by_source):
        b = report.by_source[source]
        calls = b["calls"] or 1
        lines.append("")
        lines.append(f"  {paint(source, 'bold')}: {b['calls']} calls - "
                     f"ALLOW {b['allow']} ({b['allow'] / calls:.0%}), "
                     f"REVIEW {b['review']} ({b['review'] / calls:.0%}), "
                     f"BLOCK {b['block']} ({b['block'] / calls:.0%}); "
                     f"FP candidates {b['fp_candidates']}")
        for name, count in b["top_signals"][:6]:
            lines.append(f"      {name}  {count}")
    return "\n".join(lines)


def render(report: Report, colorize: Any = None) -> str:
    """Format the report for a terminal."""
    def paint(text: str, key: str) -> str:
        return colorize(text, key) if colorize else text

    lines: list[str] = []
    lines.append(f"  window          : last {report.window} "
                 f"({report.since:%Y-%m-%d %H:%M} to {report.until:%Y-%m-%d %H:%M} UTC)")
    lines.append(f"  calls gated     : {report.total_calls}")

    if report.total_calls == 0:
        lines.append("")
        lines.append(paint("  no traffic in this window", "dim"))
        lines.append(paint("  run some real sessions through the gateway in observe "
                           "mode first, then re-run this.", "dim"))
        return "\n".join(lines)

    lines.append(f"  taint events    : {report.taint_events} "
                 f"(untrusted results fingerprinted)")
    versions = render_versions(report, colorize)
    if versions:
        lines.append(versions)
    if report.hard_enforced:
        total = sum(n for _r, n in report.hard_enforced)
        lines.append(paint(f"  HARD-ENFORCED   : {total} call(s) actually blocked, even in "
                           f"observe mode", "BLOCK"))
        for rule, n in report.hard_enforced:
            lines.append(f"      {rule}  {n}")
    lines.append("")
    for label, count, pct, key in (
        ("ALLOW ", report.allow, report.allow_pct, "ALLOW"),
        ("REVIEW", report.review, report.review_pct, "REVIEW"),
        ("BLOCK ", report.block, report.block_pct, "BLOCK"),
    ):
        bar = "#" * int(round(pct / 2.5))
        lines.append(f"  {paint(label, key)}  {count:6d}  {pct:5.1f}%  {bar}")

    # --- signals ---
    lines.append("")
    lines.append("  top signals by how many decisions they appeared in:")
    if not report.signal_counts:
        lines.append("    (none fired)")
    else:
        width = max(len(s) for s, _ in report.signal_counts[:10])
        for name, count in report.signal_counts[:10]:
            share = count / report.total_calls * 100
            lines.append(f"    {name.ljust(width)}  {count:5d}  ({share:.1f}% of calls)")

    # --- review outcomes ---
    lines.append("")
    lines.append(f"  review queue    : {report.reviews_total} queued "
                 f"({report.reviews_cleared} cleared, {report.reviews_denied} denied, "
                 f"{report.reviews_pending} still pending)")

    # --- the number this exists for ---
    lines.append("")
    lines.append(paint("  FALSE-POSITIVE CANDIDATES", "bold"))
    lines.append(f"  (interruptions a human cleared, with no block in the same "
                 f"session within {int(INCIDENT_WINDOW.total_seconds() // 60)}m after)")
    lines.append("")
    if not report.fp_candidates:
        lines.append("    none")
    else:
        for c in report.fp_candidates:
            lines.append(f"    #{c.review_id} {c.ts[11:19]}  {c.tool or '-'}  "
                         f"score {c.score or 0:.2f}  cleared by {c.resolved_by or '?'}")
            if c.reason:
                lines.append(f"        {paint(c.reason[:96], 'dim')}")
            if c.signals:
                lines.append(f"        {paint('signals: ' + ', '.join(c.signals), 'dim')}")

    lines.append("")
    lines.append(f"    candidates            : {len(report.fp_candidates)}")
    lines.append(f"    as share of all calls : {report.fp_rate:.2f}%")
    lines.append(f"    as share of interrupts: {report.overrule_rate:.1f}%  "
                 f"({len(report.fp_candidates)}/{report.interrupted})")

    if report.cleared_with_incident:
        lines.append("")
        lines.append(paint(f"  cleared BUT followed closely by a block in the same "
                           f"session: {len(report.cleared_with_incident)}", "REVIEW"))
        lines.append("  (not counted as false positives - read these by hand, the "
                     "approval may have been one step of a real chain)")
        for c in report.cleared_with_incident:
            lines.append(f"    #{c.review_id} {c.tool or '-'}  session {(c.session_id or '')[:8]}")

    lines.append("")
    if not report.enough_data:
        lines.append(paint(f"  NOTE: only {report.total_calls} calls in this window. "
                           f"Treat this rate as indicative, not measured -", "REVIEW"))
        lines.append(paint("  a few hundred calls of real traffic is the point at "
                           "which it starts to mean something.", "REVIEW"))
    else:
        lines.append(paint(f"  Based on {report.total_calls} gated calls.", "dim"))
    lines.append(paint("  These are candidates, not confirmed errors: the report sees "
                       "that a human", "dim"))
    lines.append(paint("  overruled the gateway, not whether the human was right.",
                       "dim"))
    if report.precision is not None:
        from agentguard.labels import render_precision

        lines.append("")
        lines.append(render_precision(report.precision, colorize))
    return "\n".join(lines)
