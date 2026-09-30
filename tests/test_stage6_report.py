"""Stage 6 - `agentguard report`.

A synthetic audit log with a known mix of ALLOW / REVIEW / BLOCK entries and known
review-queue outcomes, asserting the counts come out right and that the
cleared-without-incident entries are identified correctly.

The false-positive number is the thing this whole project has been waiting on, so
the arithmetic behind it gets tested rather than eyeballed.
"""

from __future__ import annotations

import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentguard import report as report_mod
from agentguard.decision import Decision, Signal, Verdict


@pytest.fixture
def db_path():
    directory = tempfile.mkdtemp(prefix="agentguard-report-")
    try:
        yield str(Path(directory) / "test.db")
    finally:
        shutil.rmtree(directory, ignore_errors=True)


NOW = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)


def _at(minutes_ago: float) -> str:
    return (NOW - timedelta(minutes=minutes_ago)).isoformat(timespec="microseconds")


def seed(db_path, *, stage="TOOL_PREPARE", verdict=Verdict.ALLOW, tool="filesystem.read",
         minutes_ago=10.0, session="s1", agent="test-agent", score=0.0,
         signals=None, reason=""):
    """Insert one audit row at a controlled timestamp.

    Written through `audit.record` and then back-dated, so the rows are shaped
    exactly like real ones rather than hand-built.
    """
    from agentguard import audit
    from agentguard.db import connect

    row_id = audit.record(
        stage=stage,
        decision=Decision(verdict, score, signals or [], reason),
        tool=tool, arguments={"path": "x"}, session_id=session, agent=agent,
        db_path=db_path,
    )
    conn = connect(db_path)
    conn.execute("UPDATE audit SET ts = ? WHERE id = ?", (_at(minutes_ago), row_id))
    conn.commit()
    return row_id


def queue(db_path, *, tool="filesystem.read", status="pending", minutes_ago=9.0,
          resolved_minutes_ago=8.0, session="s1", score=0.4, kind="tool_call",
          reason="denylisted path", signals=None):
    """Insert one review-queue entry with a controlled timestamp and outcome."""
    from agentguard.db import connect
    from agentguard.review_queue import ReviewQueue

    q = ReviewQueue(db_path)
    item_id = q.enqueue(
        kind=kind, tool=tool,
        payload={"args_digest": "{}", "signals": [{"name": s} for s in (signals or [])]},
        score=score, reason=reason, session_id=session, agent="test-agent",
    )
    conn = connect(db_path)
    if status == "pending":
        conn.execute("UPDATE review_queue SET ts = ? WHERE id = ?",
                     (_at(minutes_ago), item_id))
    else:
        conn.execute(
            "UPDATE review_queue SET ts = ?, status = ?, resolved_at = ?, "
            "resolved_by = ? WHERE id = ?",
            (_at(minutes_ago), status, _at(resolved_minutes_ago), "human", item_id),
        )
    conn.commit()
    return item_id


# =====================================================================
# duration parsing
# =====================================================================
@pytest.mark.parametrize("text,expected", [
    ("7d", timedelta(days=7)),
    ("24h", timedelta(hours=24)),
    ("90m", timedelta(minutes=90)),
    ("2w", timedelta(weeks=2)),
    ("30s", timedelta(seconds=30)),
    ("3", timedelta(days=3)),        # bare number means days
])
def test_parse_duration(text, expected):
    assert report_mod.parse_duration(text) == expected


@pytest.mark.parametrize("bad", ["", "soon", "-3d", "0h", "7y"])
def test_parse_duration_rejects_nonsense(bad):
    with pytest.raises(ValueError):
        report_mod.parse_duration(bad)


# =====================================================================
# counts
# =====================================================================
def test_counts_a_known_mix(db_path):
    """6 ALLOW, 3 REVIEW, 1 BLOCK - the arithmetic must come out exactly."""
    for _ in range(6):
        seed(db_path, verdict=Verdict.ALLOW)
    for _ in range(3):
        seed(db_path, verdict=Verdict.REVIEW, score=0.4)
    seed(db_path, verdict=Verdict.BLOCK, score=0.8)

    report = report_mod.build("7d", db_path, now=NOW)

    assert report.total_calls == 10
    assert (report.allow, report.review, report.block) == (6, 3, 1)
    assert report.allow_pct == 60.0
    assert report.review_pct == 30.0
    assert report.block_pct == 10.0
    assert report.interrupted == 4


def test_tool_result_rows_are_excluded_from_call_counts(db_path):
    """TOOL_RESULT rows are taint bookkeeping, not gated calls.

    Counting them would inflate the allow rate and understate the block rate -
    precisely the number this report exists to get right.
    """
    seed(db_path, stage="TOOL_PREPARE", verdict=Verdict.BLOCK)
    for _ in range(9):
        seed(db_path, stage="TOOL_RESULT", verdict=Verdict.ALLOW, tool="web.search")

    report = report_mod.build("7d", db_path, now=NOW)

    assert report.total_calls == 1, "only gating decisions count as calls"
    assert report.block_pct == 100.0
    assert report.taint_events == 9


def test_window_excludes_older_entries(db_path):
    seed(db_path, verdict=Verdict.ALLOW, minutes_ago=30)          # inside 1h
    seed(db_path, verdict=Verdict.BLOCK, minutes_ago=60 * 24 * 3)  # 3 days ago

    hour = report_mod.build("1h", db_path, now=NOW)
    assert hour.total_calls == 1
    assert hour.block == 0

    week = report_mod.build("7d", db_path, now=NOW)
    assert week.total_calls == 2
    assert week.block == 1


def test_default_window_is_seven_days(db_path):
    seed(db_path, minutes_ago=60 * 24 * 6)      # 6 days ago -> inside
    seed(db_path, minutes_ago=60 * 24 * 8)      # 8 days ago -> outside
    assert report_mod.build(db_path=db_path, now=NOW).total_calls == 1


def test_empty_log_does_not_divide_by_zero(db_path):
    report = report_mod.build("7d", db_path, now=NOW)
    assert report.total_calls == 0
    assert report.allow_pct == 0.0
    assert report.fp_rate == 0.0
    assert report.overrule_rate == 0.0
    assert "no traffic" in report_mod.render(report)


# =====================================================================
# signal ranking
# =====================================================================
def test_top_signals_by_frequency(db_path):
    for _ in range(5):
        seed(db_path, verdict=Verdict.BLOCK,
             signals=[Signal("path:**/.ssh/**", 0.8, "d")])
    for _ in range(2):
        seed(db_path, verdict=Verdict.REVIEW,
             signals=[Signal("injection:instruction_override", 0.35, "d")])
    seed(db_path, verdict=Verdict.REVIEW, signals=[Signal("taint:exfiltration", 0.4, "d")])

    report = report_mod.build("7d", db_path, now=NOW)
    assert report.signal_counts[0] == ("path:**/.ssh/**", 5)
    assert ("injection:instruction_override", 2) in report.signal_counts
    assert ("taint:exfiltration", 1) in report.signal_counts


def test_a_signal_repeated_within_one_decision_counts_once(db_path):
    """One noisy call must not dominate the ranking."""
    seed(db_path, verdict=Verdict.BLOCK, signals=[
        Signal("path:**/.env", 0.8, "a"),
        Signal("path:**/.env", 0.3, "b"),
        Signal("path:**/.env", 0.1, "c"),
    ])
    report = report_mod.build("7d", db_path, now=NOW)
    assert report.signal_counts == [("path:**/.env", 1)]


# =====================================================================
# the false-positive candidates - the point of the stage
# =====================================================================
def test_identifies_cleared_without_incident(db_path):
    """The required assertion.

    Three queued interruptions: one approved with nothing after it (a candidate),
    one denied (not a candidate), one still pending (not a candidate).
    """
    seed(db_path, verdict=Verdict.REVIEW, minutes_ago=10, session="s1", score=0.4)
    approved = queue(db_path, status="approved", minutes_ago=10,
                     resolved_minutes_ago=9, session="s1")
    queue(db_path, status="denied", minutes_ago=8, resolved_minutes_ago=7, session="s2")
    queue(db_path, status="pending", minutes_ago=6, session="s3")

    report = report_mod.build("7d", db_path, now=NOW)

    assert report.reviews_total == 3
    assert report.reviews_cleared == 1
    assert report.reviews_denied == 1
    assert report.reviews_pending == 1

    assert [c.review_id for c in report.fp_candidates] == [approved]
    assert report.fp_candidates[0].resolved_by == "human"
    assert not report.fp_candidates[0].followed_by_block
    assert report.cleared_with_incident == []


def test_consumed_approvals_count_as_cleared(db_path):
    """An approval that the retried call burned is still a human overrule."""
    consumed = queue(db_path, status="consumed", minutes_ago=10,
                     resolved_minutes_ago=9, session="s1")
    report = report_mod.build("7d", db_path, now=NOW)
    assert [c.review_id for c in report.fp_candidates] == [consumed]


def test_clearance_followed_by_a_block_is_separated_out(db_path):
    """Not every overrule is a false positive.

    If a block follows in the same session, the approval may have been one step of
    a real attack chain, so it must not be silently counted as a false positive.
    """
    cleared = queue(db_path, status="approved", minutes_ago=10,
                    resolved_minutes_ago=9, session="s1")
    # A block AFTER the clearance, same session.
    seed(db_path, verdict=Verdict.BLOCK, minutes_ago=5, session="s1", score=0.9)

    report = report_mod.build("7d", db_path, now=NOW)

    assert report.fp_candidates == []
    assert [c.review_id for c in report.cleared_with_incident] == [cleared]
    assert report.cleared_with_incident[0].followed_by_block


def test_a_much_later_block_does_not_disqualify_a_clearance(db_path):
    """The incident check is bounded in time, and the bound is load-bearing.

    One MCP session is a whole client connection and can stay open for hours. An
    unbounded "any block later in this session" test would disqualify nearly every
    genuine false positive and bias the headline number toward zero.
    """
    cleared = queue(db_path, status="approved", minutes_ago=120,
                    resolved_minutes_ago=119, session="s1")
    # An unrelated block two hours after the clearance, same long-lived session.
    seed(db_path, verdict=Verdict.BLOCK, minutes_ago=5, session="s1", score=0.9)

    report = report_mod.build("7d", db_path, now=NOW)
    assert [c.review_id for c in report.fp_candidates] == [cleared]
    assert report.cleared_with_incident == []


def test_incident_window_is_configurable(db_path):
    queue(db_path, status="approved", minutes_ago=120, resolved_minutes_ago=119,
          session="s1")
    seed(db_path, verdict=Verdict.BLOCK, minutes_ago=5, session="s1", score=0.9)

    wide = report_mod.build("7d", db_path, now=NOW,
                            incident_window=timedelta(hours=6))
    assert wide.fp_candidates == []
    assert len(wide.cleared_with_incident) == 1


def test_a_block_before_the_clearance_does_not_disqualify_it(db_path):
    """Only *later* blocks matter - the earlier one is what got reviewed."""
    cleared = queue(db_path, status="approved", minutes_ago=10,
                    resolved_minutes_ago=5, session="s1")
    seed(db_path, verdict=Verdict.BLOCK, minutes_ago=11, session="s1", score=0.9)

    report = report_mod.build("7d", db_path, now=NOW)
    assert [c.review_id for c in report.fp_candidates] == [cleared]


def test_a_block_in_a_different_session_does_not_disqualify(db_path):
    cleared = queue(db_path, status="approved", minutes_ago=10,
                    resolved_minutes_ago=9, session="s1")
    seed(db_path, verdict=Verdict.BLOCK, minutes_ago=5, session="OTHER", score=0.9)

    report = report_mod.build("7d", db_path, now=NOW)
    assert [c.review_id for c in report.fp_candidates] == [cleared]


def test_promoted_memory_counts_as_a_candidate(db_path):
    """A human promoting a quarantined memory is also an overrule."""
    promoted = queue(db_path, kind="memory_promotion", tool="memory.save",
                     status="approved", minutes_ago=10, resolved_minutes_ago=9,
                     session="s1", reason="memory write derived from untrusted content")
    report = report_mod.build("7d", db_path, now=NOW)
    assert [c.review_id for c in report.fp_candidates] == [promoted]
    assert report.fp_candidates[0].kind == "memory_promotion"


def test_fp_rate_arithmetic(db_path):
    """One candidate out of 20 calls, 4 of them interruptions."""
    for _ in range(16):
        seed(db_path, verdict=Verdict.ALLOW)
    for _ in range(4):
        seed(db_path, verdict=Verdict.REVIEW, score=0.4)
    queue(db_path, status="approved", minutes_ago=10, resolved_minutes_ago=9,
          session="s1")

    report = report_mod.build("7d", db_path, now=NOW)

    assert report.total_calls == 20
    assert report.interrupted == 4
    assert len(report.fp_candidates) == 1
    assert report.fp_rate == pytest.approx(5.0)          # 1/20
    assert report.overrule_rate == pytest.approx(25.0)   # 1/4


def test_candidate_carries_the_signals_that_triggered_it(db_path):
    """A candidate is only actionable if you can see which rule misfired."""
    queue(db_path, status="approved", minutes_ago=10, resolved_minutes_ago=9,
          signals=["path:**/.env", "injection:memory_implant"])
    report = report_mod.build("7d", db_path, now=NOW)
    assert report.fp_candidates[0].signals == ["path:**/.env", "injection:memory_implant"]


def test_enough_data_flag_guards_against_over_reading_a_small_sample(db_path):
    for _ in range(5):
        seed(db_path)
    small = report_mod.build("7d", db_path, now=NOW)
    assert not small.enough_data
    assert "indicative, not measured" in report_mod.render(small)

    for _ in range(100):
        seed(db_path)
    big = report_mod.build("7d", db_path, now=NOW)
    assert big.enough_data


# =====================================================================
# rendering and CLI
# =====================================================================
def test_render_includes_the_headline_number(db_path):
    for _ in range(9):
        seed(db_path, verdict=Verdict.ALLOW)
    seed(db_path, verdict=Verdict.REVIEW, signals=[Signal("path:**/.env", 0.8, "d")])
    queue(db_path, status="approved", minutes_ago=10, resolved_minutes_ago=9)

    text = report_mod.render(report_mod.build("7d", db_path, now=NOW))

    assert "FALSE-POSITIVE CANDIDATES" in text
    assert "candidates            : 1" in text
    assert "as share of all calls" in text
    assert "candidates, not confirmed errors" in text


def test_report_serialises(db_path):
    seed(db_path, verdict=Verdict.REVIEW)
    queue(db_path, status="approved", minutes_ago=10, resolved_minutes_ago=9)
    data = report_mod.build("7d", db_path, now=NOW).to_dict()

    assert {"window", "total_calls", "allow", "review", "block", "signal_counts",
            "false_positive_candidates", "fp_rate_pct", "enough_data"} <= set(data)
    assert data["false_positive_candidates"][0]["resolved_by"] == "human"


def test_cli_report_runs(monkeypatch, capsys):
    import json as _json

    directory = tempfile.mkdtemp(prefix="agentguard-cli-report-")
    monkeypatch.setenv("AGENTGUARD_HOME", directory)
    try:
        from agentguard.cli import main

        assert main(["report", "--json"]) == 0
        data = _json.loads(capsys.readouterr().out)
        assert data["total_calls"] == 0
        assert data["window"] == "7d"

        assert main(["report", "--since", "24h"]) == 0
        assert "window" in capsys.readouterr().out
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_cli_report_rejects_a_bad_duration(monkeypatch, capsys):
    directory = tempfile.mkdtemp(prefix="agentguard-cli-report-")
    monkeypatch.setenv("AGENTGUARD_HOME", directory)
    try:
        from agentguard.cli import main

        assert main(["report", "--since", "whenever"]) == 1
        assert "duration" in capsys.readouterr().err
    finally:
        shutil.rmtree(directory, ignore_errors=True)


# --- `proxy --upstream` forms (the sandbox's upstream.mcp.json must be usable) ---
def test_upstream_accepts_an_mcpconfig_json_file():
    import json as _json
    import sys as _sys

    from agentguard.cli import resolve_upstream

    directory = tempfile.mkdtemp(prefix="agentguard-upstream-")
    try:
        cfg = {"mcpServers": {"files": {"command": "npx", "args": ["-y", "server"]}}}
        path = Path(directory) / "upstream.mcp.json"
        path.write_text(_json.dumps(cfg), encoding="utf-8")
        assert resolve_upstream(str(path)) == cfg

        bad = Path(directory) / "other.json"
        bad.write_text('{"not": "a config"}', encoding="utf-8")
        with pytest.raises(ValueError):
            resolve_upstream(str(bad))
    finally:
        shutil.rmtree(directory, ignore_errors=True)

    assert resolve_upstream('{"mcpServers": {}}') == {"mcpServers": {}}
    assert resolve_upstream("https://example.com/mcp") == "https://example.com/mcp"
    assert resolve_upstream("examples/mock_mcp_server.py")["mcpServers"]["upstream"] == {
        "command": _sys.executable, "args": ["examples/mock_mcp_server.py"]}
