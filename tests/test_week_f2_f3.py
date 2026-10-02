"""F2 workspace tagging / dev exclusion, F3 gap detection."""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentguard.decision import Decision, Signal, Verdict


def hook_call(engine, cwd, command="cat ~/.ssh/id_rsa", tid="t"):
    return engine.handle({"hook_event_name": "PreToolUse", "session_id": "s", "cwd": cwd,
                          "tool_name": "Bash", "tool_input": {"command": command},
                          "tool_use_id": tid})


def _engine(db_path, dev=("agentgaurd",)):
    from agentguard.hooks import HookEngine
    from agentguard.policy import from_dict

    return HookEngine(from_dict({"dev_workspaces": list(dev)}), db_path=db_path)


# =========================================================================
# F2 - workspace label
# =========================================================================
def test_workspace_label_is_a_short_name_never_a_path():
    from agentguard.workspace import workspace_label

    assert workspace_label(r"D:\agentgaurd") == "agentgaurd"
    assert workspace_label("/home/someone/projects/shop-api/") == "shop-api"
    assert workspace_label(r"C:\work\a b c") == "a_b_c"
    assert workspace_label(None) is None and workspace_label("") is None
    assert workspace_label("C:\\") == "root"
    long = workspace_label("/x/" + "n" * 200)
    assert len(long) <= 40 and "/" not in long


def test_a_home_directory_label_never_carries_the_username(monkeypatch):
    from agentguard.workspace import workspace_label

    for var in ("USERNAME", "USER", "LOGNAME"):
        monkeypatch.setenv(var, "plantuser")
    assert workspace_label(r"C:\Users\plantuser") == "<home>"
    assert workspace_label("/home/plantuser") == "<home>"


def test_hook_rows_carry_the_workspace_label(db_path):
    from agentguard import audit

    hook_call(_engine(db_path), r"D:\work\billing-service")
    row = [r for r in audit.last(5, db_path) if r["stage"] == "TOOL_PREPARE"][0]
    assert row["workspace"] == "billing-service"
    assert "D:" not in (row["workspace"] or "") and "\\" not in row["workspace"]


def test_default_dev_workspace_is_this_repo():
    from agentguard.policy import Policy, load

    assert Policy().dev_workspaces == ["agentgaurd"]
    assert load(Path(__file__).resolve().parent.parent / "agentguard.policy.yaml"
                ).dev_workspaces == ["agentgaurd"]


def _seed(db_path):
    """2 BLOCKs in a real project, 3 BLOCKs + 1 ALLOW in the dev repo."""
    engine = _engine(db_path)
    hook_call(engine, r"D:\clients\shop-api", tid="a")
    hook_call(engine, r"D:\clients\shop-api", tid="b")
    hook_call(engine, r"D:\agentgaurd", tid="c")
    hook_call(engine, r"D:\agentgaurd", tid="d")
    hook_call(engine, r"D:\agentgaurd", tid="e")
    hook_call(engine, r"D:\agentgaurd", command="ls", tid="f")


def test_report_excludes_dev_workspaces_by_default_and_counts_them(db_path):
    from agentguard import report

    _seed(db_path)
    rep = report.build("1d", db_path=db_path, dev_workspaces=["agentgaurd"])
    assert rep.total_calls == 2 and rep.block == 2
    assert rep.excluded_dev == 4
    assert "excluded 4 call(s) from dev workspaces" in report.render(rep)

    every = report.build("1d", db_path=db_path, dev_workspaces=["agentgaurd"], include_dev=True)
    assert every.total_calls == 6 and every.excluded_dev == 0


def test_precision_and_labeler_exclude_dev_workspaces(db_path):
    from agentguard import labels

    _seed(db_path)
    dev = ["agentgaurd"]
    assert len(labels.interruptions(db_path=db_path, exclude_workspaces=dev)) == 2
    assert len(labels.interruptions(db_path=db_path)) == 5
    session = labels.review(db_path=db_path, exclude_workspaces=dev,
                            input_fn=lambda _p: "t", out=lambda _t: None)
    assert session.shown == 2
    p = labels.precision(db_path=db_path, exclude_workspaces=dev)
    assert p.interruptions == 2 and p.overall.tp == 2


def test_export_keeps_the_workspace_label(db_path):
    import csv

    from agentguard import export, report

    _seed(db_path)
    rep = report.build("1d", db_path=db_path, dev_workspaces=["agentgaurd"])
    out = Path(tempfile.mkdtemp(prefix="ag-ws-")) / "w.csv"
    try:
        export.export(out, rep, db_path=db_path)
        lines = out.read_text(encoding="utf-8").splitlines()
        rows = list(csv.DictReader(lines[1:]))
        assert {r["workspace"] for r in rows} == {"shop-api"}
        assert "excluded 4 dev-workspace" in lines[0]
    finally:
        shutil.rmtree(out.parent, ignore_errors=True)


def test_cli_include_dev_flag(monkeypatch, capsys):
    from agentguard.cli import main

    home = tempfile.mkdtemp(prefix="ag-ws-cli-")
    try:
        monkeypatch.setenv("AGENTGUARD_HOME", home)
        _seed(None)
        assert main(["report", "--since", "1d"]) == 0
        assert "excluded 4 call(s)" in capsys.readouterr().out
        assert main(["report", "--since", "1d", "--include-dev"]) == 0
        assert "calls gated     : 6" in capsys.readouterr().out
    finally:
        shutil.rmtree(home, ignore_errors=True)


# --- migration ------------------------------------------------------------
PHASE_E_SCHEMA = """
CREATE TABLE audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, session_id TEXT, agent TEXT,
    role TEXT, stage TEXT NOT NULL, tool TEXT, args_digest TEXT, score REAL,
    verdict TEXT NOT NULL, reason TEXT, signals TEXT, detail TEXT,
    prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'mcp', hash_v INTEGER NOT NULL DEFAULT 1,
    policy_version TEXT, detector_version TEXT, mode TEXT
);
"""


def test_migration_keeps_v1_v2_v3_rows_verifying(db_path):
    from agentguard import audit
    from agentguard.audit import GENESIS, _entry_hash
    from agentguard.db import connect

    conn = sqlite3.connect(db_path)
    conn.executescript(PHASE_E_SCHEMA)
    prev = GENESIS
    for i, v in enumerate((1, 2, 3)):
        entry = {"ts": f"2026-10-01T10:0{i}:00.000000+00:00", "session_id": "s", "agent": "a",
                 "role": "r", "stage": "TOOL_PREPARE", "tool": "Bash", "args_digest": "{}",
                 "score": 0.8, "verdict": "BLOCK", "reason": "x", "signals": "[]", "detail": None,
                 "source": "hook", "policy_version": "p-1", "detector_version": "2026.10.2",
                 "mode": "observe"}
        h = _entry_hash(prev, entry, v)
        conn.execute("""INSERT INTO audit (ts, session_id, agent, role, stage, tool, args_digest,
            score, verdict, reason, signals, detail, prev_hash, entry_hash, source, hash_v,
            policy_version, detector_version, mode) VALUES (:ts,:session_id,:agent,:role,:stage,
            :tool,:args_digest,:score,:verdict,:reason,:signals,:detail,:prev,:h,:source,:v,
            :policy_version,:detector_version,:mode)""", {**entry, "prev": prev, "h": h, "v": v})
        prev = h
    conn.commit()
    conn.close()

    assert "workspace" in {r[1] for r in connect(db_path).execute("PRAGMA table_info(audit)")}
    assert audit.verify_chain(db_path) == (True, None)
    hook_call(_engine(db_path), "/srv/proj")
    assert audit.verify_chain(db_path) == (True, None)
    new = audit.last(1, db_path)[0]
    assert new["hash_v"] == audit.HASH_VERSION and new["workspace"] == "proj"
    connect(db_path).execute("UPDATE audit SET workspace='other' WHERE id=?", (new["id"],))
    connect(db_path).commit()
    assert audit.verify_chain(db_path) == (False, new["id"]), "workspace is in the chain"


# =========================================================================
# F3 - gap detection
# =========================================================================
NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)


def _row_at(db_path, when: datetime, source="hook"):
    from agentguard import audit
    from agentguard.db import connect

    rid = audit.record(stage="TOOL_PREPARE", decision=Decision(Verdict.ALLOW), tool="Bash",
                       db_path=db_path, source=source, workspace="proj")
    connect(db_path).execute("UPDATE audit SET ts=? WHERE id=?",
                             (when.isoformat(timespec="microseconds"), rid))
    connect(db_path).commit()


def test_report_lists_zero_event_days_with_a_fail_open_warning(db_path):
    from agentguard import report

    for day in (1, 2, 3, 6, 7, 8):              # Oct 4 and 5 are a synthetic outage
        _row_at(db_path, datetime(2026, 10, day, 9, 0, tzinfo=timezone.utc))
    rep = report.build("7d", db_path=db_path, now=NOW, dev_workspaces=[])
    assert rep.zero_event_days == ["2026-10-04", "2026-10-05"]
    text = report.render(rep)
    assert "no events on 2026-10-04, 2026-10-05" in text
    assert "fail-open" in text


def test_no_gap_warning_when_every_day_has_events(db_path):
    from agentguard import report

    for day in range(1, 10):
        _row_at(db_path, datetime(2026, 10, day, 9, 0, tzinfo=timezone.utc))
    rep = report.build("7d", db_path=db_path, now=NOW, dev_workspaces=[])
    assert rep.zero_event_days == [] and "fail-open" not in report.render(rep)


def test_activity_per_source_and_per_day(db_path):
    from agentguard import report

    _row_at(db_path, NOW - timedelta(hours=3), source="hook")
    _row_at(db_path, NOW - timedelta(days=2, hours=1), source="mcp")
    _row_at(db_path, NOW - timedelta(days=2, hours=2), source="mcp")
    act = report.activity(db_path=db_path, now=NOW)
    assert act["last_event"]["hook"]["age_hours"] == pytest.approx(3.0, abs=0.01)
    assert act["last_event"]["mcp"]["age_hours"] == pytest.approx(49.0, abs=0.01)
    days = dict(act["per_day"])
    assert len(days) == 7 and days["2026-10-09"] == 1 and days["2026-10-07"] == 2
    assert days["2026-10-05"] == 0


def test_status_shows_activity(monkeypatch, capsys):
    from agentguard.cli import main
    from agentguard.hooks import HookEngine
    from agentguard.policy import Policy

    home = tempfile.mkdtemp(prefix="ag-status-")
    try:
        monkeypatch.setenv("AGENTGUARD_HOME", home)
        hook_call(HookEngine(Policy()), "/srv/proj", command="ls")
        assert main(["status"]) == 0
        out = capsys.readouterr().out
        assert "last event" in out and "hook" in out and "last 7 days" in out
    finally:
        shutil.rmtree(home, ignore_errors=True)


@pytest.fixture
def fake_home(monkeypatch):
    home = tempfile.mkdtemp(prefix="ag-doc-")
    monkeypatch.setenv("HOME", home)
    monkeypatch.setenv("USERPROFILE", home)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.setenv("AGENTGUARD_HOME", str(Path(home) / ".agentguard"))
    try:
        yield Path(home)
    finally:
        shutil.rmtree(home, ignore_errors=True)


def test_doctor_warns_when_hooks_are_silent(fake_home, monkeypatch):
    from agentguard import config as cfg
    from agentguard import doctor
    from agentguard.cli import main

    cfg.save(cfg.Config(hook_silence_hours=6))
    assert main(["install-hooks"]) == 0

    r = doctor.check_hook_activity()
    assert r.status == "WARN" and "no hook event" in r.detail

    _row_at(None, datetime.now(timezone.utc) - timedelta(hours=9))
    r = doctor.check_hook_activity()
    assert r.status == "WARN" and "9" in r.detail and "6 h" in r.detail

    _row_at(None, datetime.now(timezone.utc) - timedelta(minutes=5))
    assert doctor.check_hook_activity().status == "PASS"


def test_doctor_activity_check_is_quiet_without_hooks(fake_home):
    from agentguard import doctor

    assert doctor.check_hook_activity().status == "PASS"


def test_hook_silence_hours_is_validated():
    from agentguard.config import Config

    assert Config(hook_silence_hours=0).validate()
    assert not Config(hook_silence_hours=48).validate()
