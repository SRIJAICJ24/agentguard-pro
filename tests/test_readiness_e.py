"""Readiness phase E - turning the measurement week into a number.

E1 the labeler, E2 precision, E3 detector/policy versions on audit rows, E4 the
anonymized export. Every test uses a temp database; none touches ~/.agentguard.
"""

from __future__ import annotations

import csv
import json
import re
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentguard.decision import Decision, Signal, Verdict

ROOT = Path(__file__).resolve().parent.parent


def record(db_path, verdict=Verdict.BLOCK, *, tool="Bash", signals=("path:**/.ssh/**",),
           source="hook", mode="observe", detector_version=None, policy_version="p-test",
           arguments=None, ts_offset_min=0.0):
    from agentguard import audit
    from agentguard.db import connect

    rid = audit.record(
        stage="TOOL_PREPARE",
        decision=Decision(verdict, 0.8 if verdict is Verdict.BLOCK else 0.4,
                          [Signal(s, 0.4, "detail") for s in signals], reason=", ".join(signals)),
        tool=tool, arguments=arguments or {"command": "x"}, session_id="s1",
        db_path=db_path, source=source, mode=mode,
        detector_version=detector_version, policy_version=policy_version,
    )
    if ts_offset_min:
        ts = (datetime.now(timezone.utc) - timedelta(minutes=ts_offset_min)).isoformat(
            timespec="microseconds")
        conn = connect(db_path)
        conn.execute("UPDATE audit SET ts=? WHERE id=?", (ts, rid))
        conn.commit()
    return rid


def scripted(*answers):
    queue = list(answers)
    return lambda _prompt: queue.pop(0) if queue else "q"


# =========================================================================
# E1 - the labeler
# =========================================================================
def test_labeler_walks_unlabeled_decisions_with_scripted_input(db_path):
    from agentguard import labels

    ids = [record(db_path), record(db_path, Verdict.REVIEW, signals=("hook:destructive_command",)),
           record(db_path), record(db_path)]
    record(db_path, Verdict.ALLOW, signals=())            # never offered: not an interruption
    out: list[str] = []
    session = labels.review(db_path=db_path, input_fn=scripted("t", "f", "s", "u"), out=out.append)

    assert session.shown == 4 and session.skipped == 1
    assert session.labeled == {"tp": 1, "fp": 1, "unsure": 1}
    assert labels.labels_for(ids, db_path) == {ids[0]: "tp", ids[1]: "fp", ids[3]: "unsure"}

    text = "\n".join(out)
    assert "WOULD HAVE BLOCKED" in text and "WOULD HAVE ASKED FOR REVIEW" in text
    assert "source=hook" in text and "path:**/.ssh/**" in text

    # Labeled rows are not shown again; the skipped one is.
    out2: list[str] = []
    again = labels.review(db_path=db_path, input_fn=scripted("f"), out=out2.append)
    assert again.shown == 1 and f"audit #{ids[2]}" in "\n".join(out2)
    assert labels.unlabeled(db_path=db_path) == []


def test_labeler_quit_and_bad_input(db_path):
    from agentguard import labels

    rid = record(db_path)
    record(db_path)
    out: list[str] = []
    session = labels.review(db_path=db_path, input_fn=scripted("maybe", "t", "q"), out=out.append)
    assert "please answer" in "\n".join(out)
    assert session.quit_early and labels.labels_for([rid], db_path) == {rid: "tp"}


def test_labeler_ignores_a_byte_order_mark_on_piped_input(db_path):
    """Regression: Windows PowerShell 5.1 prefixes piped stdin with a UTF-8 BOM, so
    `"t`nf" | agentguard report --fp-review` read the first answer as invalid and
    every later answer landed on the wrong decision."""
    from agentguard import labels

    first, second = record(db_path), record(db_path)
    labels.review(db_path=db_path, input_fn=scripted("\ufefft", "f"), out=lambda _t: None)
    assert labels.labels_for([first, second], db_path) == {first: "tp", second: "fp"}


def test_enforce_mode_rows_say_blocked_not_would_have(db_path):
    from agentguard import labels

    record(db_path, mode="enforce")
    out: list[str] = []
    labels.review(db_path=db_path, input_fn=scripted("q"), out=out.append)
    text = "\n".join(out)
    assert "BLOCKED" in text and "WOULD HAVE" not in text


def test_labeler_shows_redacted_arguments(db_path):
    from agentguard import labels

    record(db_path, arguments={"command": "export T=ghp_16C7e42F292c6912E7710c838347Ae178B4a"})
    out: list[str] = []
    labels.review(db_path=db_path, input_fn=scripted("q"), out=out.append)
    text = "\n".join(out)
    assert "ghp_16C7e42F292c6912E7710c838347Ae178B4a" not in text
    assert "redacted" in text


def test_labels_never_touch_the_audit_chain(db_path):
    from agentguard import audit, labels
    from agentguard.db import connect

    ids = [record(db_path) for _ in range(5)]
    before = [(r["id"], r["entry_hash"]) for r in
              connect(db_path).execute("SELECT id, entry_hash FROM audit ORDER BY id")]
    assert audit.verify_chain(db_path) == (True, None)
    for rid, lab in zip(ids, ("tp", "fp", "unsure", "tp", "fp")):
        labels.set_label(rid, lab, db_path=db_path)
    labels.set_label(ids[0], "fp", db_path=db_path)        # relabel
    after = [(r["id"], r["entry_hash"]) for r in
             connect(db_path).execute("SELECT id, entry_hash FROM audit ORDER BY id")]
    assert after == before
    assert audit.verify_chain(db_path) == (True, None)
    cols = {r[1] for r in connect(db_path).execute("PRAGMA table_info(audit)")}
    assert "label" not in cols


def test_invalid_label_is_rejected(db_path):
    from agentguard import labels

    with pytest.raises(ValueError):
        labels.set_label(record(db_path), "yes", db_path=db_path)


# =========================================================================
# E2 - precision
# =========================================================================
def _mix(db_path):
    """Known synthetic mix.

    hook: 20 path-signal BLOCKs -> 17 tp, 3 fp;  4 destructive REVIEWs -> 1 tp, 2 fp, 1 unsure
    mcp : 5 taint REVIEWs -> 3 tp, 2 fp;  2 unlabeled
    """
    from agentguard import labels

    plan = ([("hook", Verdict.BLOCK, "path:**/.ssh/**", "tp")] * 17
            + [("hook", Verdict.BLOCK, "path:**/.ssh/**", "fp")] * 3
            + [("hook", Verdict.REVIEW, "hook:destructive_command", l)
               for l in ("tp", "fp", "fp", "unsure")]
            + [("mcp", Verdict.REVIEW, "taint:exfiltration", l)
               for l in ("tp", "tp", "tp", "fp", "fp")]
            + [("mcp", Verdict.REVIEW, "taint:exfiltration", None)] * 2)
    for source, verdict, signal, label in plan:
        rid = record(db_path, verdict, signals=(signal,), source=source)
        if label:
            labels.set_label(rid, label, db_path=db_path)


def test_precision_math_on_a_known_mix(db_path):
    from agentguard import labels

    _mix(db_path)
    p = labels.precision(db_path=db_path)
    assert p.interruptions == 31 and p.labeled == 29
    assert (p.overall.tp, p.overall.fp, p.overall.unsure) == (21, 7, 1)
    assert p.overall.n == 28 and p.overall.precision == pytest.approx(21 / 28)
    assert p.coverage == pytest.approx(29 / 31)

    hook, mcp = p.by_source["hook"], p.by_source["mcp"]
    assert (hook.tp, hook.fp, hook.unsure) == (18, 5, 1)
    assert hook.precision == pytest.approx(18 / 23)
    assert (mcp.tp, mcp.fp) == (3, 2) and mcp.precision == pytest.approx(0.6)

    assert p.by_signal["path:**/.ssh/**"].precision == pytest.approx(17 / 20)
    assert p.by_signal["hook:destructive_command"].precision == pytest.approx(1 / 3)
    assert p.by_signal["taint:exfiltration"].n == 5


def test_small_n_carries_an_explicit_warning(db_path):
    from agentguard import labels

    _mix(db_path)
    p = labels.precision(db_path=db_path)
    assert p.overall.trusted and "too few" not in p.overall.describe()      # n = 28
    assert p.by_signal["path:**/.ssh/**"].trusted                           # n = 20
    assert not p.by_source["mcp"].trusted
    assert "too few labels to trust" in p.by_source["mcp"].describe()
    assert "too few labels to trust" in p.by_signal["hook:destructive_command"].describe()

    text = labels.render_precision(p)
    assert "too few labels to trust" in text


def test_no_percentage_is_ever_printed_without_its_n(db_path):
    from agentguard import labels

    _mix(db_path)
    text = labels.render_precision(labels.precision(db_path=db_path))
    for line in text.splitlines():
        for match in re.finditer(r"\d+(\.\d+)?%", line):
            assert re.search(r"\bn \d+|\bof \d+", line), f"bare percentage: {line!r}"


def test_precision_is_part_of_report(db_path):
    from agentguard import report

    _mix(db_path)
    rep = report.build("1d", db_path=db_path)
    assert rep.precision.overall.n == 28
    assert rep.to_dict()["precision"]["by_source"]["mcp"]["trusted"] is False
    assert "LABELED PRECISION" in report.render(rep)


def test_no_labels_yet_prints_a_hint_not_a_number(db_path):
    from agentguard import labels

    record(db_path)
    text = labels.render_precision(labels.precision(db_path=db_path))
    assert "--fp-review" in text and "%" not in text.replace("(0%)", "")


# =========================================================================
# E3 - versions on audit rows
# =========================================================================
PHASE_A_SCHEMA = """
CREATE TABLE audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, session_id TEXT, agent TEXT,
    role TEXT, stage TEXT NOT NULL, tool TEXT, args_digest TEXT, score REAL,
    verdict TEXT NOT NULL, reason TEXT, signals TEXT, detail TEXT,
    prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'mcp', hash_v INTEGER NOT NULL DEFAULT 1
);
"""


def _phase_a_database(path: str) -> None:
    """A database as written before Phase E: two v1 rows, then two v2 (source) rows."""
    from agentguard.audit import GENESIS, _entry_hash

    conn = sqlite3.connect(path)
    conn.executescript(PHASE_A_SCHEMA)
    prev = GENESIS
    for i, (version, source) in enumerate([(1, "mcp"), (1, "mcp"), (2, "hook"), (2, "mcp")]):
        entry = {"ts": f"2026-09-29T10:0{i}:00.000000+00:00", "session_id": "old", "agent": "a",
                 "role": "r", "stage": "TOOL_PREPARE", "tool": "Bash", "args_digest": "{}",
                 "score": 0.8, "verdict": "BLOCK", "reason": "path", "signals": "[]",
                 "detail": None, "source": source}
        h = _entry_hash(prev, entry, version)
        conn.execute("""INSERT INTO audit (ts, session_id, agent, role, stage, tool, args_digest,
                        score, verdict, reason, signals, detail, prev_hash, entry_hash, source,
                        hash_v) VALUES (:ts,:session_id,:agent,:role,:stage,:tool,:args_digest,
                        :score,:verdict,:reason,:signals,:detail,:prev,:h,:source,:v)""",
                     {**entry, "prev": prev, "h": h, "v": version})
        prev = h
    conn.commit()
    conn.close()


def test_migration_keeps_old_rows_verifying(db_path):
    from agentguard import audit
    from agentguard.db import connect

    _phase_a_database(db_path)
    conn = connect(db_path)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(audit)")}
    assert {"policy_version", "detector_version", "mode"} <= cols
    assert audit.verify_chain(db_path) == (True, None), "v1 and v2 rows verify unchanged"

    rid = record(db_path)
    assert audit.verify_chain(db_path) == (True, None)
    new = audit.last(1, db_path)[0]
    assert new["hash_v"] == audit.HASH_VERSION == 3
    from agentguard.versions import DETECTOR_VERSION
    assert new["detector_version"] == DETECTOR_VERSION and new["mode"] == "observe"

    conn.execute("UPDATE audit SET detector_version='forged' WHERE id=?", (rid,))
    conn.commit()
    assert audit.verify_chain(db_path) == (False, rid), "versions are covered by the chain"
    conn.execute("UPDATE audit SET detector_version=?, hash_v=2 WHERE id=?",
                 (DETECTOR_VERSION, rid))
    conn.commit()
    assert audit.verify_chain(db_path) == (False, rid), "downgrading the hash version is caught"


async def test_gateway_and_hook_rows_record_versions_and_mode(upstream, db_path):
    from fastmcp import Client

    from agentguard import audit
    from agentguard.gateway import build_daemon
    from agentguard.policy import Policy
    from agentguard.versions import DETECTOR_VERSION, policy_version

    p = Policy()
    server, guard, engine = build_daemon(upstream, policy=p, db_path=db_path)
    async with Client(server) as client:
        await client.call_tool("web.search", {"query": "x"})
    engine.handle({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
                   "tool_input": {"command": "ls"}, "tool_use_id": "t"})
    rows = [r for r in audit.last(20, db_path) if r["stage"] == "TOOL_PREPARE"]
    assert {r["source"] for r in rows} == {"mcp", "hook"}
    for r in rows:
        assert r["detector_version"] == DETECTOR_VERSION
        assert r["policy_version"] == policy_version(p)
        assert r["mode"] == "observe"


def test_policy_version_tracks_rule_changes_not_mode():
    from agentguard.policy import Policy, from_dict
    from agentguard.versions import policy_version

    base = policy_version(Policy())
    assert base.startswith("p-")
    enforcing = Policy()
    enforcing.enforcement = True
    assert policy_version(enforcing) == base, "mode is recorded separately"
    assert policy_version(from_dict({"tools": {"deny": ["x.y"]}})) != base


def test_detector_version_is_bumped_when_detection_code_changes():
    """The rule "bump DETECTOR_VERSION whenever detection logic changes", enforced.

    If this fails, detection code changed: bump DETECTOR_VERSION in
    agentguard/versions.py and set DETECTOR_FINGERPRINT to the value below.
    """
    from agentguard import versions

    current = versions.detector_fingerprint()
    assert current == versions.DETECTOR_FINGERPRINT, (
        f"detection code changed (fingerprint {current}, recorded "
        f"{versions.DETECTOR_FINGERPRINT}): bump DETECTOR_VERSION "
        f"(now {versions.DETECTOR_VERSION}) and set DETECTOR_FINGERPRINT = '{current}'")


def test_fingerprint_ignores_comments_but_not_code():
    from agentguard import versions

    src_dir = ROOT / "agentguard"
    tmp = Path(tempfile.mkdtemp(prefix="ag-fp-"))
    try:
        for name in versions.DETECTION_MODULES:
            shutil.copy(src_dir / f"{name}.py", tmp / f"{name}.py")
        base = versions.detector_fingerprint(tmp)
        risk = tmp / "risk.py"
        text = risk.read_text(encoding="utf-8")
        risk.write_text("# a new comment\n" + text.replace('"""Risk scoring.', '"""Risk scoring, reworded.', 1),
                        encoding="utf-8")
        assert versions.detector_fingerprint(tmp) == base, "comments/docstrings don't count"
        risk.write_text(text.replace("W_INJECTION = 0.35", "W_INJECTION = 0.36"), encoding="utf-8")
        assert versions.detector_fingerprint(tmp) != base, "a weight change does"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_report_warns_on_a_version_mix(db_path):
    from agentguard import report

    record(db_path, detector_version="2026.10.1")
    single = report.build("1d", db_path=db_path)
    assert not single.mixed_versions and "WARNING" not in report.render(single)

    record(db_path, detector_version="2026.10.2")
    mixed = report.build("1d", db_path=db_path)
    assert mixed.mixed_versions
    text = report.render(mixed)
    assert "WARNING: 2 detector/policy versions" in text
    assert "2026.10.1" in text and "2026.10.2" in text


def test_unversioned_legacy_rows_count_as_their_own_version(db_path):
    from agentguard import report
    from agentguard.db import connect

    rid = record(db_path)
    record(db_path)
    connect(db_path).execute("UPDATE audit SET detector_version=NULL, policy_version=NULL "
                             "WHERE id=?", (rid,))
    connect(db_path).commit()
    rep = report.build("1d", db_path=db_path)
    assert rep.mixed_versions and any(d == "unversioned" for d, _p, _n in rep.versions)


# =========================================================================
# E4 - anonymized export
# =========================================================================
PLANTED_SECRET = "AKIAIOSFODNN7EXAMPLE"
PLANTED_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
PLANTED_HOME = r"C:\Users\plantuser"
PLANTED_USER = "plantuser"


@pytest.fixture
def planted_identity(monkeypatch):
    """Pretend the person running AgentGuard is `plantuser` at C:\\Users\\plantuser."""
    for var in ("USERNAME", "USER", "LOGNAME"):
        monkeypatch.setenv(var, PLANTED_USER)
    monkeypatch.setenv("USERPROFILE", PLANTED_HOME)
    monkeypatch.setenv("HOME", PLANTED_HOME)


def _plant(db_path):
    from agentguard.hooks import HookEngine
    from agentguard.policy import Policy

    engine = HookEngine(Policy(), db_path=db_path)
    # Real hook traffic with everything in the arguments (which are never exported).
    engine.handle({"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Bash",
                   "tool_input": {"command": f"export AWS={PLANTED_SECRET} && cat "
                                             f"{PLANTED_HOME}\\.ssh\\id_rsa"},
                   "tool_use_id": "t1"})
    engine.handle({"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Write",
                   "tool_input": {"file_path": f"{PLANTED_HOME}\\notes.txt",
                                  "content": f"token {PLANTED_TOKEN} for {PLANTED_USER}"},
                   "tool_use_id": "t2"})
    # And the same strings in fields that ARE exported, to exercise the scrubber.
    record(db_path, tool=f"mcp__files__read_{PLANTED_USER}",
           signals=(f"path:{PLANTED_HOME}\\notes", "path:/home/plantuser/.aws/config"))
    # A secret-shaped signal on its own row: the word "secret" switches on the
    # entropy redactor for the whole string, which would otherwise also swallow
    # the paths above before the home-path scrubber is exercised.
    record(db_path, tool="scan", signals=(f"secret:{PLANTED_SECRET}",))
    record(db_path, tool=f"upload {PLANTED_TOKEN}", signals=("taint:exfiltration",))


def _assert_clean(text: str):
    for needle in (PLANTED_SECRET, PLANTED_TOKEN, PLANTED_HOME, PLANTED_HOME.replace("\\", "/"),
                   "/home/plantuser", PLANTED_USER):
        assert needle.lower() not in text.lower(), f"export leaked {needle!r}"


@pytest.mark.parametrize("suffix", ["csv", "json"])
def test_export_contains_no_planted_secret_home_path_or_username(db_path, planted_identity, suffix):
    from agentguard import export, labels, report

    _plant(db_path)
    first = labels.interruptions(db_path=db_path)[0]["id"]
    labels.set_label(first, "tp", db_path=db_path)
    rep = report.build("1d", db_path=db_path)
    out = Path(tempfile.mkdtemp(prefix="ag-exp-")) / f"week.{suffix}"
    try:
        path, count = export.export(out, rep, db_path=db_path)
        text = path.read_text(encoding="utf-8")
        _assert_clean(text)
        assert count == 5
        assert "<HOME>" in text and "<USER>" in text and "redacted" in text
        if suffix == "csv":
            lines = text.splitlines()
            assert lines[0].startswith("# agentguard export - window last 1d")
            assert "versions:" in lines[0]
            rows = list(csv.DictReader(lines[1:]))
            assert set(rows[0]) == set(export.FIELDS)
            assert rows[0]["label"] == "tp"
            assert "command" not in text and "content" not in text     # no arguments at all
        else:
            data = json.loads(text)
            assert data["meta"]["window"] == "1d" and data["meta"]["versions"]
            assert data["rows"][0]["label"] == "tp"
            assert all(set(r) == set(export.FIELDS) for r in data["rows"])
    finally:
        shutil.rmtree(out.parent, ignore_errors=True)


def test_export_header_flags_a_version_mix(db_path, planted_identity):
    from agentguard import export, report

    record(db_path, detector_version="2026.10.1")
    record(db_path, detector_version="2026.10.2")
    out = Path(tempfile.mkdtemp(prefix="ag-exp-")) / "mix.csv"
    try:
        export.export(out, report.build("1d", db_path=db_path), db_path=db_path)
        assert "MIXED VERSIONS" in out.read_text(encoding="utf-8").splitlines()[0]
    finally:
        shutil.rmtree(out.parent, ignore_errors=True)


def test_scrub_units():
    from agentguard.export import scrub

    names = ["plantuser"]
    assert scrub(r"C:\Users\plantuser\proj\a.py", names) == r"<HOME>\proj\a.py"
    assert scrub("/Users/someone/x", names) == "<HOME>/x"
    assert scrub("/home/alice/.ssh/id_rsa", names) == "<HOME>/.ssh/id_rsa"
    assert scrub("owned by PlantUser", names) == "owned by <USER>"
    assert PLANTED_SECRET not in scrub(f"key {PLANTED_SECRET}", names)
    assert scrub("web.search", names) == "web.search"


# =========================================================================
# CLI
# =========================================================================
def _cli(*argv):
    from agentguard.cli import main
    return main(list(argv))


@pytest.fixture
def cli_home(monkeypatch):
    home = tempfile.mkdtemp(prefix="ag-e-cli-")
    monkeypatch.setenv("AGENTGUARD_HOME", home)
    try:
        yield Path(home)
    finally:
        shutil.rmtree(home, ignore_errors=True)


def test_cli_fp_review_then_report_then_export(cli_home, monkeypatch, capsys, planted_identity):
    import builtins

    rid = record(None)
    record(None)
    answers = iter(["f", "t"])
    monkeypatch.setattr(builtins, "input", lambda _p="": next(answers))

    assert _cli("report", "--since", "1d", "--fp-review") == 0
    out = capsys.readouterr().out
    assert "labeled 2 (tp 1, fp 1, unsure 0)" in out
    assert "too few labels to trust" in out

    assert _cli("report", "--since", "1d") == 0
    assert "LABELED PRECISION" in capsys.readouterr().out

    target = cli_home / "export.csv"
    assert _cli("report", "--since", "1d", "--export", str(target)) == 0
    assert "exported 2 decision(s)" in capsys.readouterr().out
    assert target.read_text(encoding="utf-8").startswith("# agentguard export")

    from agentguard import labels
    assert labels.labels_for([rid], None) == {rid: "fp"}
