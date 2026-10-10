"""`agentguard demo`: deterministic, offline, never touches the real home."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest


@pytest.fixture()
def fake_home(monkeypatch):
    home = Path(tempfile.mkdtemp(prefix="ag-demo-home-"))
    monkeypatch.setenv("AGENTGUARD_HOME", str(home))
    yield home
    shutil.rmtree(home, ignore_errors=True)


def test_demo_stops_the_attack(fake_home):
    from agentguard import demo

    res = demo.run(say=lambda _line: None)
    assert res.ok, res.lines
    assert res.quarantined == 1 and res.recall_tainted and res.blocked and res.chain_intact
    text = "\n".join(res.lines)
    assert "QUARANTINED" in text and "taint re-attached" in text and "STOPPED" in text
    assert "taint:exfiltration" in text and "NOT BLOCKED" not in text


def test_demo_is_deterministic(fake_home):
    from agentguard import demo

    first = demo.run(say=lambda _line: None).lines
    second = demo.run(say=lambda _line: None).lines
    assert first == second


def test_demo_writes_nothing_to_the_home_and_restores_the_environment(fake_home):
    from agentguard import demo

    demo.run(say=lambda _line: None)
    assert os.environ["AGENTGUARD_HOME"] == str(fake_home)
    assert list(fake_home.iterdir()) == []


def test_demo_keep_leaves_an_inspectable_audit_log(fake_home):
    from agentguard import audit, demo

    keep = Path(tempfile.mkdtemp(prefix="ag-demo-keep-"))
    try:
        assert demo.run(say=lambda _line: None, keep=keep).ok
        db = keep / "demo.db"
        assert db.exists() and audit.verify_chain(str(db))[0]
        assert list(fake_home.iterdir()) == []
    finally:
        shutil.rmtree(keep, ignore_errors=True)


def test_demo_cli(fake_home, capsys):
    from agentguard.cli import main

    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "SESSION 1" in out and "SESSION 2" in out and "STOPPED" in out
