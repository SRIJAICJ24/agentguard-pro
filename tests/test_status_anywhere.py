"""`status` and friends from any working directory.

Regression (week 2): run from another folder, `agentguard status` printed
"policy: <defaults>" although onboarding had recorded the policy file the daemon
uses, and showed only its own package version - so it could disagree with what
`report` showed from the audit rows without saying why.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from test_packaging import child_pythonpath

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def installed():
    """A temp AGENTGUARD_HOME whose config names a policy file kept elsewhere,
    and an unrelated working directory with no policy in it."""
    from agentguard import config as cfg

    work = Path(tempfile.mkdtemp(prefix="ag-anywhere-"))
    home, elsewhere, policies = work / "home", work / "elsewhere", work / "policies"
    for d in (home, elsewhere, policies, work / "claude"):
        d.mkdir()
    policy = policies / "agentguard.policy.yaml"
    policy.write_text("enforcement: false\ndev_workspaces: [devproj]\n", encoding="utf-8")
    cfg.save(cfg.Config(policy_file=str(policy)), home / "agentguard.json")
    env = {**os.environ, "AGENTGUARD_HOME": str(home), "HOME": str(home),
           "CLAUDE_CONFIG_DIR": str(work / "claude"),
           "PYTHONPATH": child_pythonpath(ROOT)}
    yield {"work": work, "home": home, "cwd": elsewhere, "policy": policy, "env": env}
    shutil.rmtree(work, ignore_errors=True)


def _cli(installed, *args, timeout=300):
    return subprocess.run([sys.executable, "-m", "agentguard.cli", *args],
                          cwd=installed["cwd"], env=installed["env"],
                          capture_output=True, text=True, timeout=timeout)


def test_status_shows_the_configured_policy_and_versions(installed):
    from agentguard import __version__
    from agentguard.policy import load
    from agentguard.versions import DETECTOR_VERSION, policy_version

    out = _cli(installed, "status")
    assert out.returncode == 0, out.stderr
    text = out.stdout
    assert "<defaults>" not in text
    assert str(installed["policy"]) in text
    after = text.split(str(installed["policy"]))[1].splitlines()
    assert "policy_file in" in after[1] and "agentguard.json" in after[1], \
        "says where the policy choice came from"
    assert __version__ in text and DETECTOR_VERSION in text
    assert policy_version(load(installed["policy"])) in text


def test_status_names_the_package_location(installed):
    import agentguard

    out = _cli(installed, "status")
    assert str(Path(agentguard.__file__).resolve().parent) in out.stdout


def test_the_daemon_health_answer_carries_its_versions(db_path):
    from starlette.testclient import TestClient

    from agentguard import __version__
    from agentguard.gateway import build_daemon
    from agentguard.policy import Policy
    from agentguard.versions import DETECTOR_VERSION, policy_version

    policy = Policy()
    server, _guard, _engine = build_daemon(None, policy=policy, db_path=db_path)
    with TestClient(server.http_app()) as client:
        health = client.get("/hooks/health").json()
    assert health["version"] == __version__
    assert health["detector_version"] == DETECTOR_VERSION
    assert health["policy_version"] == policy_version(policy)


def test_status_warns_when_the_daemon_runs_other_code():
    from agentguard.cli import _version_mismatches

    mine = {"version": "0.3.0", "detector_version": "2026.10.5", "policy_version": "p-1"}
    assert _version_mismatches(mine, dict(mine)) == []
    other = {**mine, "detector_version": "2026.10.3"}
    assert _version_mismatches(mine, other) == ["detector_version: this CLI 2026.10.5, "
                                                "daemon 2026.10.3"]
    assert _version_mismatches(mine, {"ok": True}) == [], "an older daemon says nothing"


@pytest.mark.parametrize("args", [
    ("simulate", "--min-score", "100"),
    ("doctor",),
    ("report", "--since", "1d"),
])
def test_commands_work_from_an_unrelated_folder(installed, args):
    if args[0] == "simulate":
        args = (*args, "--db", str(installed["home"] / "sim.db"))
    out = _cli(installed, *args)
    # doctor exits 1 when the daemon isn't running; it must still run cleanly
    assert out.returncode in (0, 1) and "Traceback" not in out.stderr, out.stderr[-1500:]
    if args[0] == "simulate":
        assert out.returncode == 0 and "100/100" in out.stdout


def test_replay_from_an_unrelated_folder(installed):
    projects = installed["work"] / "projects" / "D--x"
    projects.mkdir(parents=True)
    (projects / "s.jsonl").write_text(
        '{"sessionId":"s","cwd":"D:/x","message":{"content":[{"type":"tool_use",'
        '"id":"a","name":"Bash","input":{"command":"ls"}}]}}\n', encoding="utf-8")
    out = _cli(installed, "replay", "--projects-dir", str(installed["work"] / "projects"))
    assert out.returncode == 0 and "1 tool calls" in out.stdout, out.stderr


def test_report_uses_the_configured_dev_workspaces(installed, monkeypatch):
    from agentguard import report

    monkeypatch.setenv("AGENTGUARD_HOME", str(installed["home"]))
    monkeypatch.chdir(installed["cwd"])
    assert report._dev_workspaces(None) == ["devproj"]
