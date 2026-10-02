"""F5 - self-protection guards the LIVE setup, not every file with the same name.

Live = the policy file the daemon actually loads (and the one recorded in
agentguard.json), the live AGENTGUARD_HOME, and the Claude Code settings files
that register AgentGuard's hooks. A second copy of agentguard.policy.yaml - the
repository's, where AgentGuard is developed - is ordinary work.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def live(monkeypatch):
    """A live install: AGENTGUARD_HOME with a config naming the live policy file
    (outside the repo), Claude settings with AgentGuard's hooks, and a repo copy."""
    base = Path(tempfile.mkdtemp(prefix="ag-live-"))
    home = base / "home" / ".agentguard"
    claude = base / "claude"
    week = base / "agentguard-week"
    repo = base / "dev" / "agentgaurd"
    for d in (home, claude, week, repo):
        d.mkdir(parents=True)
    shutil.copy(ROOT / "agentguard.policy.yaml", week / "agentguard.policy.yaml")
    shutil.copy(ROOT / "agentguard.policy.yaml", repo / "agentguard.policy.yaml")
    monkeypatch.setenv("AGENTGUARD_HOME", str(home))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(claude))

    from agentguard import config as cfg
    from agentguard import hookinstall

    cfg.save(cfg.Config(policy_file=str(week / "agentguard.policy.yaml")))
    hookinstall.install(claude / "settings.json")
    try:
        yield {"base": base, "home": home, "claude": claude,
               "live_policy": week / "agentguard.policy.yaml",
               "repo_policy": repo / "agentguard.policy.yaml", "repo": repo}
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _engine(live, enforce=False):
    from agentguard.hooks import HookEngine
    from agentguard.policy import load

    policy = load(live["live_policy"])           # what the daemon loads
    policy.enforcement = enforce
    return HookEngine(policy, db_path=str(live["base"] / "t.db"))


def pre(tool, tool_input):
    return {"hook_event_name": "PreToolUse", "session_id": "s", "cwd": "/tmp/p",
            "tool_name": tool, "tool_input": tool_input, "tool_use_id": "t"}


def decision(r):
    return (r.get("hookSpecificOutput") or {}).get("permissionDecision")


def _signals(engine):
    return engine.events[-1]["signals"]


EDIT = {"old_string": "enforcement: false", "new_string": "enforcement: true"}


def test_editing_the_repo_policy_copy_is_allowed(live):
    engine = _engine(live)
    for tool, ti in [("Edit", {"file_path": str(live["repo_policy"]), **EDIT}),
                     ("Write", {"file_path": str(live["repo_policy"]), "content": "enforcement: true\n"}),
                     ("Bash", {"command": f"sed -i 's/false/true/' {live['repo_policy'].as_posix()}"}),
                     ("Bash", {"command": "sed -i 's/false/true/' ./agentguard.policy.yaml"}),
                     ("Bash", {"command": "git diff agentguard.policy.yaml"})]:
        assert engine.handle(pre(tool, ti)) == {}, (tool, ti)
        assert "selfprotect:tamper" not in _signals(engine), (tool, ti)


def test_editing_the_live_policy_is_blocked_even_in_observe_mode(live):
    engine = _engine(live)
    for tool, ti in [("Edit", {"file_path": str(live["live_policy"]), **EDIT}),
                     ("Write", {"file_path": str(live["live_policy"]).replace("/", "\\"),
                                "content": "hard_enforce: []\n"}),
                     ("Bash", {"command": f"sed -i 's/false/true/' {live['live_policy'].as_posix()}"})]:
        r = engine.handle(pre(tool, ti))
        assert decision(r) == "deny", (tool, ti)
        assert "hard_enforce:self_protection" in _signals(engine)


def test_live_home_and_hook_settings_are_protected(live):
    engine = _engine(live)
    for tool, ti in [
        ("Write", {"file_path": str(live["home"] / "agentguard.json"), "content": "{}"}),
        ("Bash", {"command": f"sqlite3 {live['home'].as_posix()}/agentguard.db 'delete from audit'"}),
        ("Edit", {"file_path": str(live["claude"] / "settings.json"),
                  "old_string": "PreToolUse", "new_string": "X"}),
    ]:
        assert decision(engine.handle(pre(tool, ti))) == "deny", (tool, ti)


def test_project_settings_registering_the_hooks_are_protected_others_are_not(live):
    from agentguard import hookinstall

    project = live["base"] / "someproj" / ".claude"
    project.mkdir(parents=True)
    plain = project / "settings.local.json"
    plain.write_text(json.dumps({"permissions": {"allow": ["Bash(npm test)"]}}), encoding="utf-8")
    guarded = project / "settings.json"
    hookinstall.install(guarded)

    engine = _engine(live)
    assert engine.handle(pre("Write", {"file_path": str(plain), "content": '{"theme": "dark"}'})) == {}
    assert decision(engine.handle(pre("Write", {"file_path": str(guarded), "content": "{}"}))) == "deny"
    # ...but any settings write that switches all hooks off is tampering, wherever it is.
    assert decision(engine.handle(pre("Write", {"file_path": str(plain),
                                                "content": '{"disableAllHooks": true}'}))) == "deny"


def test_a_generic_dot_agentguard_elsewhere_is_not_protected(live):
    """Only the live AGENTGUARD_HOME counts, not any folder with that name."""
    engine = _engine(live)
    other = live["base"] / "scratch" / ".agentguard" / "agentguard.json"
    assert engine.handle(pre("Write", {"file_path": str(other), "content": "{}"})) == {}


async def test_gateway_protects_the_live_policy_but_not_the_repo_copy(live, upstream):
    from agentguard.gateway import build_gateway
    from agentguard.policy import load

    policy = load(live["live_policy"])
    proxy, guard = build_gateway(upstream, policy=policy, db_path=str(live["base"] / "g.db"))
    async with Client(proxy) as client:
        out = await client.call_tool("filesystem.write",
                                     {"path": str(live["repo_policy"]), "content": "x"})
        assert out
        with pytest.raises(ToolError) as exc:
            await client.call_tool("filesystem.write",
                                   {"path": str(live["live_policy"]), "content": "x"})
    assert "hard-enforced" in str(exc.value)


# --- onboarding records the live policy ------------------------------------
def test_onboard_policy_dir_records_the_live_copy(live, capsys):
    from agentguard import config as cfg
    from agentguard.cli import main

    before = live["live_policy"].read_text(encoding="utf-8")
    assert main(["onboard", "--non-interactive", "--policy-dir",
                 str(live["live_policy"].parent)]) == 0
    assert cfg.load().policy_file == str(live["live_policy"].resolve())
    assert live["live_policy"].read_text(encoding="utf-8") == before, "existing policy kept"

    from agentguard.cli import build_parser
    from agentguard.onboarding import _gateway_args
    args = build_parser().parse_args(_gateway_args(cfg.load()))
    assert args.policy == str(live["live_policy"].resolve())


# --- the service runs the venv's agentguard ---------------------------------
def test_daemon_command_prefers_the_agentguard_next_to_the_interpreter(monkeypatch):
    from agentguard import onboarding

    venv = Path(tempfile.mkdtemp(prefix="ag-venv-"))
    try:
        scripts = venv / ("Scripts" if sys.platform == "win32" else "bin")
        scripts.mkdir()
        exe = scripts / ("agentguard.exe" if sys.platform == "win32" else "agentguard")
        exe.write_text("")
        monkeypatch.setattr(onboarding.sys, "executable", str(scripts / "python.exe"))
        # Even with a *different* agentguard on PATH, the interpreter's own wins.
        monkeypatch.setattr(onboarding.shutil, "which", lambda _n: r"C:\elsewhere\agentguard.exe")
        assert onboarding._console_parts() == [str(exe)]
    finally:
        shutil.rmtree(venv, ignore_errors=True)
