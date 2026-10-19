"""Trusted delete folders, and deletes inside nested `bash -c "..."` scripts.

Real case (2026-10-16, review items #8 and #9): Claude ran a game's online test
through WSL - `wsl.exe -d Ubuntu -e bash -c "cd ~/bbtest && rm -rf logs && ..."`.
Enforce mode asked for permission each time. Two gaps: there was no way to say
"deletes inside ~/bbtest are fine", and the analysis never looked inside the
quoted `bash -c` script, so it couldn't tell where the delete landed.
"""

from __future__ import annotations

import pytest

SP = "C:/Users/me/AppData/Local/Temp/claude/D--GAME/9eb6425e/scratchpad"
# review item #9, anonymized and shortened
REAL_9 = (f'SP="{SP}"; rm -f "$SP/online/w"*.log; (wsl.exe -d Ubuntu -e bash -c '
          f'"cd ~/bbtest && rm -rf logs && timeout 220 python3 bb_lobby.py --bin '
          f'\\$HOME/bbtest/Server.x86_64 --port 25680 --log-dir \\$HOME/bbtest/logs '
          f"--extra '--low-spec --unlock-all'\" > \"$SP/online/wsl_lobby.log\" 2>&1 &); sleep 5")


def _engine(db_path, trusted=None):
    from agentguard.hooks import HookEngine
    from agentguard.policy import from_dict

    hooks = {} if trusted is None else {"trusted_delete_dirs": trusted}
    return HookEngine(from_dict({"hooks": hooks}), db_path=db_path)


def run(db_path, command, trusted=None):
    engine = _engine(db_path, trusted)
    engine.handle({"hook_event_name": "PreToolUse", "session_id": "s", "cwd": "D:/GAME",
                   "tool_name": "Bash", "tool_input": {"command": command},
                   "tool_use_id": "t"})
    return engine.events[-1]


TRUSTED_OK = [
    REAL_9,
    'wsl.exe -d Ubuntu -e bash -c "cd ~/bbtest && rm -rf logs"',
    "rm -rf ~/bbtest/logs",
    "rm -rf $HOME/bbtest/build ~/bbtest/logs/*",
    "cd ~/bbtest && rm -rf out",
    "bash -c 'cd ~/bbtest/run && rm -rf tmp'",
]


@pytest.mark.parametrize("command", TRUSTED_OK)
def test_deletes_inside_a_trusted_folder_are_logged_not_flagged(db_path, command):
    ev = run(db_path, command, trusted=["~/bbtest"])
    assert "hook:destructive_command" not in ev["signals"], ev
    assert "hook:delete_in_trusted_dir" in ev["signals"], ev
    assert ev["verdict"] == "ALLOW", ev


@pytest.mark.parametrize("command", TRUSTED_OK)
def test_without_the_setting_they_are_still_flagged(db_path, command):
    ev = run(db_path, command)
    assert "hook:destructive_command" in ev["signals"], ev


STILL_FLAGGED = [
    "rm -rf ~/bbtest",                                  # the folder itself
    "rm -rf ~/bbtest/../projects",                      # escapes it
    "cd ~/bbtest && rm -rf ../projects",
    "rm -rf ~/bbtest2/x",                               # prefix look-alike
    'wsl.exe -d Ubuntu -e bash -c "rm -rf ~/projects"',
    'bash -c "cd ~/bbtest && cd .. && rm -rf x"',
    'bash -c "cd ~/bbtest && rm -rf $UNKNOWN/x"',
    "rm -rf ~/bbtest/logs ~/Documents",                 # one trusted, one not
    'wsl.exe -e bash -c "cd ~/bbtest && rm -rf logs" && rm -rf ~/projects',
]


@pytest.mark.parametrize("command", STILL_FLAGGED)
def test_everything_else_is_still_flagged(db_path, command):
    ev = run(db_path, command, trusted=["~/bbtest"])
    assert "hook:destructive_command" in ev["signals"], ev
    assert ev["verdict"] in ("REVIEW", "BLOCK"), ev


@pytest.mark.parametrize("command", [
    "bash -c 'rm -rf /tmp/agx-build'",
    f'wsl.exe -e bash -c "rm -rf /tmp/agx-cache"',
])
def test_nested_deletes_in_temp_are_recognised_too(db_path, command):
    ev = run(db_path, command)
    assert "hook:delete_in_temp" in ev["signals"] and ev["verdict"] == "ALLOW", ev


@pytest.mark.parametrize("bad", ["~", "~/", "/", "C:/", "C:\\", "$HOME", "/home", "D:"])
def test_trusting_a_home_or_root_is_refused(bad):
    from agentguard.policy import from_dict

    with pytest.raises(ValueError):
        from_dict({"hooks": {"trusted_delete_dirs": [bad]}})
