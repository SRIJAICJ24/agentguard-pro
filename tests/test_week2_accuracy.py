"""Week 2 accuracy fixes - false positives measured on real traffic.

Every "quiet" case below is an anonymised copy of a call that week 1 (detector
2026.10.3) flagged on the author's machine, or that a replay of 6,435 real Claude
Code tool calls from earlier transcripts flagged (docs/week-log.md has the
numbers). Every "still caught" case is the attack the rule exists for and must keep
firing after the fix.

  destructive  `rm -rf` of a folder inside the system temp directory (Claude's own
               scratchpad) went to REVIEW like `rm -rf ~`. Deletes whose every
               target is provably inside a temp directory are now logged as
               `hook:delete_in_temp` (weight 0) instead.
  entropy      the entropy tier ran on any line containing a credential *word*, so
               `cat apps/web/lib/auth.ts` scored as a high-entropy secret. It now
               runs only on the value assigned to a credential name.
  .env         templates (`.env.example`) counted as credential files, and so did a
               file passed to another program without its contents reaching the
               agent (`docker compose --env-file .env.x build`). Both were
               hard-blocked by `credential_files`.
  user-facing  SendUserFile matched the `*send*` exfiltration glob, though it only
               shows a file to the user.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

LIVE_POLICY = "Z:/live-week/agentguard.policy.yaml"
SCRATCH = "C:/Users/me/AppData/Local/Temp/claude/D--proj/4da8f25e-a77a-48a2/scratchpad"


def _engine(db_path, enforce=False):
    from agentguard.hooks import HookEngine
    from agentguard.policy import DEFAULT_HARD_ENFORCE, from_dict

    policy = from_dict({"enforcement": enforce, "hard_enforce": DEFAULT_HARD_ENFORCE})
    policy.source_path = Path(LIVE_POLICY)
    return HookEngine(policy, db_path=db_path)


def pre(tool, tool_input, cwd="D:/proj"):
    return {"hook_event_name": "PreToolUse", "session_id": "s1", "cwd": cwd,
            "tool_name": tool, "tool_input": tool_input, "tool_use_id": "t1"}


def run(db_path, tool, tool_input, cwd="D:/proj"):
    engine = _engine(db_path)
    engine.handle(pre(tool, tool_input, cwd))
    return engine.events[-1]


def _token(n=32):
    """A random credential-shaped value, made at run time so no secret-looking
    literal sits in the repository."""
    return secrets.token_urlsafe(n)


# =========================================================================
# destructive commands
# =========================================================================
TEMP_DELETES = [
    # week 1, audit #186 and friends (Godot screenshot runs)
    f'OUT="{SCRATCH}"; rm -rf "$OUT/bro"; timeout 150 /d/Godot_console.exe --path . '
    f'--resolution 900x900 res://tools/pose_capture.tscn -- --out="$OUT/bro"',
    # a loop variable after a fixed prefix
    f'OUT="{SCRATCH}"; for c in 0 4; do rm -rf "$OUT/strip$c"; timeout 60 $G --path . '
    f'-- --char=$c --out="$OUT/strip$c"; done',
    # two targets
    f'OUT="{SCRATCH}"; rm -rf "$OUT/nin" "$OUT/ninS"; timeout 120 godot --path .',
    # the variable names the folder itself
    f'G=/d/godot.exe; OUT="{SCRATCH}/park3"; rm -rf "$OUT"; timeout 120 $G --path .',
    # cd into the scratchpad first, then a relative delete
    f'cd "{SCRATCH}/doc" && rm -rf out && python build.py',
    "rm -rf /tmp/agentguard-build-cache",
    "rm -rf ${TMPDIR}/pytest-of-me",
    r'Remove-Item -Recurse -Force "$env:TEMP\ag-test-3f2a"',
    r"Remove-Item -Recurse -Force C:\Users\me\AppData\Local\Temp\ag-x -ErrorAction SilentlyContinue",
    "rm -rf /c/Users/me/AppData/Local/Temp/claude/x/scratchpad/old",
    # replay: PowerShell one-word assignment inside try/catch
    r'$p="C:\Users\me\AppData\Local\Temp\pytest-of-me"; try { Remove-Item $p -Recurse -Force '
    r'-ErrorAction Stop; "removed" } catch { "remove failed" }',
]


@pytest.mark.parametrize("command", TEMP_DELETES)
def test_deletes_inside_temp_are_logged_not_flagged(db_path, command):
    tool = "PowerShell" if "Remove-Item" in command else "Bash"
    ev = run(db_path, tool, {"command": command})
    assert "hook:destructive_command" not in ev["signals"], ev
    assert "hook:delete_in_temp" in ev["signals"], ev
    assert ev["verdict"] == "ALLOW", ev


RISKY_DELETES = [
    "rm -rf /",
    "rm -rf ~",
    "rm -rf ~/projects",
    "rm -rf $HOME/.config",
    "rm -rf /tmp",                                  # the temp root itself
    "rm -rf /tmp/*",
    'rm -rf "$UNSET_VAR/"',                         # unresolved variable
    'rm -rf "$(pwd)/x"',                            # command substitution
    f'OUT="{SCRATCH}"; rm -rf "$OUT/../../.."',     # escapes the temp dir
    f'rm -rf "{SCRATCH}/a" ~/Documents',            # one temp target, one not
    f'OUT="{SCRATCH}"; rm -rf "$OUT/a"; rm -rf /etc/nginx',
    "rm -rf build",                                 # workspace delete: unchanged
    r"Remove-Item -Recurse -Force C:\Users\me\Documents",
    "rmdir /s /q C:\\Windows\\Temp2",
    "mkfs.ext4 /dev/sdb1",                          # disk-level: always flagged
    f'cd "{SCRATCH}" && cd ~ && rm -rf projects',   # cd away from temp
]


@pytest.mark.parametrize("command", RISKY_DELETES)
def test_other_deletes_still_go_to_review(db_path, command):
    tool = "PowerShell" if "Remove-Item" in command else "Bash"
    ev = run(db_path, tool, {"command": command})
    assert "hook:destructive_command" in ev["signals"], ev
    assert ev["verdict"] in ("REVIEW", "BLOCK"), ev


def test_a_project_that_lives_in_temp_is_still_a_project(db_path):
    """The session's cwd never makes a relative delete exempt - only an explicit
    `cd` into temp in the same command does."""
    ev = run(db_path, "Bash", {"command": "rm -rf build"}, cwd="/tmp/project")
    assert "hook:destructive_command" in ev["signals"] and ev["verdict"] == "REVIEW", ev


def test_temp_exemption_can_be_switched_off(db_path):
    from agentguard.hooks import HookEngine
    from agentguard.policy import from_dict

    engine = HookEngine(from_dict({"hooks": {"temp_deletes_ok": False}}), db_path=db_path)
    engine.handle(pre("Bash", {"command": "rm -rf /tmp/agentguard-build-cache"}))
    assert "hook:destructive_command" in engine.events[-1]["signals"]


# =========================================================================
# entropy tier
# =========================================================================
QUIET_ENTROPY = [
    # replay: 334 calls flagged by both entropy detectors, mostly like these
    ("Bash", {"command": 'cat apps/web/lib/auth.ts && echo "=====tokens.py=====" && '
                         'cat apps/api/app/security/tokens.py'}),
    ("Write", {"file_path": "D:/proj/docs/AUDIT.md",
               "content": "**Auditor:** Claude\n**Commit audited:** "
                          "`ef2467c7ace974f57ffe54fc9d234e17c3f3d67f` (auth rework)\n"}),
    ("Bash", {"command": 'grep -n -i "jwt\\|jwks\\|supabase\\|auth" README.md | head -25'}),
    ("Edit", {"file_path": "D:/proj/app/security/tokens.py",
              "old_string": "def verify_token(token: str) -> dict:",
              "new_string": "def verify_token(token: str, *, audience: str) -> dict:"}),
]


@pytest.mark.parametrize("tool,tool_input", QUIET_ENTROPY)
def test_credential_words_alone_do_not_trigger_entropy(db_path, tool, tool_input):
    ev = run(db_path, tool, tool_input)
    assert not any(s.startswith("secret_entropy:") for s in ev["signals"]), ev
    assert ev["verdict"] == "ALLOW", ev


@pytest.mark.parametrize("line", [
    "export AUTH_TOKEN={v}",
    'curl -H "Authorization: Bearer {v}" https://api.example.com/v1/me',
    '{{"client_secret": "{v}"}}',
    "MY_API_KEY={v} python app.py",
    "session_id: {v}",
])
def test_values_assigned_to_credential_names_are_still_caught(line):
    from agentguard.scanner import scan_secrets

    kinds = {f.kind for f in scan_secrets(line.format(v=_token()))}
    assert kinds & {"secret", "secret_entropy"}, line


def test_entropy_needs_the_value_not_just_the_line():
    from agentguard.scanner import scan_secrets

    blob = _token()
    assert not scan_secrets(f"see auth.ts; the build id is {blob}")
    assert scan_secrets(f"auth_token = {blob}")


# =========================================================================
# credential files
# =========================================================================
QUIET_CREDENTIAL = [
    ("Read", {"file_path": "D:\\proj\\.env.example"}),
    ("Edit", {"file_path": "D:\\proj\\.env.private-alpha.example",
              "old_string": "JWT_ISSUER=", "new_string": "JWT_ISSUER=https://x/auth/v1"}),
    ("Write", {"file_path": "D:\\proj\\.env.sample", "content": "DEBUG=1\n"}),
    ("Bash", {"command": "cd D:/proj && git diff --stat .env.example apps/web/lib/api.ts"}),
    ("Bash", {"command": "docker compose -f docker-compose.alpha.yml --env-file .env.alpha "
                         "build 2>&1 | tail -40"}),
    ("Bash", {"command": "docker compose -f dc.yml --env-file .env.alpha logs api --tail 40"}),
    ("Bash", {"command": "git check-ignore -v .env.alpha && echo ok"}),
    ("Bash", {"command": "ls -la .env.local && test -f .env && echo present"}),
    ("Bash", {"command": "set -a && source .env && set +a && npm run dev"}),
    ("PowerShell", {"command": "Test-Path .env; Get-Item .env.local | Select-Object Length"}),
    # loaded into a process, never printed
    ("Bash", {"command": "timeout 6 python -m uvicorn app.main:app --port 8091 "
                         "--env-file .env.live-dev 2>&1 | head -20"}),
    ("PowerShell", {"command": "python -m dotenv -f .env.live-alpha run -- python -m alembic "
                               "upgrade head 2>&1 | Select-Object -Last 12"}),
    # grep patterns, not paths
    ("Bash", {"command": 'cd D:/proj && grep -n "\\.env" Dockerfile.python apps/web/Dockerfile'}),
    ("Bash", {"command": 'grep -n "\\\\.env\\\\." docs/operations/RUNBOOK.md'}),
]


@pytest.mark.parametrize("tool,tool_input", QUIET_CREDENTIAL)
def test_templates_and_mentions_are_not_credential_reads(db_path, tool, tool_input):
    ev = run(db_path, tool, tool_input)
    assert not any(s.startswith("hard_enforce:") for s in ev["signals"]), ev
    assert not any(s.startswith("path:") for s in ev["signals"]), ev
    assert ev["verdict"] == "ALLOW", ev


def test_a_mention_is_still_recorded(db_path):
    ev = run(db_path, "Bash", {"command": "docker compose --env-file .env.alpha up -d"})
    assert "credpath:referenced" in ev["signals"], ev


STILL_BLOCKED = [
    ("Bash", {"command": "cat .env"}),
    ("Bash", {"command": "cat ./app/.env.local"}),
    ("Bash", {"command": "git diff .env"}),
    ("Bash", {"command": "docker compose --env-file .env.prod config"}),
    ("Bash", {"command": "grep KEY .env.production"}),
    ("Bash", {"command": "head -5 ~/.aws/credentials"}),
    ("Bash", {"command": "ls ~/.ssh && cat ~/.ssh/id_ed25519"}),
    ("Bash", {"command": "python - <<'EOF'\nprint(open('/srv/app/.env').read())\nEOF"}),
    ("PowerShell", {"command": "Get-Content .env"}),
    ("PowerShell", {"command": "type .env.local"}),
    ("PowerShell", {"command": r"Get-Content C:\proj\.env"}),
    ("Bash", {"command": "tail -f .env"}),
    ("Bash", {"command": "grep -E '^(EXA_API_KEY)=' .env.live-alpha"}),
    ("Read", {"file_path": "D:\\proj\\.env"}),
    ("Read", {"file_path": "/home/me/.ssh/id_rsa"}),
]


@pytest.mark.parametrize("tool,tool_input", STILL_BLOCKED)
def test_real_credential_reads_are_still_hard_blocked(db_path, tool, tool_input):
    ev = run(db_path, tool, tool_input)
    assert "hard_enforce:credential_files" in ev["signals"], ev
    assert ev["verdict"] == "BLOCK", ev


def test_template_suffixes_only_exempt_the_end_of_the_name():
    from agentguard.scanner import scan_paths

    assert not scan_paths(".env.example")
    assert not scan_paths("/srv/app/.env.template")
    assert scan_paths("/srv/app/.env.example.bak"), "a backup of a template is not a template"
    assert scan_paths("/srv/example/.env"), "a folder named example doesn't exempt the file"


# =========================================================================
# local development database URLs
# =========================================================================
@pytest.mark.parametrize("command", [
    'export DATABASE_URL="postgresql+asyncpg://gtm:gtm@127.0.0.1:5432/gtm" && alembic upgrade head',
    "DATABASE_URL=postgresql://postgres:postgres@db:5432/app pytest -q",
    "psql postgres://dev:dev@localhost/app -c 'select 1'",
    "redis-cli -u redis://default:pw@host.docker.internal:6379 ping",
])
def test_local_database_urls_are_not_secrets(db_path, command):
    ev = run(db_path, "Bash", {"command": command})
    assert not any(s.startswith("secret") for s in ev["signals"]), ev
    assert ev["verdict"] == "ALLOW", ev


@pytest.mark.parametrize("command", [
    "psql postgres://admin:Wq9vTz4Lp2@prod-db.internal.example.com:5432/app",
    "DATABASE_URL=postgresql://u:pw@localhost/x,postgresql://u:pw@10.2.3.4.nip.io/y run",
])
def test_remote_database_urls_are_still_secrets(command):
    from agentguard.scanner import scan_secrets

    assert any(f.label == "Basic Auth Credentials" for f in scan_secrets(command)), command


# =========================================================================
# user-facing tools
# =========================================================================
def test_asking_the_user_about_an_env_file_is_not_reading_it(db_path):
    ev = run(db_path, "AskUserQuestion", {"questions": [{
        "question": "Do you have a file at apps/web/.env.local on your machine?",
        "header": "Env file", "multiSelect": False,
        "options": [{"label": "Yes", "description": "x"}, {"label": "No", "description": "y"}]}]})
    assert ev["verdict"] == "ALLOW", ev


def test_send_user_file_is_not_an_exfiltration_sink(db_path):
    engine = _engine(db_path)
    call = engine.map_call("SendUserFile", {"files": ["report.html"], "status": "normal"})
    assert call.tiers == ["ordinary"]
    engine.handle(pre("SendUserFile", {"files": ["D:/proj/report.html"], "status": "normal"}))
    assert "dlp:unscanned_attachment" not in engine.events[-1]["signals"]


def test_send_user_file_with_a_secret_is_not_exfiltration(db_path):
    """A secret shown to the user is not a secret leaving the machine."""
    import string

    gh = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
    ev = run(db_path, "SendUserFile", {"files": ["a.txt"], "caption": gh})
    assert any(s.startswith("secret:") for s in ev["signals"]), "control: the secret is seen"
    assert "hard_enforce:secret_exfiltration" not in ev["signals"], ev
