"""`agentguard hook` - the command-hook fallback. Standard library only.

Claude Code runs this once per hook event, so it must start fast and must never
hang the agent. It imports nothing outside the standard library (no fastmcp, no
yaml, no detect-secrets): it reads the event from stdin, forwards it to the
running AgentGuard daemon, and prints the daemon's answer.

    python -m agentguard.hookclient          (what install-hooks registers)
    python -m agentguard.cli hook            (same thing, via the CLI)

When the daemon is down or slow
-------------------------------
A short timeout (default 2 s), then:

  fail-open  (default)  exit 0, no output: Claude Code's normal permission flow
                        applies, as if AgentGuard weren't installed. The reason
                        goes to stderr, which Claude Code keeps in its debug log.
  fail-closed           a PreToolUse event exits 2, which Claude Code treats as a
                        block; other events still exit 0 (they can't be blocked).

Set it in ~/.agentguard/agentguard.json (`hook_fail_mode`, `hook_timeout`) or with
the AGENTGUARD_HOOK_FAIL_MODE / AGENTGUARD_HOOK_TIMEOUT environment variables.

An HTTP hook (the default install) can't fail closed at all: Claude Code treats a
connection failure or timeout of an HTTP hook as a non-blocking error. Anyone who
needs fail-closed has to use this command hook.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import IO, Any

HOOK_PATH = "/hooks/claude-code"
DEFAULT_PORT = 9000
DEFAULT_TIMEOUT = 2.0
FAIL_OPEN = "open"
FAIL_CLOSED = "closed"


def _home() -> Path:
    override = os.environ.get("AGENTGUARD_HOME")
    return Path(override) if override else Path.home() / ".agentguard"


def settings() -> dict[str, Any]:
    """Port, timeout and failure mode: config file, then environment overrides."""
    out: dict[str, Any] = {"port": DEFAULT_PORT, "timeout": DEFAULT_TIMEOUT,
                           "fail_mode": FAIL_OPEN}
    try:
        data = json.loads((_home() / "agentguard.json").read_text(encoding="utf-8"))
        if isinstance(data, dict):
            out["port"] = int(data.get("port", out["port"]))
            out["timeout"] = float(data.get("hook_timeout", out["timeout"]))
            out["fail_mode"] = str(data.get("hook_fail_mode", out["fail_mode"]))
    except (OSError, ValueError, TypeError):
        pass                      # no or unusable config: defaults
    env = os.environ
    if env.get("AGENTGUARD_HOOK_TIMEOUT"):
        try:
            out["timeout"] = float(env["AGENTGUARD_HOOK_TIMEOUT"])
        except ValueError:
            pass
    if env.get("AGENTGUARD_HOOK_FAIL_MODE"):
        out["fail_mode"] = env["AGENTGUARD_HOOK_FAIL_MODE"]
    out["fail_mode"] = FAIL_CLOSED if str(out["fail_mode"]).lower() == FAIL_CLOSED \
        else FAIL_OPEN
    out["url"] = env.get("AGENTGUARD_HOOK_URL") or \
        f"http://127.0.0.1:{out['port']}{HOOK_PATH}"
    return out


def forward(body: bytes, url: str, timeout: float) -> bytes:
    """POST the event to the daemon. Proxies are bypassed: this is loopback."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
    with opener.open(request, timeout=timeout) as response:
        return response.read()


def main(stdin: IO[bytes] | None = None, stdout: IO[str] | None = None,
         stderr: IO[str] | None = None) -> int:
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    conf = settings()

    raw = stdin.read()
    try:
        event = json.loads(raw.decode("utf-8", "replace")).get("hook_event_name")
    except (ValueError, AttributeError):
        event = None

    try:
        reply = forward(raw, conf["url"], conf["timeout"]).decode("utf-8", "replace").strip()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        if conf["fail_mode"] == FAIL_CLOSED and event == "PreToolUse":
            stderr.write(f"AgentGuard daemon unreachable at {conf['url']} ({reason}); "
                         f"failing closed. Start it with `agentguard proxy`, or set "
                         f"hook_fail_mode to open.\n")
            return 2
        stderr.write(f"AgentGuard daemon unreachable ({reason}); failing open.\n")
        return 0

    if reply:
        # Only ever relay a JSON object; anything else would make Claude Code
        # report a hook error instead of running the normal permission flow.
        try:
            parsed = json.loads(reply)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            stdout.write(reply)
    return 0


if __name__ == "__main__":
    sys.exit(main())
