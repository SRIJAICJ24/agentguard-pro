"""`agentguard daemon status|stop` - find and stop the background daemon.

The daemon writes its pid to AGENTGUARD_HOME/daemon.pid while it runs. On Windows
the service is a launcher script that restarts the daemon if it exits, so stopping
it also drops a `daemon.stop` flag that tells the launcher not to restart.
"""

from __future__ import annotations

import json
import os
import signal
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from agentguard import config as cfg

PID_FILE = "daemon.pid"
STOP_FLAG = "daemon.stop"


@dataclass
class DaemonStatus:
    pid: int | None
    port: int
    running: bool
    mode: str | None
    detail: str


def _pid() -> int | None:
    try:
        return int((cfg.agentguard_home() / PID_FILE).read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def probe(port: int, timeout: float = 1.0) -> dict | None:
    """GET /hooks/health on the daemon; None if nothing answers like AgentGuard."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"http://127.0.0.1:{port}/hooks/health", timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("service") == "agentguard" else None


def status() -> DaemonStatus:
    try:
        port = cfg.load().port
    except cfg.ConfigError:
        port = cfg.DEFAULT_PORT
    health = probe(port)
    pid = _pid()
    if health:
        return DaemonStatus(pid, port, True, health.get("mode"),
                            f"answering on http://127.0.0.1:{port}/hooks/claude-code")
    return DaemonStatus(pid, port, False, None,
                        f"nothing answering on port {port}"
                        + (f" (stale pid file: {pid})" if pid else ""))


def render_status(s: DaemonStatus) -> str:
    state = f"running ({s.mode} mode)" if s.running else "not running"
    lines = [f"  daemon : {state}", f"  port   : {s.port}", f"  detail : {s.detail}"]
    if s.pid:
        lines.insert(1, f"  pid    : {s.pid}")
    return "\n".join(lines)


def stop() -> tuple[bool, str]:
    home = cfg.agentguard_home()
    home.mkdir(parents=True, exist_ok=True)
    (home / STOP_FLAG).write_text("stop requested by `agentguard daemon stop`\n",
                                  encoding="utf-8")
    pid = _pid()
    if pid is None:
        return True, ("no pid file - the daemon doesn't look like it's running "
                      "(stop flag set, so a launcher won't restart it)")
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        # POSIX: ProcessLookupError. Windows: WinError 87 (invalid parameter).
        if isinstance(exc, ProcessLookupError) or getattr(exc, "winerror", None) == 87:
            (home / PID_FILE).unlink(missing_ok=True)
            return True, f"pid {pid} was not running; cleared the stale pid file"
        return False, f"could not stop pid {pid}: {exc}"
    (home / PID_FILE).unlink(missing_ok=True)
    return True, (f"stopped the daemon (pid {pid}). While stopped, Claude Code hooks "
                  f"fail open - nothing is checked. Start it again with the service "
                  f"(schtasks /Run /TN AgentGuard on Windows) or `agentguard proxy`.")


def clear_stop_flag(home: Path | None = None) -> None:
    (home or cfg.agentguard_home()).joinpath(STOP_FLAG).unlink(missing_ok=True)
