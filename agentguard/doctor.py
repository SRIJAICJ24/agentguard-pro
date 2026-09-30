"""`agentguard doctor` - preflight checks with actionable output.

Each check returns a `CheckResult` rather than raising, so one failure does not
hide the others: a broken config and a tampered audit chain are separate problems
and the user should see both in one run. Every failure carries a `hint` naming the
next action, because "FAIL: config invalid" on its own is not help.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from agentguard import config as cfg

STATUS_PASS = "PASS"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"


@dataclass
class CheckResult:
    name: str
    status: str
    detail: str = ""
    hint: str = ""

    @property
    def ok(self) -> bool:
        """WARN is not a failure - it means usable but worth knowing."""
        return self.status in (STATUS_PASS, STATUS_WARN)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "status": self.status,
                "detail": self.detail, "hint": self.hint}


@dataclass
class DoctorReport:
    results: list[CheckResult]

    @property
    def ok(self) -> bool:
        return all(r.ok for r in self.results)

    @property
    def failures(self) -> list[CheckResult]:
        return [r for r in self.results if r.status == STATUS_FAIL]

    @property
    def warnings(self) -> list[CheckResult]:
        return [r for r in self.results if r.status == STATUS_WARN]

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "checks": [r.to_dict() for r in self.results]}


# --- individual checks -----------------------------------------------------
def check_config() -> tuple[CheckResult, cfg.Config | None]:
    """Config file exists, parses, and holds usable values.

    Returns the loaded config too, since later checks need the port from it.
    """
    path = cfg.config_path()
    if not path.is_file():
        return (
            CheckResult(
                "config file", STATUS_WARN,
                f"no config at {path} (using built-in defaults)",
                "run `agentguard onboard` to create one",
            ),
            cfg.Config(),
        )
    try:
        config = cfg.load()
    except cfg.ConfigError as exc:
        return (
            CheckResult(
                "config file", STATUS_FAIL, str(exc),
                "fix the file by hand, or re-run `agentguard onboard` to rewrite it",
            ),
            None,
        )
    return (
        CheckResult("config file", STATUS_PASS,
                    f"{path} (mode: {config.mode}, port: {config.port})"),
        config,
    )


def _port_is_free(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def _probe_http(port: int, path: str, timeout: float = 1.0) -> int | None:
    """Return an HTTP status code from a bare GET, or None if nothing answered."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
            sock.sendall(
                f"GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n".encode()
            )
            data = sock.recv(256).decode("latin-1", errors="replace")
    except OSError:
        return None
    parts = data.split(" ", 2)
    if len(parts) >= 2 and parts[0].startswith("HTTP/"):
        try:
            return int(parts[1])
        except ValueError:
            return None
    return None


def check_port(port: int, label: str = "gateway port") -> CheckResult:
    """Port is free, or already held by something that looks like AgentGuard.

    Identification is best-effort: without inspecting the process table we cannot
    prove who owns a socket, so a responding MCP endpoint is reported as "probably
    AgentGuard" rather than asserted as fact.
    """
    if _port_is_free(port):
        return CheckResult(label, STATUS_PASS, f"port {port} is free")

    status = _probe_http(port, "/mcp")
    if status is not None:
        return CheckResult(
            label, STATUS_PASS,
            f"port {port} is in use and answering on /mcp (HTTP {status}) - "
            f"probably AgentGuard already running",
            "if this is not AgentGuard, stop it or pick another port with "
            "`agentguard configure`",
        )
    return CheckResult(
        label, STATUS_FAIL,
        f"port {port} is in use by something that does not answer on /mcp",
        f"stop whatever holds port {port}, or run `agentguard configure` to change it",
    )


def check_policy(policy_path: str | Path | None = None) -> CheckResult:
    from agentguard import policy as policy_mod

    target = Path(policy_path) if policy_path else policy_mod.find_policy_file()
    if target is None:
        return CheckResult(
            "policy file", STATUS_WARN,
            "no agentguard.policy.yaml found (built-in defaults apply)",
            "run `agentguard onboard` to generate a starter policy",
        )
    if not target.is_file():
        return CheckResult(
            "policy file", STATUS_FAIL, f"{target} does not exist",
            "correct the path or run `agentguard onboard`",
        )
    try:
        loaded = policy_mod.load(target)
    except Exception as exc:                                   # noqa: BLE001
        # yaml raises several unrelated exception types; the user needs the message,
        # not the class name.
        return CheckResult(
            "policy file", STATUS_FAIL, f"{target} failed to parse: {exc}",
            "check the YAML indentation and syntax",
        )
    mode = "ENFORCING" if loaded.enforcement else "observe (log only)"
    return CheckResult("policy file", STATUS_PASS,
                       f"{target} parses ({len(loaded.roles)} roles, {mode})")


def check_database() -> CheckResult:
    from agentguard.db import connect, default_db_path

    path = default_db_path()
    try:
        conn = connect()
        conn.execute("SELECT COUNT(*) FROM audit").fetchone()
    except Exception as exc:                                   # noqa: BLE001
        return CheckResult(
            "audit database", STATUS_FAIL, f"{path} is not usable: {exc}",
            "check permissions on the directory, or move it with AGENTGUARD_HOME",
        )
    return CheckResult("audit database", STATUS_PASS, f"{path} is reachable")


def check_audit_chain() -> CheckResult:
    """Reuses the Stage 1 hash-chain verification."""
    from agentguard import audit

    try:
        intact, broken = audit.verify_chain()
    except Exception as exc:                                   # noqa: BLE001
        return CheckResult(
            "audit chain", STATUS_FAIL, f"could not verify: {exc}",
            "the database may be corrupt; inspect it before trusting the log",
        )
    if intact:
        return CheckResult("audit chain", STATUS_PASS, "hash chain verifies cleanly")
    return CheckResult(
        "audit chain", STATUS_FAIL,
        f"hash chain is broken starting at row {broken}",
        "the audit log has been modified since it was written - treat entries from "
        f"row {broken} onward as untrustworthy and investigate",
    )


def check_dependencies() -> CheckResult:
    """The two libraries the design depends on being present and importable."""
    missing: list[str] = []
    for module, label in (("fastmcp", "fastmcp"), ("detect_secrets", "detect-secrets")):
        try:
            __import__(module)
        except ImportError:
            missing.append(label)
    if missing:
        return CheckResult(
            "dependencies", STATUS_FAIL, f"missing: {', '.join(missing)}",
            "reinstall with `pip install -e .`",
        )
    import fastmcp

    return CheckResult("dependencies", STATUS_PASS,
                       f"fastmcp {fastmcp.__version__}, detect-secrets present")


# --- runner ----------------------------------------------------------------
def run(policy_path: str | Path | None = None) -> DoctorReport:
    """Run every check. Never raises - problems come back as FAIL results."""
    results: list[CheckResult] = []

    results.append(check_dependencies())

    config_result, config = check_config()
    results.append(config_result)

    if config is not None:
        results.append(check_port(config.port, "gateway port"))
        if config.dashboard:
            results.append(check_port(config.dashboard_port, "dashboard port"))

    results.append(check_policy(policy_path or (config.policy_file if config else None)))
    results.append(check_database())
    results.append(check_audit_chain())
    return DoctorReport(results)


def render(report: DoctorReport, colorize: Callable[[str, str], str] | None = None) -> str:
    """Format a report as a pass/fail list."""
    def paint(text: str, status: str) -> str:
        return colorize(text, status) if colorize else text

    width = max(len(r.name) for r in report.results)
    lines: list[str] = []
    for r in report.results:
        lines.append(f"  {paint(r.status.ljust(4), r.status)}  {r.name.ljust(width)}  {r.detail}")
        if r.hint and r.status != STATUS_PASS:
            lines.append(f"        {' ' * width}  -> {r.hint}")

    lines.append("")
    if report.ok:
        note = "all checks passed" if not report.warnings else (
            f"usable, with {len(report.warnings)} warning(s)"
        )
        lines.append(f"  {paint(note, STATUS_PASS)}")
    else:
        lines.append(f"  {paint(f'{len(report.failures)} check(s) failed', STATUS_FAIL)}")
    return "\n".join(lines)
