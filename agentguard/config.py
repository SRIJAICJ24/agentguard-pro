"""User configuration: `~/.agentguard/agentguard.json`.

Kept separate from `policy.py` on purpose, because the two answer different
questions and change on different schedules:

  * `agentguard.json`  - how this *installation* runs: port, mode, dashboard.
                         Machine-local, written by the onboarding wizard.
  * `agentguard.policy.yaml` - what the gateway *allows*. Project-local, belongs
                         in version control alongside the code it protects.

This module deliberately imports nothing else from agentguard, so that `db.py`,
`doctor.py` and the CLI can all depend on it without an import cycle.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CONFIG_FILENAME = "agentguard.json"

DEFAULT_PORT = 9000
DEFAULT_DASHBOARD_PORT = 9001

MODE_OBSERVE = "observe"
MODE_ENFORCE = "enforce"


class ConfigError(Exception):
    """Raised when a config file exists but cannot be used.

    Distinct from "no config yet", which is a normal first-run state rather than
    an error - `doctor` needs to tell those two apart to give a useful message.
    """


def agentguard_home() -> Path:
    """The local state directory. `AGENTGUARD_HOME` overrides it."""
    override = os.environ.get("AGENTGUARD_HOME")
    return Path(override) if override else Path.home() / ".agentguard"


def config_path() -> Path:
    return agentguard_home() / CONFIG_FILENAME


@dataclass
class Config:
    """One installation's settings."""

    mode: str = MODE_OBSERVE
    port: int = DEFAULT_PORT
    dashboard: bool = True
    dashboard_port: int = DEFAULT_DASHBOARD_PORT
    upstream: str | None = None
    agent: str | None = None
    role: str | None = None
    policy_file: str | None = None
    # Claude Code command hook (`agentguard hook`): what to do when the daemon is
    # down or slower than `hook_timeout` seconds. HTTP hooks always fail open;
    # that is Claude Code's behaviour, not a setting.
    hook_fail_mode: str = "open"
    hook_timeout: float = 2.0
    # F3: `doctor` warns when hooks are installed but no hook event has arrived
    # for this many hours - fail-open makes an outage otherwise invisible.
    hook_silence_hours: float = 24.0
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    updated_at: str | None = None
    version: int = 1

    # --- derived ----------------------------------------------------------
    @property
    def enforcement(self) -> bool:
        """`mode` is the stored form; `enforcement` is what the gateway wants."""
        return self.mode == MODE_ENFORCE

    def validate(self) -> list[str]:
        """Return a list of problems, empty if the config is usable."""
        problems: list[str] = []
        if self.mode not in (MODE_OBSERVE, MODE_ENFORCE):
            problems.append(
                f"mode must be '{MODE_OBSERVE}' or '{MODE_ENFORCE}', got {self.mode!r}"
            )
        for name, value in (("port", self.port), ("dashboard_port", self.dashboard_port)):
            if not isinstance(value, int) or isinstance(value, bool):
                problems.append(f"{name} must be an integer, got {value!r}")
            elif not (1 <= value <= 65535):
                problems.append(f"{name} must be between 1 and 65535, got {value}")
        if not isinstance(self.dashboard, bool):
            problems.append(f"dashboard must be true or false, got {self.dashboard!r}")
        if self.hook_fail_mode not in ("open", "closed"):
            problems.append(f"hook_fail_mode must be 'open' or 'closed', "
                            f"got {self.hook_fail_mode!r}")
        if not isinstance(self.hook_silence_hours, (int, float)) \
                or isinstance(self.hook_silence_hours, bool) or float(self.hook_silence_hours) <= 0:
            problems.append(f"hook_silence_hours must be a positive number of hours, "
                            f"got {self.hook_silence_hours!r}")
        if not isinstance(self.hook_timeout, (int, float)) or isinstance(self.hook_timeout, bool) \
                or not (0 < float(self.hook_timeout) <= 30):
            problems.append(f"hook_timeout must be a number of seconds in (0, 30], "
                            f"got {self.hook_timeout!r}")
        if not problems and self.dashboard and self.port == self.dashboard_port:
            problems.append(
                f"port and dashboard_port are both {self.port}; they must differ"
            )
        return problems

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def from_dict(data: dict[str, Any]) -> Config:
    """Build a Config from parsed JSON, ignoring keys we don't know.

    Unknown keys are dropped rather than raising, so a config written by a newer
    version still loads in an older one instead of bricking the install.
    """
    if not isinstance(data, dict):
        raise ConfigError(
            f"config must be a JSON object, found {type(data).__name__}"
        )
    known = {f for f in Config.__dataclass_fields__}
    return Config(**{k: v for k, v in data.items() if k in known})


def exists() -> bool:
    return config_path().is_file()


def load(path: str | Path | None = None) -> Config:
    """Load the config, or return defaults if there is no file yet.

    Raises ConfigError when a file exists but is unusable - a malformed config is
    a problem to report, not something to silently paper over with defaults.
    """
    target = Path(path) if path is not None else config_path()
    if not target.is_file():
        return Config()
    try:
        raw = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {target}: {exc}") from exc
    if not raw.strip():
        raise ConfigError(f"{target} is empty")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{target} is not valid JSON: {exc}") from exc

    config = from_dict(data)
    problems = config.validate()
    if problems:
        raise ConfigError(f"{target} has invalid values: " + "; ".join(problems))
    return config


def resolve_policy_path(explicit: str | Path | None = None) -> tuple[Path | None, str]:
    """Which policy file a command should use, and why.

    Most specific first: `--policy`, then `policy_file` in this installation's
    config (what the daemon was started with), then an agentguard.policy.yaml
    found from the current folder upward, then built-in defaults (None). Without
    the config step, a command run from another folder showed a different policy
    from the one the daemon enforces.
    """
    if explicit:
        return Path(explicit), "--policy"
    try:
        if exists():
            recorded = load().policy_file
            if recorded:
                return Path(recorded), f"policy_file in {config_path()}"
    except ConfigError:
        pass
    from agentguard.policy import find_policy_file

    found = find_policy_file()
    if found is not None:
        return found, f"found from {Path.cwd()}"
    return None, "built-in defaults (no policy file found)"


def save(config: Config, path: str | Path | None = None) -> Path:
    """Write the config, creating the home directory if needed."""
    problems = config.validate()
    if problems:
        raise ConfigError("refusing to save an invalid config: " + "; ".join(problems))

    target = Path(path) if path is not None else config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    config.updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    target.write_text(json.dumps(config.to_dict(), indent=2) + "\n", encoding="utf-8")
    return target
