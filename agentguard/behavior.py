"""Behaviour monitoring and the kill switch.

Not every threat is an attacker. An agent stuck in a retry loop hammering
`filesystem.delete`, or a compromised one enumerating an API as fast as it can,
looks nothing like a prompt injection but does real damage. This module watches
call *rate* rather than call content.

The baseline is learned per (agent, tool) as a rolling mean of calls per minute.
Until `MIN_OBSERVATIONS` samples exist for a tool, no anomaly can fire - a cold
system must not block the first few calls it has ever seen just because it has
nothing to compare them to.

The kill switch is separate and manual: it revokes everything for a session
immediately, and only a human clears it.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from agentguard.decision import Signal
from agentguard.risk import W_VELOCITY

# Rolling window over which call rate is measured.
WINDOW_SECONDS = 60.0

# How many windows must be observed before a baseline is trusted.
MIN_OBSERVATIONS = 5

# A burst this many times the learned mean is an anomaly.
SPIKE_MULTIPLIER = 4.0

# Absolute ceiling per window regardless of baseline - catches a runaway loop on a
# cold system, where no baseline exists yet.
HARD_RATE_CEILING = 60


@dataclass
class ToolStats:
    """Rolling call history for one (agent, tool) pair.

    `observed_rates` is sampled at most once per window (see `last_trained_at`).
    Training on every call instead would let the baseline learn a rising rate as it
    happened: each call nudges the mean up, the spike threshold rises with it, and a
    slow ramp is never flagged. Sampling per window keeps the baseline a measure of
    normal *history* rather than of the burst currently in progress.
    """

    events: deque[float] = field(default_factory=deque)
    observed_rates: list[int] = field(default_factory=list)
    last_trained_at: float | None = None

    def prune(self, now: float) -> None:
        while self.events and now - self.events[0] > WINDOW_SECONDS:
            self.events.popleft()

    @property
    def rate(self) -> int:
        return len(self.events)

    @property
    def baseline(self) -> float | None:
        if len(self.observed_rates) < MIN_OBSERVATIONS:
            return None
        return sum(self.observed_rates) / len(self.observed_rates)

    def may_train(self, now: float) -> bool:
        return self.last_trained_at is None or \
            (now - self.last_trained_at) >= WINDOW_SECONDS


@dataclass
class BehaviorAssessment:
    anomaly: bool
    signals: list[Signal] = field(default_factory=list)
    rate: int = 0
    baseline: float | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"anomaly": self.anomaly, "rate": self.rate,
                "baseline": self.baseline, "detail": self.detail}


class BehaviorMonitor:
    """Per-agent velocity baselines plus a manual kill switch."""

    def __init__(self) -> None:
        self._stats: dict[tuple[str, str], ToolStats] = defaultdict(ToolStats)
        self._locked: dict[str, str] = {}     # session_id -> reason

    # --- kill switch ------------------------------------------------------
    def kill(self, session_id: str, reason: str = "manual kill switch") -> None:
        self._locked[session_id] = reason

    def release(self, session_id: str) -> None:
        self._locked.pop(session_id, None)

    def is_locked(self, session_id: str) -> str | None:
        return self._locked.get(session_id)

    @property
    def locked_sessions(self) -> dict[str, str]:
        return dict(self._locked)

    # --- velocity ---------------------------------------------------------
    def observe(self, agent: str, tool: str, now: float | None = None) -> BehaviorAssessment:
        """Record a call and report whether the rate looks anomalous."""
        now = now if now is not None else time.monotonic()
        stats = self._stats[(agent, tool)]
        stats.prune(now)
        stats.events.append(now)
        rate = stats.rate
        baseline = stats.baseline

        anomaly = False
        detail = ""
        signals: list[Signal] = []

        if rate > HARD_RATE_CEILING:
            anomaly = True
            detail = (f"{rate} calls to {tool} in the last {int(WINDOW_SECONDS)}s "
                      f"exceeds the absolute ceiling of {HARD_RATE_CEILING}")
        elif baseline is not None and rate > max(baseline * SPIKE_MULTIPLIER, 3):
            anomaly = True
            detail = (f"{rate} calls to {tool} in the last {int(WINDOW_SECONDS)}s is "
                      f"{rate / baseline:.1f}x the learned baseline of {baseline:.1f}")

        if anomaly:
            signals.append(Signal("behavior:velocity_spike", W_VELOCITY, detail))
        elif stats.may_train(now):
            # One sample per window, and never from an anomalous window - otherwise
            # an attack in progress teaches the monitor that the attack is normal.
            stats.observed_rates.append(rate)
            stats.last_trained_at = now
            if len(stats.observed_rates) > 100:
                stats.observed_rates.pop(0)

        return BehaviorAssessment(anomaly, signals, rate, baseline, detail)

    def snapshot(self) -> list[dict[str, Any]]:
        """Current per-(agent,tool) rates, for the dashboard."""
        now = time.monotonic()
        out = []
        for (agent, tool), stats in sorted(self._stats.items()):
            stats.prune(now)
            out.append({"agent": agent, "tool": tool, "rate": stats.rate,
                        "baseline": stats.baseline,
                        "observations": len(stats.observed_rates)})
        return out
