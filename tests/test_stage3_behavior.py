"""Stage 3 - behaviour baseline, velocity anomaly, kill switch."""

from __future__ import annotations

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError


def test_cold_monitor_does_not_fire_without_a_baseline():
    """A system with no history must not block the first calls it ever sees."""
    from agentguard.behavior import BehaviorMonitor

    monitor = BehaviorMonitor()
    for i in range(3):
        assessment = monitor.observe("agent", "filesystem.read", now=float(i))
        assert not assessment.anomaly
        assert assessment.baseline is None


def test_hard_ceiling_catches_a_runaway_loop_with_no_baseline():
    """The absolute ceiling exists precisely for the cold-start case."""
    from agentguard.behavior import HARD_RATE_CEILING, BehaviorMonitor

    monitor = BehaviorMonitor()
    fired = False
    for i in range(HARD_RATE_CEILING + 5):
        # All within one window, so the rate accumulates.
        fired = monitor.observe("agent", "filesystem.delete", now=1.0 + i * 0.01).anomaly
    assert fired, "a runaway loop must trip the ceiling"


def test_velocity_spike_against_a_learned_baseline():
    from agentguard.behavior import MIN_OBSERVATIONS, BehaviorMonitor

    monitor = BehaviorMonitor()
    # Teach a quiet baseline: one call per window, well separated in time.
    for i in range(MIN_OBSERVATIONS + 2):
        monitor.observe("agent", "api.call", now=i * 120.0)

    stats = monitor._stats[("agent", "api.call")]
    assert stats.baseline is not None and stats.baseline < 2

    # Now burst inside a single window.
    base = 10_000.0
    anomaly = False
    for i in range(12):
        anomaly = monitor.observe("agent", "api.call", now=base + i).anomaly or anomaly
    assert anomaly


def test_anomalous_windows_do_not_train_the_baseline():
    """An attack must not teach the monitor that the attack is normal."""
    from agentguard.behavior import BehaviorMonitor

    monitor = BehaviorMonitor()
    for i in range(8):
        monitor.observe("agent", "t", now=i * 120.0)
    stats = monitor._stats[("agent", "t")]
    baseline_before = stats.baseline

    base = 50_000.0
    for i in range(40):
        monitor.observe("agent", "t", now=base + i * 0.1)

    # The spike windows were excluded, so the baseline has not been dragged up.
    assert stats.baseline is not None
    assert stats.baseline <= (baseline_before or 0) + 1


def test_slow_ramp_cannot_train_the_baseline_upward():
    """Regression guard for a real evasion.

    An earlier version trained the baseline on every call, so an attacker who
    ramped the rate gradually moved the threshold up with it and was never flagged.
    The baseline is now sampled at most once per window, so a ramp inside a window
    still trips.
    """
    from agentguard.behavior import BehaviorMonitor

    monitor = BehaviorMonitor()
    # Establish a quiet baseline over several separate windows.
    for i in range(8):
        monitor.observe("agent", "api.call", now=i * 120.0)

    # Ramp gradually inside one window rather than bursting all at once.
    base = 90_000.0
    anomaly = False
    for i in range(20):
        anomaly = monitor.observe("agent", "api.call", now=base + i * 2.0).anomaly or anomaly
    assert anomaly, "a gradual ramp must still be detected"


def test_kill_switch_locks_and_releases():
    from agentguard.behavior import BehaviorMonitor

    monitor = BehaviorMonitor()
    assert monitor.is_locked("s1") is None
    monitor.kill("s1", "compromised")
    assert monitor.is_locked("s1") == "compromised"
    monitor.release("s1")
    assert monitor.is_locked("s1") is None


async def test_kill_switch_blocks_every_call_in_that_session(upstream, db_path):
    """The kill switch is absolute - checked before policy, RBAC or scoring."""
    from agentguard.gateway import build_gateway
    from agentguard.policy import Policy

    p = Policy()
    p.enforcement = True
    proxy, guard = build_gateway(upstream, policy=p, db_path=db_path)

    async with Client(proxy) as client:
        # A benign call works first.
        await client.call_tool("filesystem.read", {"path": "notes.txt"})
        session_id = guard.taints.sessions[0] if guard.taints.sessions else None
        # Lock every session the gateway has seen.
        from agentguard.db import connect
        rows = connect(db_path).execute(
            "SELECT DISTINCT session_id FROM audit WHERE session_id IS NOT NULL"
        ).fetchall()
        for row in rows:
            guard.behavior.kill(row["session_id"], "manual kill switch")

        with pytest.raises(ToolError) as exc:
            await client.call_tool("filesystem.read", {"path": "notes.txt"})
    assert "locked" in str(exc.value).lower()


def test_snapshot_reports_live_rates():
    from agentguard.behavior import BehaviorMonitor

    monitor = BehaviorMonitor()
    monitor.observe("a", "t1")
    monitor.observe("a", "t1")
    monitor.observe("b", "t2")
    snap = {(row["agent"], row["tool"]): row["rate"] for row in monitor.snapshot()}
    assert snap[("a", "t1")] == 2
    assert snap[("b", "t2")] == 1
