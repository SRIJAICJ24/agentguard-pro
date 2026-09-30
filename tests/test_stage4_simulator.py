"""Stage 4 - red-team simulator and security scoring.

Two things are under test: that the simulator actually exercises the gateway, and
that the score cannot be gamed. The second matters more - a security score that
rewards blocking everything is worse than no score at all.
"""

from __future__ import annotations

import pytest

from agentguard.simulator import (
    RedTeamSimulator,
    Scenario,
    default_scenarios,
)


@pytest.fixture
def sim(upstream, db_path):
    from agentguard.gateway import build_gateway
    from agentguard.policy import Policy

    p = Policy()
    p.enforcement = True
    proxy, guard = build_gateway(upstream, policy=p, db_path=db_path)
    return RedTeamSimulator(proxy, guard)


async def test_simulator_covers_every_documented_attack_class(sim):
    categories = {s.category for s in default_scenarios()}
    assert {"prompt_injection", "credential_access", "secret_leak",
            "memory_poisoning", "exfiltration", "privilege_escalation",
            "benign"} <= categories


async def test_simulation_scores_the_shipped_configuration(sim):
    """The headline number. If this drops, coverage genuinely regressed."""
    report = await sim.run()

    failures = [r.to_dict() for r in report.results if not r.passed]
    assert report.detection_rate == 1.0, f"missed attacks: {failures}"
    assert report.clean_pass_rate == 1.0, f"false positives: {failures}"
    assert report.score == 100
    assert report.grade == "A"


async def test_benign_control_scenarios_are_actually_allowed(sim):
    report = await sim.run()
    for result in report.benign:
        assert result.observed == "ALLOW", (
            f"false positive on benign scenario {result.scenario.name}: "
            f"{result.detail}"
        )


async def test_score_punishes_a_block_everything_gateway(upstream, db_path):
    """The anti-gaming property.

    A gateway configured to deny every tool detects every attack, but destroys the
    benign half - so the score must fall, not rise.
    """
    from agentguard.gateway import build_gateway
    from agentguard.policy import Policy

    paranoid = Policy()
    paranoid.enforcement = True
    paranoid.deny_tools = ["*"]
    proxy, guard = build_gateway(upstream, policy=paranoid, db_path=db_path)

    report = await RedTeamSimulator(proxy, guard).run()

    assert report.detection_rate == 1.0        # it does block every attack
    assert report.clean_pass_rate == 0.0       # and every legitimate call too
    assert report.score == 50, "blocking everything must not score well"
    assert report.grade in {"F", "D"}


async def test_score_punishes_a_disabled_gateway(upstream, db_path):
    """The mirror case: a gateway that allows everything scores 50 too."""
    from agentguard.gateway import build_gateway
    from agentguard.policy import Policy

    permissive = Policy()
    permissive.enforcement = False             # observe only: nothing is stopped
    proxy, guard = build_gateway(upstream, policy=permissive, db_path=db_path)

    report = await RedTeamSimulator(proxy, guard).run()

    assert report.clean_pass_rate == 1.0
    assert report.detection_rate < 0.5
    assert report.score < 75


async def test_report_serialises_for_the_dashboard_and_ci(sim):
    report = await sim.run()
    data = report.to_dict()
    assert set(data) >= {"score", "grade", "detection_rate", "clean_pass_rate",
                         "by_category", "results"}
    assert all({"name", "category", "expect", "observed", "passed"} <= set(r)
               for r in data["results"])


async def test_custom_scenario_can_be_supplied(sim):
    """The simulator is extensible - users can add their own attack patterns."""
    from agentguard.simulator import EXPECT_BLOCK

    custom = Scenario(
        "custom_kube_config", "credential_access", EXPECT_BLOCK,
        [("filesystem.read", {"path": "~/.kube/config"})],
        "Read of a kubernetes cluster credential file.",
    )
    report = await sim.run([custom])
    assert len(report.results) == 1
    assert report.results[0].passed
