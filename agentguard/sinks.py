"""Sink classification: what kind of damage could this call do?

Every outgoing tool call lands in exactly one tier:

  ordinary      read-only / local / reversible. Taint overlap is logged, never
                blocked - the system must not punish reading.
  exfiltration  network egress, email send, external POST. Untrusted taint in the
                arguments means the untrusted content is leaving; REVIEW or BLOCK
                per policy.
  persistence   writes to durable memory. Untrusted taint here does not go to the
                egress path at all - it routes to the Quarantined Memory Ledger,
                because the risk is different in kind: not "data leaves now" but
                "attacker text becomes trusted knowledge later".

Persistence is checked before exfiltration so a `memory_save` that also matches an
exfiltration glob still reaches the ledger.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentguard.decision import Signal, Verdict
from agentguard.policy import (
    TIER_EXFILTRATION,
    TIER_ORDINARY,
    TIER_PERSISTENCE,
    Policy,
)
from agentguard.risk import W_TAINT_EXFIL, W_TAINT_PERSIST
from agentguard.taint import TaintMap, TaintOverlap


@dataclass
class SinkAssessment:
    """What the sink classifier concluded about one call."""

    tier: str
    overlap: TaintOverlap
    signals: list[Signal]
    verdict_floor: Verdict = Verdict.ALLOW
    quarantine: bool = False
    # Every tier the tool belongs to (Stage 7: a call can be in several). `tier`
    # stays the single primary tier that the logic above is keyed on.
    tiers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "tiers": self.tiers,
            "taint": self.overlap.to_dict(),
            "verdict_floor": self.verdict_floor.value,
            "quarantine": self.quarantine,
        }


class SinkClassifier:
    """Assigns a tier to each call and decides what taint means for that tier."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def tier(self, tool: str) -> str:
        return self.policy.sink_tier(tool)

    def assess(self, tool: str, arguments: Any, taint: TaintMap) -> SinkAssessment:
        return self.assess_tier(self.tier(tool), arguments, taint)

    def assess_tier(self, tier: str, arguments: Any, taint: TaintMap) -> SinkAssessment:
        """The same assessment for an explicitly chosen tier.

        Claude Code's built-in tools don't have MCP-style names to glob on (a Bash
        command's tier depends on the command, not on the word "Bash"), so the
        hook integration decides the tier itself and passes it here.
        """
        overlap = taint.check_arguments(arguments)
        signals: list[Signal] = []

        if not overlap.tainted:
            return SinkAssessment(tier=tier, overlap=overlap, signals=signals)

        sources = ", ".join(overlap.sources) or "unknown"

        if tier == TIER_EXFILTRATION:
            floor = (
                Verdict.BLOCK
                if self.policy.exfiltration_on_taint == "BLOCK"
                else Verdict.REVIEW
            )
            signals.append(Signal(
                "taint:exfiltration", W_TAINT_EXFIL,
                f"untrusted content from [{sources}] is being sent to an "
                f"exfiltration-tier sink ({len(overlap.shared)} matching fingerprints)",
            ))
            return SinkAssessment(tier, overlap, signals, verdict_floor=floor)

        if tier == TIER_PERSISTENCE:
            signals.append(Signal(
                "taint:persistence", W_TAINT_PERSIST,
                f"untrusted content from [{sources}] is being written to durable "
                f"memory; routing to quarantine instead of trusted memory",
            ))
            # Not a block: the write is redirected, not refused.
            return SinkAssessment(tier, overlap, signals,
                                  verdict_floor=Verdict.ALLOW, quarantine=True)

        # ordinary tier: record the flow, do not act on it.
        signals.append(Signal(
            "taint:observed", 0.0,
            f"untrusted content from [{sources}] used in an ordinary-tier call "
            f"(logged only)",
        ))
        return SinkAssessment(TIER_ORDINARY, overlap, signals)
