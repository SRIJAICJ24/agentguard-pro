"""Core decision vocabulary shared by every stage of the pipeline.

Kept in its own module so that scanner/risk/policy/middleware can all import it
without creating import cycles.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Verdict(str, enum.Enum):
    """The three terminal outcomes for any intercepted action."""

    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"

    def escalate(self, other: "Verdict") -> "Verdict":
        """Return whichever verdict is more restrictive."""
        order = {Verdict.ALLOW: 0, Verdict.REVIEW: 1, Verdict.BLOCK: 2}
        return self if order[self] >= order[other] else other


@dataclass
class Signal:
    """One piece of evidence contributing to a risk score.

    `weight` is the score contribution; `detail` is human-readable and ends up
    in the audit log / incident timeline verbatim.
    """

    name: str
    weight: float
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "weight": round(self.weight, 4), "detail": self.detail}


@dataclass
class Decision:
    """The full result of evaluating one action, including why."""

    verdict: Verdict
    score: float = 0.0
    signals: list[Signal] = field(default_factory=list)
    reason: str = ""
    # Set when policy/RBAC/pinning short-circuits the score entirely.
    override: str | None = None

    @property
    def blocked(self) -> bool:
        return self.verdict is Verdict.BLOCK

    @property
    def signal_names(self) -> list[str]:
        return [s.name for s in self.signals]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "score": round(self.score, 4),
            "reason": self.reason,
            "override": self.override,
            "signals": [s.to_dict() for s in self.signals],
        }
