"""Risk scoring. Scanner findings in, a single score and verdict out.

All weights and thresholds are named constants so they can be tuned from
measurement rather than guessed at in-line. Scores saturate at 1.0.

Two-tier secrets (see scanner.py) get two different weights on purpose: a
structural detector hit (`AWS Access Key`) is strong evidence, whereas a gated
entropy hit is suggestive but not conclusive, so it lands in REVIEW territory
rather than pushing straight to BLOCK.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentguard.decision import Decision, Signal, Verdict
from agentguard.scanner import ScanResult

# --- signal weights --------------------------------------------------------
#
# Calibration note: these are set so that each signal's *own* strength decides its
# own verdict, rather than every finding landing in REVIEW and relying on a second
# signal to escalate.
#
#   A structural detect-secrets hit and a credential-store path are both
#   individually conclusive - an agent reading `~/.ssh/id_rsa` or pasting a live
#   AWS key into an argument has no legitimate reading - so each is weighted above
#   the 0.75 BLOCK threshold on its own.
#
#   A gated entropy hit and an injection phrase are individually *suggestive*, so
#   each lands in REVIEW alone and only reaches BLOCK in combination (e.g. an
#   injection phrase plus untrusted taint heading for an egress sink).
W_SECRET_STRUCTURAL = 0.80   # detect-secrets structural detector -> BLOCK alone
W_SECRET_ENTROPY = 0.30      # gated entropy detector -> REVIEW alone
W_DENYLISTED_PATH = 0.80     # credential-store path -> BLOCK alone
W_INJECTION = 0.35           # prompt-injection / jailbreak phrasing -> REVIEW alone
W_UNKNOWN_DESTINATION = 0.15 # egress to a host not in the policy allowlist
W_TAINT_EXFIL = 0.40         # untrusted content flowing into an exfiltration sink
W_TAINT_PERSIST = 0.30       # untrusted content flowing into durable memory
W_PIN_MISMATCH = 0.50        # tool description changed after approval (rug pull)
W_VELOCITY = 0.25            # call rate above learned baseline
W_PROPAGATION = 0.45         # untrusted AI-addressed instructions copied into a
                             # propagation sink (self-replicating injection)
W_ALIGNMENT = 0.35           # optional model auditor judged the call off-goal
                             # -> REVIEW alone, like an injection phrase

# Additional findings of the same kind add less than the first one; a call with
# five injection phrases is not five times riskier than one.
DIMINISHING_FACTOR = 0.4

# --- decision thresholds ---------------------------------------------------
THRESHOLD_ALLOW = 0.25   # below this -> ALLOW
THRESHOLD_BLOCK = 0.75   # above this -> BLOCK; between the two -> REVIEW

_KIND_WEIGHTS = {
    "secret": W_SECRET_STRUCTURAL,
    "secret_entropy": W_SECRET_ENTROPY,
    "path": W_DENYLISTED_PATH,
    "injection": W_INJECTION,
}


def verdict_for(score: float) -> Verdict:
    if score < THRESHOLD_ALLOW:
        return Verdict.ALLOW
    if score > THRESHOLD_BLOCK:
        return Verdict.BLOCK
    return Verdict.REVIEW


@dataclass
class RiskEngine:
    """Turns evidence into a verdict. Thresholds overridable per policy."""

    allow_below: float = THRESHOLD_ALLOW
    block_above: float = THRESHOLD_BLOCK

    def signals_from_scan(self, scan: ScanResult) -> list[Signal]:
        """Group findings by kind and apply diminishing returns within a kind."""
        signals: list[Signal] = []
        by_kind: dict[str, list] = {}
        for f in scan.findings:
            by_kind.setdefault(f.kind, []).append(f)

        for kind, findings in by_kind.items():
            base = _KIND_WEIGHTS.get(kind, 0.1)
            for i, f in enumerate(findings):
                weight = base if i == 0 else base * (DIMINISHING_FACTOR ** i)
                label = f"{kind}:{f.label}"
                where = f" at `{f.where}`" if f.where else ""
                signals.append(Signal(label, weight, f"{f.label}{where}: {f.excerpt}"))
        return signals

    def score(self, signals: list[Signal]) -> float:
        total = sum(s.weight for s in signals)
        return min(total, 1.0)

    def evaluate(self, scan: ScanResult | None = None,
                 extra: list[Signal] | None = None) -> Decision:
        """Combine scanner findings plus any stage-specific signals into a Decision."""
        signals = self.signals_from_scan(scan) if scan is not None else []
        if extra:
            signals.extend(extra)

        total = self.score(signals)
        if total < self.allow_below:
            verdict = Verdict.ALLOW
        elif total > self.block_above:
            verdict = Verdict.BLOCK
        else:
            verdict = Verdict.REVIEW

        if signals:
            top = sorted(signals, key=lambda s: -s.weight)[:3]
            reason = "; ".join(s.name for s in top)
        else:
            reason = "no signals"
        return Decision(verdict=verdict, score=total, signals=signals, reason=reason)
