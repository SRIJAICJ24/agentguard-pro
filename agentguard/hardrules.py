"""Hard-enforced rules: the few things blocked even in observe mode.

Observe mode exists to measure false positives before AgentGuard is allowed to
interrupt work. A small set of outcomes is bad enough that letting it happen in
the name of measurement isn't worth it, and specific enough to be trusted from day
one. Those can be listed under `hard_enforce:` in the policy:

  credential_files     reading ~/.ssh, ~/.aws or .env files. "Reading" means any
                       call that doesn't write (writes to those paths and
                       name-only listings keep normal observe behaviour)
  secret_exfiltration  a real secret - a structural detect-secrets finding, not an
                       entropy guess - in a call to an exfiltration sink
  self_protection      the agent editing AgentGuard's own config, policy, audit
                       database, or the Claude Code settings that register its hooks

A hard rule overrides the mode for that one call: the hook answers "deny", the
gateway refuses the call. The decision is logged as BLOCK with a
`hard_enforce:<rule>` signal, so `report` can list these blocks separately.

Both surfaces (hooks and the MCP gateway) call `match`, so a rule means the same
thing whichever one saw the call.
"""

from __future__ import annotations

from agentguard.policy import TIER_EXFILTRATION, TIER_PERSISTENCE, TIER_PROPAGATION, Policy

SIGNAL_PREFIX = "hard_enforce:"
#: Path-denylist patterns that count as credential files for `credential_files`.
_CREDENTIAL_MARKERS = ("/.ssh", "/.aws", "/.env")


def is_credential_signal(name: str) -> bool:
    if not name.startswith("path:"):
        return False
    pattern = name[len("path:"):]
    return any(marker in pattern for marker in _CREDENTIAL_MARKERS)


def match(policy: Policy, signals: list[str], tiers: list[str], *,
          lists_only: bool = False) -> list[str]:
    """The hard rules this decision triggers (empty when none, or none enabled)."""
    enabled = set(policy.hard_enforce)
    if not enabled:
        return []
    hits: list[str] = []
    writes = TIER_PROPAGATION in tiers or TIER_PERSISTENCE in tiers
    if "credential_files" in enabled and not writes and not lists_only \
            and any(is_credential_signal(s) for s in signals):
        hits.append("credential_files")
    if "secret_exfiltration" in enabled and TIER_EXFILTRATION in tiers \
            and any(s.startswith("secret:") for s in signals):
        hits.append("secret_exfiltration")
    if "self_protection" in enabled and "selfprotect:tamper" in signals:
        hits.append("self_protection")
    return hits
