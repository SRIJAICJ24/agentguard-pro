"""Agent identity and RBAC.

A single machine runs many agents with genuinely different needs: a research agent
should reach the web and never write files; a coding agent should write files and
never send email. Least privilege only means something if the gateway can tell
which agent is calling.

Identity comes from the session (set by the gateway at startup, or per-connection
via the AGENTGUARD_AGENT / AGENTGUARD_ROLE environment variables the client passes
through). It is intentionally not inferred from the request content - an agent must
not be able to claim a role by asking for one.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from agentguard.decision import Verdict
from agentguard.policy import Policy

DEFAULT_AGENT = "unknown-agent"
DEFAULT_ROLE = "default"


@dataclass
class AgentIdentity:
    """Who is making this call."""

    name: str = DEFAULT_AGENT
    role: str = DEFAULT_ROLE
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def from_env(cls, session_id: str | None = None) -> "AgentIdentity":
        return cls(
            name=os.environ.get("AGENTGUARD_AGENT", DEFAULT_AGENT),
            role=os.environ.get("AGENTGUARD_ROLE", DEFAULT_ROLE),
            session_id=session_id or uuid.uuid4().hex[:12],
        )

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "role": self.role, "session_id": self.session_id,
                "started_at": self.started_at.isoformat()}


class RBACPolicy:
    """Role -> tool permission checks, backed by the policy YAML `roles:` section."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def known_role(self, role: str | None) -> bool:
        return bool(role) and role in self.policy.roles

    def check(self, identity: AgentIdentity, tool: str) -> tuple[Verdict | None, str]:
        """Return (verdict, explanation). A None verdict means "no opinion"."""
        verdict = self.policy.check_role(identity.role, tool)
        if verdict is None:
            return None, ""
        rule = self.policy.roles.get(identity.role)
        if rule and any(_matches(tool, p) for p in rule.deny):
            return verdict, (
                f"role '{identity.role}' explicitly denies '{tool}'"
            )
        return verdict, (
            f"role '{identity.role}' has an allow list that does not include '{tool}'"
        )


def _matches(tool: str, pattern: str) -> bool:
    from fnmatch import fnmatch
    return fnmatch(tool, pattern)
