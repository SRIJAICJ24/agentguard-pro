"""Workspace labels for hook rows (F2).

Claude Code hook payloads carry the session's working directory. Storing the full
path would put a username into every audit row, so only a short label is kept:
the folder's own name, cleaned up, capped at 40 characters. A home directory is
labelled `<home>` because its name usually *is* the username.

The label lets `report`, `--fp-review` and precision leave out traffic from
workspaces listed under `dev_workspaces` in the policy - by default AgentGuard's
own repository, where testing the gateway produces deliberate attacks that would
otherwise count as real decisions.
"""

from __future__ import annotations

import re

_CLEAN = re.compile(r"[^A-Za-z0-9._-]+")
MAX_LEN = 40


def workspace_label(cwd: str | None) -> str | None:
    if not cwd or not str(cwd).strip():
        return None
    parts = [p for p in re.split(r"[\\/]+", str(cwd).strip()) if p]
    if not parts or (len(parts) == 1 and parts[0].endswith(":")):
        return "root"
    name = parts[-1]
    from agentguard.export import usernames

    if name.lower() in {u.lower() for u in usernames()}:
        return "<home>"
    cleaned = _CLEAN.sub("_", name).strip("_") or "root"
    return cleaned[:MAX_LEN]
