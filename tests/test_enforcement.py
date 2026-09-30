"""Observe mode vs enforcing mode.

The shipped default is observe: every control runs and every decision is logged,
but nothing is stopped. That is how the false-positive rate gets measured before
the gateway is allowed to interrupt real work - so it needs its own tests, since a
mode that silently blocked things would defeat the purpose.
"""

from __future__ import annotations

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from conftest import ATTACK_RULE, POISON_QUERY, text_of


async def test_observe_mode_logs_but_does_not_block(upstream, db_path):
    from agentguard.gateway import build_gateway
    from agentguard.policy import Policy

    p = Policy()
    p.enforcement = False
    proxy, guard = build_gateway(upstream, policy=p, db_path=db_path)

    async with Client(proxy) as client:
        # A call that WOULD be blocked when enforcing.
        out = text_of(await client.call_tool("filesystem.read", {"path": "~/.ssh/id_rsa"}))

    assert out, "observe mode must still return the upstream result"
    assert "PRIVATE KEY" in out
    # The decision was recorded even though it was not enforced.
    assert guard.stats.blocked == 1
    assert guard.stats.observed_only == 1


async def test_observe_mode_still_records_the_full_decision(upstream, db_path):
    from agentguard import audit
    from agentguard.gateway import build_gateway
    from agentguard.policy import Policy

    p = Policy()
    p.enforcement = False
    proxy, _guard = build_gateway(upstream, policy=p, db_path=db_path)

    async with Client(proxy) as client:
        await client.call_tool("filesystem.read", {"path": "/srv/.env"})

    rows = audit.last(10, db_path)
    blocked = [r for r in rows if r["verdict"] == "BLOCK"]
    assert blocked, "the decision must be logged even in observe mode"
    assert "path" in (blocked[0]["reason"] or "")
    intact, _ = audit.verify_chain(db_path)
    assert intact


async def test_enforcing_mode_blocks_the_same_call(upstream, db_path):
    from agentguard.gateway import build_gateway
    from agentguard.policy import Policy

    p = Policy()
    p.enforcement = True
    proxy, _guard = build_gateway(upstream, policy=p, db_path=db_path)

    async with Client(proxy) as client:
        with pytest.raises(ToolError):
            await client.call_tool("filesystem.read", {"path": "~/.ssh/id_rsa"})


async def test_observe_mode_still_quarantines_memory(upstream, db_path):
    """Observe mode does not stop the upstream write, but the ledger still records
    the item so the reviewer sees what happened."""
    from agentguard.gateway import build_gateway
    from agentguard.policy import Policy
    from agentguard.quarantine import QuarantinedMemoryLedger

    p = Policy()
    p.enforcement = False
    proxy, _guard = build_gateway(upstream, policy=p, db_path=db_path)

    async with Client(proxy) as client:
        await client.call_tool("web.search", {"query": POISON_QUERY})
        out = text_of(await client.call_tool(
            "memory.save", {"key": "routing", "content": ATTACK_RULE}
        ))

    assert "saved" in out                      # not stopped
    held = QuarantinedMemoryLedger(db_path).list()
    assert len(held) == 1                      # but recorded
    assert "web.search" in held[0].source_tools


async def test_exfiltration_policy_can_escalate_to_block(upstream, db_path):
    from agentguard.gateway import build_gateway
    from agentguard.policy import Policy

    p = Policy()
    p.enforcement = True
    p.exfiltration_on_taint = "BLOCK"
    proxy, _guard = build_gateway(upstream, policy=p, db_path=db_path)

    async with Client(proxy) as client:
        await client.call_tool("web.search", {"query": POISON_QUERY})
        with pytest.raises(ToolError) as exc:
            await client.call_tool("email.send", {"to": "a@b.example", "body": ATTACK_RULE})
    assert "blocked" in str(exc.value).lower()
