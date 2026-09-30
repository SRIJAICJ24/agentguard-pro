"""Stage 7D - financial sink tier, payment receipts, and the global lock."""

from __future__ import annotations

import json
import shutil
import tempfile

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from conftest import text_of

PURCHASE = {"amount": 60.0, "currency": "USD", "payee": "Acme Supplies"}


def _prepare(guard, tool):
    return [e for e in guard.stats.events
            if e["stage"] == "TOOL_PREPARE" and e["tool"] == tool][-1]


def _gateway(upstream, db_path, enforcement=True, **policy):
    from agentguard.gateway import build_gateway
    from agentguard.policy import from_dict

    p = from_dict({"enforcement": enforcement, **policy})
    return build_gateway(upstream, policy=p, db_path=db_path)


# =========================================================================
# extraction
# =========================================================================
def test_amount_currency_and_payee_are_extracted():
    from agentguard.financial import extract

    t = extract({"amount": "$1,200.50", "payee": "Acme"})
    assert (t.amount, t.currency, t.payee) == (1200.50, "USD", "Acme")
    t = extract({"order": {"total": "499 INR", "merchant": "Chaiwala"}})
    assert (t.amount, t.currency, t.payee) == (499.0, "INR", "Chaiwala")
    t = extract({"amount": 20, "currency": "eur", "recipient": "IBAN DE00"})
    assert (t.amount, t.currency, t.payee) == (20.0, "EUR", "IBAN DE00")
    assert extract({"note": "no money here"}).amount is None


def test_financial_tier_matches_actions_not_substrings():
    from agentguard.policy import Policy

    p = Policy()
    for tool in ("payments.purchase", "stripe.create_payment", "shop.checkout",
                 "bank.transfer_funds", "billing.refund", "ap.pay_invoice", "wallet.pay"):
        assert "financial" in p.sink_tiers(tool), tool
    for tool in ("api.send_payload", "filesystem.read", "email.send", "display.show"):
        assert "financial" not in p.sink_tiers(tool), tool


# =========================================================================
# every purchase reaches the review queue
# =========================================================================
@pytest.mark.parametrize("enforcement", [True, False])
async def test_a_purchase_always_reaches_the_review_queue(upstream, db_path, enforcement):
    from agentguard.review_queue import ReviewQueue

    proxy, guard = _gateway(upstream, db_path, enforcement=enforcement)
    async with Client(proxy) as client:
        if enforcement:
            with pytest.raises(ToolError) as exc:
                await client.call_tool("payments.purchase", PURCHASE)
            assert "review" in str(exc.value).lower()
        else:
            await client.call_tool("payments.purchase", PURCHASE)   # observe: logged only

    queued = [i for i in ReviewQueue(db_path).list() if i.tool == "payments.purchase"]
    assert len(queued) == 1
    event = _prepare(guard, "payments.purchase")
    assert event["verdict"] == "REVIEW"
    assert "financial:action" in event["signals"]
    assert event["score"] == 0.0, "held regardless of a zero risk score"


async def test_exceeding_the_session_cap_blocks(upstream, db_path):
    proxy, guard = _gateway(upstream, db_path,
                            financial={"session_cap": {"amount": 100, "currency": "USD"}})
    async with Client(proxy) as client:
        with pytest.raises(ToolError) as exc:
            await client.call_tool("payments.purchase",
                                   {**PURCHASE, "amount": 250.0})
    assert "blocked" in str(exc.value).lower()
    event = _prepare(guard, "payments.purchase")
    assert event["verdict"] == "BLOCK"
    assert "financial:cap_exceeded" in event["signals"]


async def test_currency_mismatch_is_flagged_not_guessed(upstream, db_path):
    proxy, guard = _gateway(upstream, db_path,
                            financial={"session_cap": {"amount": 100, "currency": "USD"}})
    async with Client(proxy) as client:
        with pytest.raises(ToolError):
            await client.call_tool("payments.purchase",
                                   {"amount": 5000, "currency": "INR", "payee": "x"})
    event = _prepare(guard, "payments.purchase")
    assert event["verdict"] == "REVIEW"
    assert "financial:currency_mismatch" in event["signals"]


# =========================================================================
# receipts
# =========================================================================
async def test_approved_payment_writes_a_receipt_that_passes_chain_verification(
    upstream, db_path
):
    from agentguard import audit
    from agentguard.financial import RECEIPT_STAGE, args_hash
    from agentguard.review_queue import ReviewQueue

    proxy, guard = _gateway(upstream, db_path)
    queue = ReviewQueue(db_path)
    async with Client(proxy) as client:
        with pytest.raises(ToolError):
            await client.call_tool("payments.purchase", PURCHASE)
        item = next(i for i in queue.list() if i.tool == "payments.purchase")
        queue.approve(item.id, by="alice")

        out = text_of(await client.call_tool("payments.purchase", PURCHASE))
    assert "paid 60.00 USD to Acme Supplies" in out

    rows = [r for r in audit.last(20, db_path) if r["stage"] == RECEIPT_STAGE]
    assert len(rows) == 1
    receipt = json.loads(rows[0]["detail"])
    assert receipt["amount"] == 60.0 and receipt["currency"] == "USD"
    assert receipt["payee"] == "Acme Supplies"
    assert receipt["approver"] == "alice"
    assert receipt["approval_id"] == item.id
    assert receipt["action"] == "payments.purchase"
    assert receipt["agent"] and receipt["policy_rule"] == "*payment*"   # first match
    assert receipt["args_sha256"] == args_hash(PURCHASE)

    intact, broken = audit.verify_chain(db_path)
    assert intact, f"chain broken at {broken}"


async def test_tampering_with_a_receipt_breaks_the_chain(upstream, db_path):
    from agentguard import audit
    from agentguard.db import connect
    from agentguard.review_queue import ReviewQueue

    proxy, _guard = _gateway(upstream, db_path)
    queue = ReviewQueue(db_path)
    async with Client(proxy) as client:
        with pytest.raises(ToolError):
            await client.call_tool("payments.purchase", PURCHASE)
        queue.approve(queue.list()[0].id, by="alice")
        await client.call_tool("payments.purchase", PURCHASE)

    conn = connect(db_path)
    row = conn.execute("SELECT id, detail FROM audit WHERE stage='RECEIPT'").fetchone()
    forged = json.loads(row["detail"]) | {"amount": 6.0}
    conn.execute("UPDATE audit SET detail=? WHERE id=?", (json.dumps(forged), row["id"]))
    conn.commit()
    assert audit.verify_chain(db_path) == (False, row["id"])


async def test_approved_spend_counts_toward_the_cap(upstream, db_path):
    """The cap is enforced against approved receipts, so approving one payment
    reduces the room left for the next."""
    from agentguard.review_queue import ReviewQueue

    proxy, guard = _gateway(upstream, db_path,
                            financial={"session_cap": {"amount": 100, "currency": "USD"}})
    queue = ReviewQueue(db_path)
    async with Client(proxy) as client:
        with pytest.raises(ToolError):
            await client.call_tool("payments.purchase", PURCHASE)          # 60
        queue.approve(queue.list()[0].id)
        await client.call_tool("payments.purchase", PURCHASE)

        with pytest.raises(ToolError):
            await client.call_tool("payments.purchase", {**PURCHASE, "amount": 50.0})
    event = _prepare(guard, "payments.purchase")
    assert event["verdict"] == "BLOCK"
    assert "financial:cap_exceeded" in event["signals"]


# =========================================================================
# locks
# =========================================================================
@pytest.fixture
def home(monkeypatch):
    directory = tempfile.mkdtemp(prefix="agentguard-lock-")
    monkeypatch.setenv("AGENTGUARD_HOME", directory)
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _cli(*argv) -> int:
    from agentguard.cli import main
    return main(list(argv))


async def test_lock_all_denies_calls_in_every_session_even_in_observe_mode(home, upstream):
    from agentguard.gateway import build_gateway
    from agentguard.policy import Policy

    proxy, guard = build_gateway(upstream, policy=Policy())      # observe mode, default DB
    async with Client(proxy) as a, Client(proxy) as b:
        await a.call_tool("web.search", {"query": "x"})
        await b.call_tool("web.search", {"query": "y"})
        assert len(guard.taints.sessions) == 2

        assert _cli("lock", "--all", "--reason", "incident 42") == 0
        for client in (a, b):
            with pytest.raises(ToolError) as exc:
                await client.call_tool("filesystem.read", {"path": "notes.txt"})
            assert "incident 42" in str(exc.value)

        assert _cli("unlock", "--all") == 0
        assert "notes.txt" in text_of(
            await a.call_tool("filesystem.read", {"path": "notes.txt"}))

    locked = [e for e in guard.stats.events if "lock:global" in (e.get("signals") or [])]
    assert len(locked) == 2 and all(e["verdict"] == "BLOCK" for e in locked)


async def test_lock_session_only_affects_that_session(home, upstream):
    from agentguard.gateway import build_gateway
    from agentguard.policy import Policy

    proxy, guard = build_gateway(upstream, policy=Policy())
    async with Client(proxy) as a, Client(proxy) as b:
        await a.call_tool("web.search", {"query": "x"})
        session_a = guard.taints.sessions[-1]
        await b.call_tool("web.search", {"query": "y"})

        assert _cli("lock", "--session", session_a) == 0
        with pytest.raises(ToolError):
            await a.call_tool("web.search", {"query": "x"})
        await b.call_tool("web.search", {"query": "still fine"})
        assert _cli("unlock", "--session", session_a) == 0
        await a.call_tool("web.search", {"query": "x"})


async def test_in_process_kill_switch_is_absolute_in_observe_mode(upstream, db_path):
    from agentguard.gateway import build_gateway
    from agentguard.policy import Policy

    proxy, guard = build_gateway(upstream, policy=Policy(), db_path=db_path)
    async with Client(proxy) as client:
        await client.call_tool("web.search", {"query": "x"})
        guard.behavior.kill(guard.taints.sessions[-1], "compromised")
        with pytest.raises(ToolError):
            await client.call_tool("web.search", {"query": "x"})


def test_lock_cli_status_and_limitation_note(home, capsys):
    assert _cli("lock", "--status") == 0
    assert "no active locks" in capsys.readouterr().out
    assert _cli("lock", "--all") == 0
    out = capsys.readouterr().out
    assert "does not revoke credentials held by upstream servers" in out
    assert _cli("lock", "--status") == 0
    assert "ALL SESSIONS" in capsys.readouterr().out
    assert _cli("unlock", "--all") == 0
    assert _cli("unlock", "--all") == 1
