"""Stage 7B - volume-aware DLP and data classification.

Counts matter more than presence: one address in a message is correspondence,
two hundred in a body is an export. Validation matters as much as matching: a
random 16-digit number is not a card, and treating it as one would make the
detector unusable on order numbers and IDs.
"""

from __future__ import annotations

import time

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from conftest import text_of

TEST_CARD = "4111 1111 1111 1111"          # published Visa test number, Luhn-valid
NOT_A_CARD = "4111 1111 1111 1112"         # same shape, fails Luhn


def _prepare(guard, tool):
    return [e for e in guard.stats.events
            if e["stage"] == "TOOL_PREPARE" and e["tool"] == tool][-1]


def _csv_of_emails(n: int) -> str:
    rows = ["name,email"] + [f"user{i},user{i}@customer-{i % 7}.example" for i in range(n)]
    return "\n".join(rows)


# =========================================================================
# checksums and entity counting
# =========================================================================
def test_luhn_distinguishes_a_card_from_a_random_16_digit_number():
    from agentguard.classify import find_entities, luhn_valid

    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")
    assert [e.kind for e in find_entities(f"card {TEST_CARD} on file")] == ["card"]
    assert find_entities(f"order number {NOT_A_CARD}") == []
    assert find_entities("ref 8273645501928374") == []          # random run, not Luhn


def test_verhoeff_validates_aadhaar():
    from agentguard.classify import find_entities, verhoeff_valid

    assert verhoeff_valid("234123412346")        # valid Verhoeff check digit
    assert not verhoeff_valid("234123412345")
    assert [e.kind for e in find_entities("aadhaar 2341 2341 2346")] == ["aadhaar"]
    assert find_entities("aadhaar 2341 2341 2345") == []


def test_pan_email_and_phone_are_counted():
    from agentguard.classify import find_entities

    kinds = sorted(e.kind for e in find_entities(
        "PAN ABCDE1234F, mail a.b@example.com, call +91 98765 43210 or (415) 555-2671"
    ))
    assert kinds == ["email", "pan", "phone", "phone"]


def test_card_digits_are_not_double_counted_as_a_phone():
    from agentguard.classify import find_entities

    assert [e.kind for e in find_entities(f"pay with 4111111111111111")] == ["card"]


def test_labels_follow_volume_not_presence():
    from agentguard.classify import classify_text
    from agentguard.policy import Policy

    p = Policy()
    assert classify_text("the weather is nice", p).label == "PUBLIC"
    assert classify_text("mail me at a@example.com", p).label == "INTERNAL"
    assert classify_text(_csv_of_emails(12), p).label == "CONFIDENTIAL"
    assert classify_text(_csv_of_emails(200), p).label == "PII"
    assert classify_text(f"card {TEST_CARD}", p).label == "PII"
    assert classify_text("CONFIDENTIAL: q3 roadmap", p).label == "CONFIDENTIAL"
    assert classify_text("anything", p, secret=True).label == "SECRET"


def test_classification_policy_parses_and_rejects_bad_rules():
    from agentguard.policy import from_dict

    p = from_dict({"classification": {
        "thresholds": {"confidential": 3, "pii": 5},
        "max_label": {"default": {"exfiltration": "INTERNAL"},
                      "researcher": {"exfiltration": "PUBLIC"}},
        "actions": {"CONFIDENTIAL": "redact"},
    }})
    c = p.classification
    assert (c.confidential_count, c.pii_count) == (3, 5)
    assert c.limit_for(None, "exfiltration") == "INTERNAL"
    assert c.limit_for("researcher", "exfiltration") == "PUBLIC"
    assert c.limit_for("researcher", "propagation") == "PII"
    assert c.actions["CONFIDENTIAL"] == "redact"

    with pytest.raises(ValueError):
        from_dict({"classification": {"actions": {"PII": "shred"}}})
    with pytest.raises(ValueError):
        from_dict({"classification": {"max_label": {"default": {"exfiltration": "TOP"}}}})


# =========================================================================
# through the live gateway
# =========================================================================
async def test_one_email_address_in_a_message_is_allowed(gateway):
    proxy, guard = gateway
    async with Client(proxy) as client:
        out = text_of(await client.call_tool("email.send", {
            "to": "team@example.com",
            "body": "Please loop in dana@example.com on the Thursday review.",
        }))
    assert "sent" in out
    event = _prepare(guard, "email.send")
    assert event["verdict"] == "ALLOW"
    assert not any(s.startswith("dlp:") for s in event["signals"])


async def test_a_csv_of_200_emails_to_an_external_sink_is_blocked(gateway):
    proxy, guard = gateway
    async with Client(proxy) as client:
        with pytest.raises(ToolError) as exc:
            await client.call_tool("email.send", {
                "to": "buyer@external.example", "body": _csv_of_emails(200),
            })
    assert "blocked" in str(exc.value).lower()
    event = _prepare(guard, "email.send")
    assert event["verdict"] == "BLOCK"
    assert "dlp:over_limit:PII" in event["signals"]


async def test_redact_rewrites_what_reaches_the_upstream(upstream, db_path):
    from agentguard.gateway import build_gateway
    from agentguard.policy import from_dict

    policy = from_dict({"enforcement": True, "classification": {
        "actions": {"PII": "redact"},
    }})
    proxy, guard = build_gateway(upstream, policy=policy, db_path=db_path)
    body = (f"Customer card {TEST_CARD}, contact ravi@example.com, "
            f"backup ravi@example.com, PAN ABCDE1234F")
    async with Client(proxy) as client:
        echoed = text_of(await client.call_tool(
            "chat.post_message", {"channel": "#ops", "text": body}))

    assert TEST_CARD not in echoed
    assert "ravi@example.com" not in echoed
    assert "ABCDE1234F" not in echoed
    assert "<CARD_1>" in echoed and "<PAN_1>" in echoed
    # the same value gets the same placeholder
    assert echoed.count("<EMAIL_1>") == 2
    event = _prepare(guard, "chat.post_message")
    assert "dlp:redacted" in event["signals"]
    assert event["verdict"] == "ALLOW"


async def test_redact_in_observe_mode_only_logs(upstream, db_path):
    """Observe mode never rewrites traffic - it records what it would have done."""
    from agentguard.gateway import build_gateway
    from agentguard.policy import from_dict

    policy = from_dict({"classification": {"actions": {"PII": "redact"}}})
    proxy, guard = build_gateway(upstream, policy=policy, db_path=db_path)
    async with Client(proxy) as client:
        echoed = text_of(await client.call_tool(
            "chat.post_message", {"channel": "#ops", "text": f"card {TEST_CARD}"}))
    assert TEST_CARD in echoed
    event = _prepare(guard, "chat.post_message")
    assert "dlp:over_limit:PII" in event["signals"]
    assert "dlp:redacted" not in event["signals"]


async def test_per_role_limit_is_applied(upstream, db_path):
    from agentguard.gateway import build_gateway
    from agentguard.identity import AgentIdentity
    from agentguard.policy import from_dict

    policy = from_dict({"enforcement": True, "classification": {
        "max_label": {"intern": {"exfiltration": "PUBLIC"}},
        "actions": {"INTERNAL": "review"},
    }})
    proxy, guard = build_gateway(upstream, policy=policy, db_path=db_path,
                                 identity=AgentIdentity(name="a", role="intern"))
    async with Client(proxy) as client:
        with pytest.raises(ToolError):
            await client.call_tool("email.send", {
                "to": "x@example.com", "body": "ping dana@example.com"})
    assert "dlp:over_limit:INTERNAL" in _prepare(guard, "email.send")["signals"]


async def test_attachment_passed_by_path_is_logged_as_unscanned(gateway):
    proxy, guard = gateway
    async with Client(proxy) as client:
        await client.call_tool("email.send", {
            "to": "team@example.com", "body": "report attached",
            "attachments": ["/home/me/reports/q3-customers.xlsx"],
        })
    event = _prepare(guard, "email.send")
    assert "dlp:unscanned_attachment" in event["signals"]
    assert event["verdict"] == "ALLOW"


async def test_ordinary_tier_calls_are_not_classified(gateway):
    proxy, guard = gateway
    async with Client(proxy) as client:
        await client.call_tool("web.search", {"query": _csv_of_emails(200)[:400]})
    assert not any(s.startswith("dlp:") for s in _prepare(guard, "web.search")["signals"])


async def test_classification_can_be_switched_off(upstream, db_path):
    from agentguard.gateway import build_gateway
    from agentguard.policy import from_dict

    policy = from_dict({"enforcement": True, "classification": {"enabled": False}})
    proxy, guard = build_gateway(upstream, policy=policy, db_path=db_path)
    async with Client(proxy) as client:
        await client.call_tool("email.send", {"to": "b@external.example",
                                              "body": _csv_of_emails(200)})
    assert _prepare(guard, "email.send")["verdict"] == "ALLOW"


# =========================================================================
# latency
# =========================================================================
def test_classification_stays_inside_the_fast_path_budget():
    from agentguard.classify import DataClassifier
    from agentguard.policy import Policy

    clf = DataClassifier(Policy())
    tiers = ["exfiltration", "propagation"]
    typical = {"to": "team@example.com",
               "body": "Standup moved to 10am tomorrow, agenda attached. " * 6}
    bulk = {"to": "b@external.example", "body": _csv_of_emails(200)}

    for args, budget in ((typical, 2.0), (bulk, 5.0)):
        start = time.perf_counter()
        for _ in range(50):
            clf.assess("email.send", args, tiers, None)
        avg_ms = (time.perf_counter() - start) / 50 * 1000
        assert avg_ms < budget, f"classification averaged {avg_ms:.2f}ms (budget {budget})"


def test_a_write_destination_is_not_an_unscanned_attachment():
    """Regression: a file-write tool's `file_path` is where the content goes, not
    an attachment, so a propagation-only call must not log dlp:unscanned_attachment.
    Found when Claude Code's Write tool started flowing through the hooks."""
    from agentguard.classify import DataClassifier
    from agentguard.policy import Policy

    out = DataClassifier(Policy()).assess(
        "Write", {"file_path": "/home/me/project/notes.md", "content": "hello"},
        ["ordinary", "propagation"], None)
    assert not any(s.name == "dlp:unscanned_attachment" for s in out.signals)

    # ...while a file passed by path to an egress sink still is one.
    out = DataClassifier(Policy()).assess(
        "email.send", {"to": "a@example.com", "file_path": "/tmp/q3.xlsx"},
        ["exfiltration", "propagation"], None)
    assert any(s.name == "dlp:unscanned_attachment" for s in out.signals)
