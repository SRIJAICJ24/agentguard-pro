"""The financial sink tier and payment receipts - Stage 7D.

Money is the one sink where an irreversible mistake is expected rather than
exceptional, so the rule is blunt: every call in the financial tier is held for
REVIEW regardless of its risk score. No signal combination makes a payment
routine.

On top of that:

  * amount, currency and payee are extracted where the arguments carry them, so
    the reviewer sees what is being paid to whom rather than raw JSON;
  * an optional per-session spending cap BLOCKs a call that would take the
    session's approved total over the cap (the approved total is read back from
    the receipts in the audit log, so it survives a gateway restart);
  * when an approved payment is forwarded, a structured receipt is written into
    the hash-chained audit log - agent, action, amount, payee, approver, policy
    rule and an argument hash - so the record is tamper-evident like every other
    decision.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from agentguard.db import connect
from agentguard.decision import Signal, Verdict
from agentguard.policy import TIER_FINANCIAL, Policy

RECEIPT_STAGE = "RECEIPT"

_AMOUNT_KEYS = ("amount", "total", "price", "value", "sum", "cost")
_CURRENCY_KEYS = ("currency", "currency_code", "ccy")
_PAYEE_KEYS = ("payee", "to", "recipient", "merchant", "vendor", "beneficiary",
               "destination", "account", "seller")
_SYMBOLS = {"$": "USD", "€": "EUR", "£": "GBP", "₹": "INR", "¥": "JPY"}
_MONEY_RE = re.compile(
    r"^\s*([$€£₹¥])?\s*([A-Za-z]{3})?\s*(\d[\d,]*(?:\.\d+)?)\s*([A-Za-z]{3})?\s*$"
)


@dataclass
class Transaction:
    amount: float | None = None
    currency: str | None = None
    payee: str | None = None
    rule: str | None = None

    def describe(self) -> str:
        money = (f"{self.amount:,.2f} {self.currency or '(currency unknown)'}"
                 if self.amount is not None else "an unknown amount")
        return f"{money} to {self.payee or '(payee unknown)'}"


def _parse_money(value: Any) -> tuple[float | None, str | None]:
    if isinstance(value, bool):
        return None, None
    if isinstance(value, (int, float)):
        return float(value), None
    m = _MONEY_RE.match(str(value))
    if not m:
        return None, None
    symbol, pre, number, post = m.groups()
    currency = _SYMBOLS.get(symbol or "") or (pre or post or "").upper() or None
    return float(number.replace(",", "")), currency


def extract(arguments: Any) -> Transaction:
    """Pull amount / currency / payee out of a (possibly nested) argument dict."""
    txn = Transaction()
    if not isinstance(arguments, dict):
        return txn

    def walk(obj: dict[str, Any]) -> None:
        for key, value in obj.items():
            k = str(key).lower()
            if isinstance(value, dict):
                walk(value)
                continue
            if txn.amount is None and k in _AMOUNT_KEYS:
                txn.amount, cur = _parse_money(value)
                txn.currency = txn.currency or cur
            elif k in _CURRENCY_KEYS and isinstance(value, str) and value.strip():
                txn.currency = value.strip().upper()
            elif txn.payee is None and k in _PAYEE_KEYS and isinstance(value, (str, int)):
                txn.payee = str(value)[:120]

    walk(arguments)
    return txn


def args_hash(arguments: Any) -> str:
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class FinancialAssessment:
    signals: list[Signal] = field(default_factory=list)
    verdict_floor: Verdict = Verdict.ALLOW
    transaction: Transaction | None = None


class FinancialGuard:
    def __init__(self, policy: Policy, db_path: str | Path | None = None) -> None:
        self.policy = policy
        self.db_path = db_path

    def matched_rule(self, tool: str) -> str | None:
        return next((p for p in self.policy.sinks.get(TIER_FINANCIAL, [])
                     if fnmatch(tool, p)), None)

    def spent(self, session_id: str, currency: str | None = None) -> float:
        """Approved total for a session, summed from its receipts in the audit log."""
        total = 0.0
        for row in connect(self.db_path).execute(
            "SELECT detail FROM audit WHERE stage = ? AND session_id = ?",
            (RECEIPT_STAGE, session_id),
        ):
            try:
                receipt = json.loads(row["detail"] or "{}")
            except ValueError:
                continue
            if receipt.get("amount") is None:
                continue
            if currency and receipt.get("currency") and receipt["currency"] != currency:
                continue
            total += float(receipt["amount"])
        return total

    def assess(self, tool: str, arguments: Any, tiers: list[str],
               session_id: str) -> FinancialAssessment:
        out = FinancialAssessment()
        cfg = self.policy.financial
        if not cfg.enabled or TIER_FINANCIAL not in tiers:
            return out

        txn = extract(arguments)
        txn.rule = self.matched_rule(tool)
        out.transaction = txn
        out.verdict_floor = Verdict.REVIEW
        out.signals.append(Signal(
            "financial:action", 0.0,
            f"'{tool}' moves money ({txn.describe()}; rule {txn.rule}) - financial "
            f"calls always need a human",
        ))

        if cfg.session_cap is None:
            return out
        if txn.amount is None:
            out.signals.append(Signal(
                "financial:amount_unknown", 0.0,
                f"a session cap of {cfg.session_cap:,.2f} is set but no amount could "
                f"be read from the arguments",
            ))
            return out
        if cfg.cap_currency and txn.currency and txn.currency != cfg.cap_currency:
            out.signals.append(Signal(
                "financial:currency_mismatch", 0.0,
                f"payment in {txn.currency} cannot be checked against the "
                f"{cfg.cap_currency} session cap",
            ))
            return out

        already = self.spent(session_id, cfg.cap_currency)
        if already + txn.amount > cfg.session_cap:
            out.verdict_floor = Verdict.BLOCK
            out.signals.append(Signal(
                "financial:cap_exceeded", 0.0,
                f"{txn.amount:,.2f} on top of {already:,.2f} already approved this "
                f"session exceeds the cap of {cfg.session_cap:,.2f}"
                f"{' ' + cfg.cap_currency if cfg.cap_currency else ''}",
            ))
        return out

    @staticmethod
    def receipt(*, tool: str, arguments: Any, txn: Transaction, agent: str,
                role: str, session_id: str, approval_id: int,
                approver: str | None) -> dict[str, Any]:
        return {
            "type": "payment_receipt",
            "agent": agent, "role": role, "session_id": session_id,
            "action": tool,
            "amount": txn.amount, "currency": txn.currency, "payee": txn.payee,
            "approver": approver, "approval_id": approval_id,
            "policy_rule": txn.rule,
            "args_sha256": args_hash(arguments),
        }
