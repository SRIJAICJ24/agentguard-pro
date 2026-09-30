"""Volume-aware DLP and data classification - Stage 7B.

Runs on every call to an exfiltration or propagation sink. Presence of personal
data is not the signal - one email address in a message is ordinary
correspondence. *Volume* is: a body carrying two hundred addresses is an export.
So entities are counted, the counts map to a label, and the label is compared
against the most sensitive label that role may send through that sink tier.

Labels, least to most sensitive: PUBLIC, INTERNAL, CONFIDENTIAL, PII, SECRET.

  SECRET        a structural detect-secrets finding (the scanner already has it)
  PII           any card / PAN / Aadhaar number, or email+phone count >= pii_count
  CONFIDENTIAL  email+phone count >= confidential_count, or a confidentiality marker
  INTERNAL      at least one email or phone, or an internal-use marker
  PUBLIC        none of the above

Validation keeps random digit runs from counting: card numbers must pass Luhn,
Aadhaar numbers must pass Verhoeff. A 16-digit order number is not a card.

Scope limit, deliberately stated: only content present in the arguments is read.
An attachment passed as a file path is never opened by the gateway - it is logged
as `dlp:unscanned_attachment` so the gap is visible rather than silent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agentguard.decision import Signal, Verdict
from agentguard.policy import (
    DLP_ACTIONS,
    LABELS,
    TIER_EXFILTRATION,
    TIER_PROPAGATION,
    Policy,
)
from agentguard.scanner import ScanResult, flatten, redact_text

_RANK = {label: i for i, label in enumerate(LABELS)}
_ACTION_RANK = {action: i for i, action in enumerate(DLP_ACTIONS)}
_DLP_TIERS = (TIER_EXFILTRATION, TIER_PROPAGATION)

# --- entity patterns -------------------------------------------------------
EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"
)
# 13-19 digits, optionally grouped by single spaces or dashes.
CARD_CANDIDATE_RE = re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])")
# 12 digits, first 2-9, as 4-4-4 or contiguous.
AADHAAR_CANDIDATE_RE = re.compile(r"(?<![\d-])[2-9]\d{3}([ -]?)\d{4}\1\d{4}(?![\d-])")
PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
PHONE_RES = (
    # Indian mobile: optional +91 / 0, then 10 digits starting 6-9
    re.compile(r"(?<![\w+])(?:\+91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"),
    # international E.164-ish, must start with +
    re.compile(r"(?<![\w+])\+\d{1,3}(?:[\s.-]?\d{2,4}){2,4}(?!\d)"),
    # North American: (555) 123-4567 / 555-123-4567 / 555.123.4567
    re.compile(r"(?<![\w+])\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)"),
)

_PATHISH = re.compile(r"[/\\]|\.[A-Za-z0-9]{2,5}$")
_FILE_KEYS = {"file", "files", "file_path", "file_paths", "filepath"}


def _is_attachment_key(where: str) -> bool:
    """`attachments[0]`, `email.attachment`, `files[2]` - but not `profile`."""
    segments = [s.lower() for s in re.split(r"[.\[\]]", where) if s and not s.isdigit()]
    return any(s.startswith("attach") or s in _FILE_KEYS for s in segments)


# --- checksums -------------------------------------------------------------
def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_valid(digits: str) -> bool:
    check = 0
    for i, ch in enumerate(reversed(digits)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[i % 8][int(ch)]]
    return check == 0


# --- entity extraction -----------------------------------------------------
@dataclass
class Entity:
    kind: str       # email | phone | card | pan | aadhaar
    value: str


def find_entities(text: str) -> list[Entity]:
    """Every validated entity in `text`.

    Cards and Aadhaar numbers are found and masked first, so their digits cannot
    be counted a second time as phone numbers.
    """
    found: list[Entity] = []
    masked = text

    for m in CARD_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn_valid(digits):
            found.append(Entity("card", m.group(0)))
            masked = masked.replace(m.group(0), " " * len(m.group(0)), 1)

    for m in AADHAAR_CANDIDATE_RE.finditer(masked):
        digits = re.sub(r"\D", "", m.group(0))
        if verhoeff_valid(digits):
            found.append(Entity("aadhaar", m.group(0)))
            masked = masked.replace(m.group(0), " " * len(m.group(0)), 1)

    found.extend(Entity("pan", m.group(0)) for m in PAN_RE.finditer(masked))
    found.extend(Entity("email", m.group(0)) for m in EMAIL_RE.finditer(masked))

    phone_spans: list[tuple[int, int]] = []
    for rx in PHONE_RES:
        for m in rx.finditer(masked):
            digits = re.sub(r"\D", "", m.group(0))
            if not 10 <= len(digits) <= 15:
                continue
            if any(m.start() < e and s < m.end() for s, e in phone_spans):
                continue            # already matched by an earlier pattern
            phone_spans.append((m.start(), m.end()))
            found.append(Entity("phone", m.group(0).strip()))
    return found


@dataclass
class Classification:
    label: str
    counts: dict[str, int] = field(default_factory=dict)
    entities: list[Entity] = field(default_factory=list)

    def summary(self) -> str:
        parts = [f"{n} {k}" for k, n in sorted(self.counts.items()) if n]
        return ", ".join(parts) or "no entities"


def classify_text(text: str, policy: Policy, secret: bool = False) -> Classification:
    cfg = policy.classification
    entities = find_entities(text)
    counts: dict[str, int] = {}
    for e in entities:
        counts[e.kind] = counts.get(e.kind, 0) + 1
    contacts = counts.get("email", 0) + counts.get("phone", 0)
    lowered = text.lower()

    if secret:
        label = "SECRET"
    elif any(counts.get(k) for k in ("card", "pan", "aadhaar")) or contacts >= cfg.pii_count:
        label = "PII"
    elif contacts >= cfg.confidential_count or \
            any(m.lower() in lowered for m in cfg.confidential_markers):
        label = "CONFIDENTIAL"
    elif contacts or any(m.lower() in lowered for m in cfg.internal_markers):
        label = "INTERNAL"
    else:
        label = "PUBLIC"
    return Classification(label, counts, entities)


# --- redaction -------------------------------------------------------------
class _Redactor:
    """Typed, numbered placeholders, consistent across one call's arguments.

    The value -> placeholder mapping lives only for the duration of one call and
    is never stored: placeholders are not reversible by the gateway, by design.
    """

    def __init__(self, entities: list[Entity], redact_secrets: bool) -> None:
        self.redact_secrets = redact_secrets
        self.mapping: dict[str, str] = {}
        per_kind: dict[str, int] = {}
        # longest first, so a value containing another is replaced whole
        for e in sorted(entities, key=lambda e: -len(e.value)):
            if e.value in self.mapping:
                continue
            per_kind[e.kind] = per_kind.get(e.kind, 0) + 1
            self.mapping[e.value] = f"<{e.kind.upper()}_{per_kind[e.kind]}>"

    def text(self, value: str) -> str:
        if self.redact_secrets:
            value = redact_text(value)
        for original in sorted(self.mapping, key=len, reverse=True):
            value = value.replace(original, self.mapping[original])
        return value

    def arguments(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: self.arguments(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.arguments(v) for v in value]
        if isinstance(value, tuple):
            return tuple(self.arguments(v) for v in value)
        if isinstance(value, str):
            return self.text(value)
        return value


# --- the detector ----------------------------------------------------------
@dataclass
class ClassifyAssessment:
    label: str = "PUBLIC"
    signals: list[Signal] = field(default_factory=list)
    verdict_floor: Verdict = Verdict.ALLOW
    action: str | None = None
    redacted_arguments: Any = None


class DataClassifier:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def assess(self, tool: str, arguments: Any, tiers: list[str],
               role: str | None, scan: ScanResult | None = None,
               enforcing: bool = False) -> ClassifyAssessment:
        out = ClassifyAssessment()
        cfg = self.policy.classification
        sink_tiers = [t for t in tiers if t in _DLP_TIERS]
        if not cfg.enabled or not sink_tiers:
            return out

        leaves = flatten(arguments)
        for where, value in leaves:
            if _is_attachment_key(where) and _PATHISH.search(value.strip()):
                out.signals.append(Signal(
                    "dlp:unscanned_attachment", 0.0,
                    f"`{where}` passes a file by path ({value[:80]}); the gateway does "
                    f"not open attachments, so its contents were not classified",
                ))

        secret = bool(scan and scan.of_kind("secret"))
        result = classify_text("\n".join(v for _w, v in leaves), self.policy, secret)
        out.label = result.label

        # The strictest rule across every DLP tier this call belongs to.
        chosen: tuple[str, str, str] | None = None     # (action, tier, limit)
        for tier in sink_tiers:
            limit = cfg.limit_for(role, tier)
            if _RANK[result.label] <= _RANK[limit]:
                continue
            action = cfg.actions.get(result.label, "review")
            if chosen is None or _ACTION_RANK[action] > _ACTION_RANK[chosen[0]]:
                chosen = (action, tier, limit)
        if chosen is None:
            return out

        action, tier, limit = chosen
        out.action = action
        detail = (f"{result.label} payload ({result.summary()}) exceeds the "
                  f"{limit} limit for role '{role or 'default'}' on the {tier} tier; "
                  f"action: {action}")
        if action == "redact" and not enforcing:
            detail += " (observe mode: would redact, arguments left unchanged)"
        out.signals.append(Signal(f"dlp:over_limit:{result.label}", 0.0, detail))

        if action == "block":
            out.verdict_floor = Verdict.BLOCK
        elif action == "review":
            out.verdict_floor = Verdict.REVIEW
        elif action == "redact" and enforcing:
            redactor = _Redactor(result.entities, redact_secrets=secret)
            out.redacted_arguments = redactor.arguments(arguments)
            out.signals.append(Signal(
                "dlp:redacted", 0.0,
                f"replaced {len(redactor.mapping)} value(s) with typed placeholders "
                f"before forwarding to '{tool}'",
            ))
        return out
