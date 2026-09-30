"""Fast-path scanner. Deterministic, no model calls, target <5ms per call.

Three independent signal sources, deliberately kept separate because they are
different kinds of evidence and want different weights:

  1. Secrets   - the `detect-secrets` engine (Yelp), two-tier (see below).
  2. Paths     - glob denylist for credential stores (~/.ssh, .env, ...).
  3. Injection - prompt-injection / jailbreak phrasing patterns.

Why detect-secrets is used in two tiers
---------------------------------------
detect-secrets ships 26 structural detectors (AWS, GitHub, JWT, private keys...)
plus two entropy detectors. The entropy detectors are built for scanning source
files, where surrounding filters suppress noise. Applied naively to a tool
argument they fire constantly on ordinary prose - measured during build, the
string "the weather is nice in paris today" produced ten entropy findings.
Because a secret finding pushes the risk score toward BLOCK, that would make the
gateway unusable on real traffic.

So: structural detectors always run (high precision, full weight), while the two
entropy detectors run only against text that already looks credential-bearing
(`key=`, `token:`, `password ...`) and carry a lower weight. Real base64/hex
secrets still get caught; ordinary English sentences do not get blocked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import PurePosixPath
from typing import Any, Iterable

from detect_secrets.core import scan as ds_scan
from detect_secrets.settings import transient_settings

# --- tier 1: structural detectors, always applied ---------------------------
_STRUCTURAL_PLUGINS = [
    {"name": n}
    for n in (
        "AWSKeyDetector", "ArtifactoryDetector", "AzureStorageKeyDetector",
        "BasicAuthDetector", "CloudantDetector", "DiscordBotTokenDetector",
        "GitHubTokenDetector", "GitLabTokenDetector", "IbmCloudIamDetector",
        "IbmCosHmacDetector", "JwtTokenDetector", "KeywordDetector",
        "MailchimpDetector", "NpmDetector", "OpenAIDetector",
        "PrivateKeyDetector", "PypiTokenDetector", "SendGridDetector",
        "SlackDetector", "SoftlayerDetector", "SquareOAuthDetector",
        "StripeDetector", "TelegramBotTokenDetector", "TwilioKeyDetector",
    )
]

# --- tier 2: entropy detectors, gated on credential-looking context ---------
_ENTROPY_SETTINGS = [
    {"name": "Base64HighEntropyString", "limit": 4.5},
    {"name": "HexHighEntropyString", "limit": 3.0},
]

CRED_CONTEXT = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|credential|auth|"
    r"bearer|access[_-]?key|private[_-]?key|client[_-]?secret|session[_-]?id)\b"
)

# Paths a tool call should never touch by default.
DEFAULT_PATH_DENYLIST: tuple[str, ...] = (
    "**/.ssh/**", "**/.ssh", "**/.aws/**", "**/.env", "**/.env.*",
    "**/credentials/**", "**/credentials", "**/.gnupg/**",
    "**/id_rsa*", "**/id_ed25519*", "**/.netrc", "**/.npmrc",
    "**/.docker/config.json", "**/shadow", "**/.kube/config",
)

# Prompt-injection and jailbreak phrasings, as (name, pattern).
INJECTION_PATTERNS: tuple[tuple[str, str], ...] = (
    ("instruction_override",
     r"(?i)ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier)\s+"
     r"(instruction|prompt|rule|direction)"),
    ("instruction_disregard",
     r"(?i)disregard\s+(all\s+|your\s+)?(previous|prior|above|system)\s+\w+"),
    ("role_hijack", r"(?i)you\s+are\s+now\s+(a|an|the)\s+\w+"),
    ("system_prompt_probe",
     r"(?i)(reveal|print|show|repeat|output)\s+(me\s+)?(your\s+)?"
     r"(system\s+prompt|initial\s+instruction|the\s+prompt)"),
    ("dev_mode", r"(?i)(developer|debug|god|dan)\s+mode\s+(on|enabled|activated)"),
    ("safety_bypass",
     r"(?i)(bypass|disable|turn\s+off|ignore)\s+(all\s+|your\s+)?"
     r"(safety|security|guardrail|filter|restriction)"),
    ("hidden_directive", r"(?i)<!--\s*(system|instruction|ai|assistant|agent)"),
    ("exfil_instruction",
     r"(?i)(send|post|upload|email|forward|transmit)\s+(this|it|the\s+\w+|contents?)"
     r"\s+to\s+(https?://|\S+@|\S+\.\w{2,})"),
    ("credential_hunt",
     r"(?i)(read|cat|open|fetch|find|locate)\s+\S{0,20}"
     r"(\.ssh|id_rsa|\.env|credentials|api[_-]?key)"),
    ("memory_implant",
     r"(?i)(remember|save|store|memorize|persist|add)\s+(this|that|the\s+following)?"
     r"\s*(to|in|into)\s+(your\s+)?(memory|notes|context|preferences)"),
    ("tool_directive",
     r"(?i)(you\s+must|always)\s+(now\s+)?(call|use|route|invoke)\s+\S+\s+(tool|through|via)"),
    ("urgency_pressure",
     r"(?i)(urgent|immediately|do\s+not\s+tell|without\s+(telling|asking|informing))"
     r"\s+(the\s+)?(user|human|owner)"),
)

_COMPILED_INJECTION = [(name, re.compile(p)) for name, p in INJECTION_PATTERNS]

# Self-propagation phrasing: text addressed to a *later* AI reader, asking it to
# carry the text onward. Kept out of INJECTION_PATTERNS on purpose - these only
# count as evidence inside untrusted content bound for a propagation sink (see
# propagation.py), so adding them to scan_text would change the scanner's
# verdict on ordinary instruction text, which Stage 7A must not do.
#
# `self_replicate` requires a spreading quantifier ("into EVERY file", "in ANY
# email") so that a tutorial's "copy this into your terminal" does not match.
PROPAGATION_PATTERNS: tuple[tuple[str, str], ...] = (
    ("ai_reader_address",
     r"(?i)\bwhen(ever)?\s+(an?\s+|any\s+|the\s+)?"
     r"(ai|agent|assistant|llm|model|bot|copilot)s?\s+"
     r"(reads?|sees?|process(es)?|encounters?|summari[sz]es?|opens?)\b"),
    ("ai_reader_note",
     r"(?i)\b(note|instructions?|message|attention)\s+(to|for)\s+"
     r"(any|all|every|the)\s+(ai|agent|assistant|llm|model|bot)s?\b"),
    ("self_replicate",
     r"(?i)\b(copy|paste|include|insert|append|embed|forward|propagate|replicate|"
     r"repeat|reproduce)\s+(this|these|it|the\s+following)\b[^.\n]{0,40}?"
     r"\b(into|in|to|with)\s+(every|all|any|each|other|future)\b"),
)

_COMPILED_PROPAGATION = [(name, re.compile(p)) for name, p in PROPAGATION_PATTERNS]


@dataclass
class Finding:
    """One scanner hit. `kind` groups findings for the risk engine."""

    kind: str          # "secret" | "secret_entropy" | "path" | "injection"
    label: str         # detector or pattern name
    where: str = ""    # which argument leaf it came from
    excerpt: str = ""  # short, redacted context

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "label": self.label,
                "where": self.where, "excerpt": self.excerpt}


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)

    def of_kind(self, *kinds: str) -> list[Finding]:
        return [f for f in self.findings if f.kind in kinds]

    @property
    def secrets(self) -> list[Finding]:
        return self.of_kind("secret", "secret_entropy")

    @property
    def paths(self) -> list[Finding]:
        return self.of_kind("path")

    @property
    def injections(self) -> list[Finding]:
        return self.of_kind("injection")

    def __bool__(self) -> bool:
        return bool(self.findings)

    def to_dict(self) -> list[dict[str, Any]]:
        return [f.to_dict() for f in self.findings]


def _redact(text: str, limit: int = 60) -> str:
    """Never echo a full secret into a log line."""
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit] + "..."


def flatten(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    """Walk a nested argument structure into (path, text) leaves.

    Argument-level validation is a requirement, so the scanner has to see inside
    dicts and lists rather than only stringifying the top-level payload.
    """
    out: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, val in value.items():
            out.extend(flatten(val, f"{prefix}.{key}" if prefix else str(key)))
    elif isinstance(value, (list, tuple)):
        for i, val in enumerate(value):
            out.extend(flatten(val, f"{prefix}[{i}]"))
    elif value is None or isinstance(value, bool):
        pass
    else:
        out.append((prefix or "value", str(value)))
    return out


def _scrub_excerpts(findings: list[Finding]) -> list[Finding]:
    """Redact secret values out of finding excerpts.

    Excerpts travel into the audit log and the review queue, so a finding about a
    credential must not carry the credential with it. Called after the detector
    settings context has closed, since redaction opens its own.
    """
    for f in findings:
        if f.excerpt:
            f.excerpt = _redact(redact_text(f.excerpt))
    return findings


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per (kind,label,where) so repeated matches don't inflate scores."""
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.kind, f.label, f.where)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def scan_secrets(text: str, where: str = "") -> list[Finding]:
    """Two-tier secret scan of one string."""
    findings: list[Finding] = []
    lines = text.splitlines() or [text]

    with transient_settings({"plugins_used": _STRUCTURAL_PLUGINS}):
        for line in lines:
            for s in ds_scan.scan_line(line):
                findings.append(Finding("secret", s.type, where, _redact(line)))

    if CRED_CONTEXT.search(text):
        with transient_settings({"plugins_used": _ENTROPY_SETTINGS}):
            for line in lines:
                if not CRED_CONTEXT.search(line):
                    continue
                for s in ds_scan.scan_line(line):
                    findings.append(Finding("secret_entropy", s.type, where, _redact(line)))

    return _scrub_excerpts(_dedupe(findings))


def _normalise_path(text: str) -> str | None:
    """Turn a candidate string into a comparable posix path, or None."""
    t = text.strip().strip("'").strip('"')
    if not t or "\n" in t or len(t) > 512:
        return None
    looks_like_path = ("/" in t) or ("\\" in t) or t.startswith("~") or t.startswith(".")
    if not looks_like_path:
        return None
    t = t.replace("\\", "/")
    if t.startswith("~"):
        t = "/home/user" + t[1:]
    return str(PurePosixPath(t))


def scan_paths(text: str, where: str = "",
               denylist: Iterable[str] = DEFAULT_PATH_DENYLIST) -> list[Finding]:
    """Glob-match a candidate path against the credential-store denylist."""
    p = _normalise_path(text)
    if p is None:
        return []
    name = PurePosixPath(p).name
    for pattern in denylist:
        bare = pattern.replace("**/", "")
        if fnmatch(p, pattern) or fnmatch(p, bare) or fnmatch(name, bare):
            return _scrub_excerpts([Finding("path", pattern, where, _redact(text))])
    return []


def scan_injection(text: str, where: str = "") -> list[Finding]:
    return _scrub_excerpts([
        Finding("injection", name, where, _redact(text))
        for name, rx in _COMPILED_INJECTION
        if rx.search(text)
    ])


def scan_propagation_phrasing(text: str, where: str = "") -> list[Finding]:
    """Self-propagation phrasing. Not part of scan_text - see PROPAGATION_PATTERNS."""
    return _scrub_excerpts([
        Finding("propagation_phrasing", name, where, _redact(text))
        for name, rx in _COMPILED_PROPAGATION
        if rx.search(text)
    ])


def scan_text(text: str, where: str = "",
              denylist: Iterable[str] = DEFAULT_PATH_DENYLIST) -> ScanResult:
    """Run all three detectors over a single string."""
    res = ScanResult()
    res.findings.extend(scan_secrets(text, where))
    res.findings.extend(scan_paths(text, where, denylist))
    res.findings.extend(scan_injection(text, where))
    return res


def scan_arguments(arguments: Any,
                   denylist: Iterable[str] = DEFAULT_PATH_DENYLIST) -> ScanResult:
    """Scan every leaf of a tool-call argument structure."""
    res = ScanResult()
    for where, text in flatten(arguments):
        res.findings.extend(scan_text(text, where, denylist).findings)
    res.findings = _dedupe(res.findings)
    return res


# --- redaction -------------------------------------------------------------
def redact_text(text: str) -> str:
    """Replace any detected secret value in `text` with a type marker.

    Used before anything is written to the audit log. A log that records the very
    credentials it caught would be a new place for secrets to accumulate, which
    defeats the point of catching them.
    """
    replacements: dict[str, str] = {}
    lines = text.splitlines() or [text]

    with transient_settings({"plugins_used": _STRUCTURAL_PLUGINS}):
        for line in lines:
            for s in ds_scan.scan_line(line):
                value = getattr(s, "secret_value", None)
                if value and len(str(value)) >= 6:
                    replacements[str(value)] = f"<redacted:{s.type}>"

    if CRED_CONTEXT.search(text):
        with transient_settings({"plugins_used": _ENTROPY_SETTINGS}):
            for line in lines:
                if not CRED_CONTEXT.search(line):
                    continue
                for s in ds_scan.scan_line(line):
                    value = getattr(s, "secret_value", None)
                    if value and len(str(value)) >= 12:
                        replacements[str(value)] = "<redacted:high-entropy>"

    out = text
    # Longest first, so a secret containing another match is replaced whole.
    for value in sorted(replacements, key=len, reverse=True):
        out = out.replace(value, replacements[value])
    return out


def redact_arguments(arguments: Any) -> Any:
    """Return a copy of an argument structure with secret values redacted."""
    if isinstance(arguments, dict):
        return {k: redact_arguments(v) for k, v in arguments.items()}
    if isinstance(arguments, list):
        return [redact_arguments(v) for v in arguments]
    if isinstance(arguments, tuple):
        return tuple(redact_arguments(v) for v in arguments)
    if isinstance(arguments, str):
        return redact_text(arguments)
    return arguments
