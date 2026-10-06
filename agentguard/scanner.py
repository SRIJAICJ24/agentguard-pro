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

# --- tier 1b: current key formats detect-secrets doesn't cover --------------
# Each prefix was checked against the provider's own documentation (F1, see
# docs/week-log.md for sources). Bodies are matched loosely, by character class
# and a minimum length, because providers don't publish body lengths; the left
# boundary keeps `ask-admin-...` from reading as `sk-admin-...`, and the minimum
# length keeps a bare prefix mentioned in prose from matching.
_KEY_LEFT = r"(?<![A-Za-z0-9_\-.])"
MODERN_KEY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (label, re.compile(pattern)) for label, pattern in (
        # OpenAI: sk-admin- (Admin API reference); sk-proj-, sk-svcacct-
        ("OpenAI API Key", _KEY_LEFT + r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}"),
        # Anthropic: sk-ant-api03-... (API keys), sk-ant-admin... (Admin API keys)
        ("Anthropic API Key", _KEY_LEFT + r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{20,}"),
        # Google Cloud API keys: AIza + 35 (docs example is 39 characters)
        ("Google API Key", _KEY_LEFT + r"AIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])"),
        # GitHub fine-grained personal access tokens (classic ghp_ etc. are
        # already covered by detect-secrets)
        ("GitHub Fine-grained Token", _KEY_LEFT + r"github_pat_[A-Za-z0-9_]{22,}"),
        # Slack app-level (xapp-), rotating app-level (xoxe.xapp-), workflow (xwfp-);
        # xoxb-/xoxp- are already covered by detect-secrets
        ("Slack App Token", _KEY_LEFT + r"(?:xoxe\.)?(?:xapp|xwfp)-[A-Za-z0-9\-]{20,}"),
        # Stripe: live and sandbox secret/restricted keys, organisation keys.
        # Publishable pk_ keys are documented as safe to expose and not flagged.
        ("Stripe API Key", _KEY_LEFT + r"(?:(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}"
                                       r"|sk_org_[0-9A-Za-z_]{20,})"),
    )
)


def scan_modern_keys(text: str, where: str = "") -> list["Finding"]:
    return [Finding("secret", label, where, _redact(line))
            for line in (text.splitlines() or [text])
            for label, rx in MODERN_KEY_PATTERNS if rx.search(line)]


CRED_CONTEXT = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|credential|auth|"
    r"bearer|access[_-]?key|private[_-]?key|client[_-]?secret|session[_-]?id)\b"
)

# The entropy tier looks only at the *value* given to a credential name -
# `AUTH_TOKEN=...`, `"client_secret": "..."`, `Authorization: Bearer ...` - not at
# every string on a line that happens to contain the word "auth". Week 2: the
# line-level gate flagged 334 of 6,435 replayed real calls (`cat lib/auth.ts`,
# commit hashes in a document that mentions auth) and still missed unquoted
# `export AUTH_TOKEN=<value>`, which detect-secrets' quoted-string scan skips.
CRED_VALUE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:api[_-]?key|secret|token|password|passwd|pwd|credentials?|"
    r"auth(?:orization)?|bearer|access[_-]?key|private[_-]?key|client[_-]?secret|"
    r"session[_-]?id)[A-Za-z0-9_\-]*[\"']?\s*(?::=|=>|=|:|\s)\s*"
    r"(?:(?:bearer|basic|token)\s+)?[\"']?([A-Za-z0-9+/_\-.~=]{16,})"
)
_PLACEHOLDER = re.compile(r"(?i)example|placeholder|changeme|your|xxxx|dummy|redacted|sample")


def _entropy_label(value: str) -> str | None:
    """The detect-secrets entropy type `value` qualifies as, or None."""
    from detect_secrets.plugins.high_entropy_strings import (
        Base64HighEntropyString, HexHighEntropyString)
    import math

    value = value.rstrip(".")                 # sentence punctuation, not the value
    if len(value) < 16 or _PLACEHOLDER.search(value):
        return None
    has_digit = bool(re.search(r"\d", value))
    mixed_case = bool(re.search(r"[a-z]", value) and re.search(r"[A-Z]", value))
    # Identifiers (`access_token_expires_at`, `process.env.API_KEY`) have no digits
    # or no case mix; random tokens nearly always have both. A long token with no
    # digit must clear detect-secrets' full bar.
    if not re.search(r"[A-Za-z]", value) or not (has_digit or (mixed_case and len(value) >= 32)):
        return None
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        hex_limit = next(s["limit"] for s in _ENTROPY_SETTINGS if s["name"].startswith("Hex"))
        if HexHighEntropyString(limit=hex_limit).calculate_shannon_entropy(value) > hex_limit:
            return "Hex High Entropy String"
        return None
    b64_limit = next(s["limit"] for s in _ENTROPY_SETTINGS if s["name"].startswith("Base64"))
    # Short tokens can't reach detect-secrets' 4.5 bits (a 22-character random
    # token measures about 4.4), so the bar scales with length; the credential
    # name in front of the value is what makes a lower bar safe here.
    limit = max(3.0, min(b64_limit, 0.8 * math.log2(len(value)))) if has_digit else b64_limit
    if Base64HighEntropyString(limit=b64_limit).calculate_shannon_entropy(value) > limit:
        return "Base64 High Entropy String"
    return None


def credential_values(line: str) -> list[tuple[str, str]]:
    """(value, entropy label) for each high-entropy value given to a credential name."""
    out: list[tuple[str, str]] = []
    for m in CRED_VALUE.finditer(line):
        label = _entropy_label(m.group(1))
        if label:
            out.append((m.group(1), label))
    return out

# Paths a tool call should never touch by default.
DEFAULT_PATH_DENYLIST: tuple[str, ...] = (
    "**/.ssh/**", "**/.ssh", "**/.aws/**", "**/.env", "**/.env.*",
    "**/credentials/**", "**/credentials", "**/.gnupg/**",
    "**/id_rsa*", "**/id_ed25519*", "**/.netrc", "**/.npmrc",
    "**/.docker/config.json", "**/shadow", "**/.kube/config",
)
#: Committed templates of credential files (`.env.example`) hold names, not
#: secrets. Week 2: 97 hard blocks in the replay were reads/diffs of these.
TEMPLATE_SUFFIXES: tuple[str, ...] = (".example", ".sample", ".template", ".tmpl",
                                      ".tpl", ".dist", ".defaults")

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


_USERINFO_URL = re.compile(r"[a-z][a-z0-9+.\-]*://[^\s:/@'\"]+:[^\s/@'\"]*@(\[[^\]]+\]|[^\s/:'\"?#]+)",
                           re.IGNORECASE)
_LOCAL_HOSTS = re.compile(r"^(localhost|127(\.\d{1,3}){3}|\[?::1\]?|0\.0\.0\.0|"
                          r"host\.docker\.internal|[a-z0-9_\-]+)$", re.IGNORECASE)


def _local_basic_auth(line: str) -> bool:
    """True if every `scheme://user:pass@host` on the line points at this machine
    or a container-internal name (no dot: `db`, `postgres`). Week 2: 13 replayed
    calls were local development database URLs like postgres:postgres@127.0.0.1."""
    hosts = [m.group(1) for m in _USERINFO_URL.finditer(line)]
    return bool(hosts) and all(_LOCAL_HOSTS.match(h) for h in hosts)


def scan_secrets(text: str, where: str = "") -> list[Finding]:
    """Two-tier secret scan of one string."""
    findings: list[Finding] = []
    lines = text.splitlines() or [text]

    with transient_settings({"plugins_used": _STRUCTURAL_PLUGINS}):
        for line in lines:
            for s in ds_scan.scan_line(line):
                if s.type == "Basic Auth Credentials" and _local_basic_auth(line):
                    continue
                findings.append(Finding("secret", s.type, where, _redact(line)))
    findings.extend(scan_modern_keys(text, where))

    for line in lines:
        for _value, label in credential_values(line):
            findings.append(Finding("secret_entropy", label, where, _redact(line)))

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
    if name.lower().endswith(TEMPLATE_SUFFIXES):
        return []
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
                # Some detectors report only part of the secret as its value -
                # GitHub's returns just the "ghp" prefix - so redacting the value
                # alone left the whole token in the log. Also redact the full
                # match of the reporting detector's own patterns.
                for match in _full_matches(s.type, line):
                    if len(match) >= 6:
                        replacements[match] = f"<redacted:{s.type}>"

    # Current key formats (MODERN_KEY_PATTERNS) - always the whole token.
    for line in lines:
        for label, rx in MODERN_KEY_PATTERNS:
            for m in rx.finditer(line):
                end = m.end()
                while end < len(line) and line[end] in _TOKEN_CHARS:
                    end += 1
                replacements[line[m.start():end]] = f"<redacted:{label}>"

    if CRED_CONTEXT.search(text):
        with transient_settings({"plugins_used": _ENTROPY_SETTINGS}):
            for line in lines:
                if not CRED_CONTEXT.search(line):
                    continue
                for s in ds_scan.scan_line(line):
                    value = getattr(s, "secret_value", None)
                    if value and len(str(value)) >= 12:
                        replacements[str(value)] = "<redacted:high-entropy>"

    # Whatever the entropy tier flagged must not reach the log either.
    for line in lines:
        for value, _label in credential_values(line):
            replacements[value] = "<redacted:high-entropy>"

    out = text
    # Longest first, so a secret containing another match is replaced whole.
    for value in sorted(replacements, key=len, reverse=True):
        out = out.replace(value, replacements[value])
    return out


_DETECTOR_PATTERNS: dict[str, tuple[Any, ...]] = {}


def _full_matches(secret_type: str, line: str) -> list[str]:
    """Whole-match text of a detect-secrets detector's regexes in `line`.

    Only used for redaction, after the detector has already reported a finding
    on this line. Detectors without a regex denylist (keyword, entropy) are
    covered by their reported value instead.
    """
    if secret_type not in _DETECTOR_PATTERNS:
        patterns: tuple[Any, ...] = ()
        try:
            from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class

            cls = get_mapping_from_secret_type_to_class().get(secret_type)
            if cls is not None:
                patterns = tuple(getattr(cls(), "denylist", ()) or ())
        except Exception:                                     # noqa: BLE001
            patterns = ()
        _DETECTOR_PATTERNS[secret_type] = patterns
    out: list[str] = []
    for rx in _DETECTOR_PATTERNS[secret_type]:
        for m in rx.finditer(line):
            # Some patterns match only the start of a token (a JWT's first two
            # segments, a fixed-length Stripe prefix). Extend to the end of the
            # contiguous token so no tail of the secret is left behind.
            end = m.end()
            while end < len(line) and line[end] in _TOKEN_CHARS:
                end += 1
            out.append(line[m.start():end])
    return out


_TOKEN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.+/=")


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
