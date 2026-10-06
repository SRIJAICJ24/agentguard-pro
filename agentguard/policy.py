"""Policy: the YAML file that governs the gateway.

One file holds every tunable: tool allow/deny, role-based access, sink tiers,
quarantine TTLs, thresholds and the enforcement switch. An explicit deny always
wins and is checked before any score is computed - a policy statement is not
evidence to be weighed, it is a rule.

Enforcement defaults to OFF (observe/log-only). Detection features ship quiet
until their false-positive rate has been measured on real traffic; in observe
mode every decision is still computed and logged, but BLOCK/REVIEW does not
actually stop the call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import yaml

from agentguard.decision import Verdict

DEFAULT_POLICY_FILENAME = "agentguard.policy.yaml"

# Sink tiers. `ordinary` is the default for anything unmatched.
TIER_ORDINARY = "ordinary"
TIER_EXFILTRATION = "exfiltration"
TIER_PERSISTENCE = "persistence"
# Stage 7 tiers. Unlike the three above, a call may belong to several tiers at
# once (an outgoing email is both exfiltration and propagation); see sink_tiers().
TIER_PROPAGATION = "propagation"
TIER_FINANCIAL = "financial"

DEFAULT_SINKS: dict[str, list[str]] = {
    TIER_EXFILTRATION: [
        "*email*", "*send*", "*smtp*", "*slack*", "*webhook*", "*http_post*",
        "*post_request*", "*upload*", "*publish*", "*tweet*", "*message*",
        "web.post", "network.*",
    ],
    TIER_PERSISTENCE: [
        "*memory_save*", "*memory.save*", "*save_memory*", "*remember*",
        "*vector*", "*embed*store*", "*rag*", "*index_add*", "*upsert*",
        "memory.*", "knowledge.*",
    ],
    # Surfaces other agents or people will later read: the channels a
    # self-replicating injection travels through. Deliberately specific - a read
    # tool that merely mentions "slack" or "chat" must not land here.
    TIER_PROPAGATION: [
        "*write*", "*create_file*", "*edit_file*", "*append*",
        "git.commit*", "*git_commit*",
        "*add_comment*", "*create_comment*", "*post_comment*", "*create_issue*",
        "*pull_request*",
        # GitHub MCP server names that the patterns above miss
        "*issue_comment*", "*create_or_update_file*", "*push_files*",
        "*update_document*", "*edit_document*",
        "*post_message*", "*slack*post*", "*slack*send*", "*chat*post*", "*chat*send*",
        "email.send", "*send_email*", "*send_mail*",
    ],
    # Moves money. `*pay*` alone would also catch `payload`, so the globs name
    # the action rather than the substring.
    TIER_FINANCIAL: [
        "*payment*", "payments.*", "*.pay", "*_pay", "pay_*", "*purchase*",
        "*checkout*", "*refund*", "*transfer_funds*", "*wire_transfer*",
        "*send_money*", "*invoice*pay*", "*pay*invoice*",
    ],
}

#: Tiers that are only ever *additional* memberships, checked by sink_tiers().
EXTRA_TIERS: tuple[str, ...] = (TIER_PROPAGATION, TIER_FINANCIAL)

DEFAULT_TRUSTED_READ_PATHS: list[str] = ["./**", "docs/**", "src/**"]


#: Data classification labels, least to most sensitive (Stage 7B).
LABELS: tuple[str, ...] = ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "PII", "SECRET")
DLP_ACTIONS: tuple[str, ...] = ("log", "redact", "review", "block")   # mildest first


@dataclass
class ClassificationConfig:
    """`classification:` - volume-aware DLP on exfiltration/propagation sinks.

    Counts, not presence: one address in a message is correspondence, fifty is an
    export. Email/phone counts at or above `confidential_count` make the payload
    CONFIDENTIAL, at or above `pii_count` PII. Any card, PAN or Aadhaar number is
    PII outright.

    Propagation defaults to PII rather than CONFIDENTIAL: a contributors file or a
    commit with a list of addresses is normal local work, while the same list
    leaving by email is not. A call in both tiers (email) takes the stricter limit.
    """

    enabled: bool = True
    confidential_count: int = 10
    pii_count: int = 50
    confidential_markers: list[str] = field(default_factory=lambda: [
        "confidential", "proprietary", "do not distribute", "not for distribution",
    ])
    internal_markers: list[str] = field(default_factory=lambda: [
        "internal only", "internal use only", "for internal use",
    ])
    max_label: dict[str, str] = field(default_factory=lambda: {
        "exfiltration": "CONFIDENTIAL", "propagation": "PII",
    })
    role_max_label: dict[str, dict[str, str]] = field(default_factory=dict)
    actions: dict[str, str] = field(default_factory=lambda: {
        "SECRET": "block", "PII": "block", "CONFIDENTIAL": "review", "INTERNAL": "log",
    })

    def limit_for(self, role: str | None, tier: str) -> str:
        per_role = self.role_max_label.get(role or "", {})
        return per_role.get(tier, self.max_label.get(tier, "SECRET"))


def _classification_from_dict(data: dict[str, Any]) -> ClassificationConfig:
    c = ClassificationConfig()
    c.enabled = bool(data.get("enabled", c.enabled))
    thresholds = data.get("thresholds") or {}
    c.confidential_count = int(thresholds.get("confidential", c.confidential_count))
    c.pii_count = int(thresholds.get("pii", c.pii_count))
    markers = data.get("markers") or {}
    if "confidential" in markers:
        c.confidential_markers = _as_list(markers["confidential"])
    if "internal" in markers:
        c.internal_markers = _as_list(markers["internal"])
    for key, limits in (data.get("max_label") or {}).items():
        limits = {str(t): str(lbl).upper() for t, lbl in (limits or {}).items()}
        bad = [lbl for lbl in limits.values() if lbl not in LABELS]
        if bad:
            raise ValueError(f"classification.max_label: unknown label(s) {bad}")
        if key == "default":
            c.max_label.update(limits)
        else:
            c.role_max_label[str(key)] = limits
    for label, action in (data.get("actions") or {}).items():
        label, action = str(label).upper(), str(action).lower()
        if label not in LABELS or action not in DLP_ACTIONS:
            raise ValueError(f"classification.actions: bad rule {label}: {action}")
        c.actions[label] = action
    return c


@dataclass
class ScopeConfig:
    """`scope:` - declared task scope (Stage 7C)."""

    enabled: bool = True
    # Tool names that belong to AgentGuard's own control plane. No upstream tool
    # may use them; a call to one is a tamper attempt, never forwarded as normal.
    reserved_tools: list[str] = field(default_factory=lambda: ["agentguard*"])


@dataclass
class AlignmentConfig:
    """`alignment:` - optional model-based AlignmentAuditor (Stage 7C).

    Off unless `auditor` is set. Only a loopback endpoint is accepted unless
    `allow_remote` is explicitly true - the gateway never calls a remote API on
    its own initiative.
    """

    auditor: str = "none"            # none | openai_compatible
    endpoint: str = "http://127.0.0.1:11434/v1"
    model: str = "llama3.1"
    allow_remote: bool = False
    history: int = 8
    timeout_seconds: float = 5.0


@dataclass
class FinancialConfig:
    """`financial:` - the financial sink tier (Stage 7D).

    Every financial call is held for REVIEW regardless of score. The optional
    per-session cap is in one currency; a call in another currency cannot be
    compared against it and is flagged rather than guessed at.
    """

    enabled: bool = True
    session_cap: float | None = None
    cap_currency: str | None = None


#: Rules that may be hard-enforced: they block even in observe mode, while every
#: other rule keeps observe behaviour. See agentguard/hardrules.py.
HARD_RULES: tuple[str, ...] = ("credential_files", "secret_exfiltration", "self_protection")
#: What the shipped policy and the onboarding starter policy enable. A Policy built
#: in code starts with an empty list, which behaves exactly as before the feature.
DEFAULT_HARD_ENFORCE: list[str] = list(HARD_RULES)


#: Default Claude Code hook patterns (readiness phase). They live here only so a
#: missing `hooks:` section still gets sane behaviour; the shipped policy YAML
#: lists them explicitly, and anything under `hooks.bash.*` in YAML replaces the
#: corresponding list. All are Python regular expressions matched against the
#: whole shell command (Bash or PowerShell tool), case-insensitively.
DEFAULT_HOOK_BASH: dict[str, list[str]] = {
    # network egress commands - the call joins the exfiltration tier unless every
    # destination host it names is allowlisted
    "exfiltration": [
        r"\b(curl|wget|nc|ncat|netcat|socat|telnet|scp|sftp|ftp|rsync)\b",
        r"\b(Invoke-WebRequest|Invoke-RestMethod|iwr|Start-BitsTransfer)\b",
    ],
    # commands that publish to a surface other people or agents read
    "propagation": [
        r"\bgit\s+(commit|push)\b",
        r"\bgh\s+(pr|issue)\s+(create|comment|edit|review)\b",
        # output redirected into a file (not /dev/null, not fd duplication)
        r"(?<![0-9&=\-])>{1,2}\s*(?!&|/dev/null\b|\$null\b|nul\b)[^\s|&;>]+",
        r"\b(Set-Content|Add-Content|Out-File)\b",
    ],
    # recursive deletes and disk-level commands -> REVIEW
    "destructive": [
        r"\brm\s+(-[a-z]*r[a-z]*|--recursive)\b",
        r"\bRemove-Item\b[^\n]*-Recurse\b",
        r"\b(rmdir|rd)\s+/s\b",
        r"\bdel\s+(/[a-z]\s+)*/s\b",
        r"\bmkfs(\.\w+)?\b",
        r"\bdd\s+[^\n]*\bof=/dev/",
        r"\bformat\s+[a-z]:",
        r"\b(diskpart|shred|wipefs)\b",
        r"\bFormat-Volume\b|\bClear-Disk\b",
    ],
}

#: Commands that would disable AgentGuard itself (self-protection, A6).
DEFAULT_SELF_PROTECT_COMMANDS: list[str] = [
    r"\b(pkill|killall)\b[^\n]*\b(agentguard|python)",
    r"\btaskkill\b[^\n]*\b(agentguard|python)",
    r"\bStop-Process\b[^\n]*\b(agentguard|python)",
    r"\bschtasks\b[^\n]*/(delete|end|change)\b[^\n]*agentguard",
    r"\bsystemctl\s+--user\s+(stop|disable|mask|kill)\s+agentguard",
    r"\blaunchctl\s+(unload|remove|bootout)\b[^\n]*agentguard",
    r"\bagentguard(\.cli)?\s+(uninstall-hooks|unlock)\b",
    r"\bdisableAllHooks\b",
]

#: Extra file locations treated as AgentGuard's own (self-protection, A6). Globs
#: matched against a forward-slash, lower-cased absolute path.
#:
#: Self-protection guards the LIVE setup (F5), resolved at runtime: the policy
#: file the daemon loaded and the one recorded in agentguard.json, the live
#: AGENTGUARD_HOME, the Claude Code user settings, and any settings file that
#: currently registers AgentGuard's hooks. It deliberately does NOT match every
#: file named agentguard.policy.yaml - the repository's copy, where AgentGuard is
#: developed, is ordinary work. Only the service definitions, which live outside
#: AGENTGUARD_HOME, are listed here.
DEFAULT_SELF_PROTECT_PATHS: list[str] = [
    "*/systemd/user/agentguard.service",
    "*/launchagents/com.agentguard.gateway.plist",
]


@dataclass
class HooksConfig:
    """`hooks:` - Claude Code hook integration (readiness phase, Phase A)."""

    enabled: bool = True
    # MCP servers whose traffic already goes through the AgentGuard gateway. The
    # gateway is the gate for those calls; the hook only bridges taint for them,
    # so the same call is never counted twice. Matched against the server name in
    # `mcp__<server>__<tool>` and the payload's `mcp_server.name`.
    gateway_servers: list[str] = field(default_factory=lambda: ["agentguard"])
    # Hosts a Bash network command may reach without joining the exfiltration
    # tier. Merged with `egress.allow_hosts`.
    allow_hosts: list[str] = field(default_factory=lambda: ["localhost", "127.0.0.1", "::1"])
    bash: dict[str, list[str]] = field(
        default_factory=lambda: {k: list(v) for k, v in DEFAULT_HOOK_BASH.items()})
    self_protection: bool = True
    self_protect_commands: list[str] = field(
        default_factory=lambda: list(DEFAULT_SELF_PROTECT_COMMANDS))
    self_protect_paths: list[str] = field(
        default_factory=lambda: list(DEFAULT_SELF_PROTECT_PATHS))
    # Results of these Claude Code tools are UNTRUSTED taint sources. MCP tools
    # are classified by their inner name against `taint.untrusted_tools`.
    untrusted_tools: list[str] = field(default_factory=lambda: ["WebFetch", "WebSearch"])
    # A recursive delete whose every target is provably inside the system temp
    # directory is logged (`hook:delete_in_temp`) instead of sent to REVIEW. Week 1:
    # all 14 destructive-command flags were Claude clearing its own scratchpad.
    temp_deletes_ok: bool = True


def _hooks_from_dict(data: dict[str, Any]) -> HooksConfig:
    import re as _re

    h = HooksConfig()
    h.enabled = bool(data.get("enabled", h.enabled))
    if data.get("gateway_servers") is not None:
        h.gateway_servers = _as_list(data.get("gateway_servers"))
    if data.get("allow_hosts") is not None:
        h.allow_hosts = _as_list(data.get("allow_hosts"))
    for key, patterns in (data.get("bash") or {}).items():
        if key not in DEFAULT_HOOK_BASH:
            raise ValueError(f"hooks.bash: unknown pattern list {key!r} "
                             f"(expected one of {sorted(DEFAULT_HOOK_BASH)})")
        h.bash[key] = _as_list(patterns)
    sp = data.get("self_protection")
    if isinstance(sp, dict):
        h.self_protection = bool(sp.get("enabled", True))
        if sp.get("commands") is not None:
            h.self_protect_commands = _as_list(sp.get("commands"))
        if sp.get("paths") is not None:
            h.self_protect_paths = _as_list(sp.get("paths"))
    elif sp is not None:
        h.self_protection = bool(sp)
    if data.get("untrusted_tools") is not None:
        h.untrusted_tools = _as_list(data.get("untrusted_tools"))
    h.temp_deletes_ok = bool(data.get("temp_deletes_ok", h.temp_deletes_ok))
    # Fail at load time, not on the first tool call.
    for pattern in [*(p for ps in h.bash.values() for p in ps), *h.self_protect_commands]:
        try:
            _re.compile(pattern)
        except _re.error as exc:
            raise ValueError(f"hooks: invalid regular expression {pattern!r}: {exc}") from exc
    return h


@dataclass
class RoleRule:
    """Least-privilege rule set for one agent role."""

    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    # Stage 7C: default task scope for sessions of this role (empty = none).
    # Unlike allow/deny this is not a permission: out-of-scope calls are
    # REVIEWed, not blocked.
    scope: list[str] = field(default_factory=list)

    def check(self, tool: str) -> Verdict | None:
        """Deny wins. Then, if an allowlist exists, anything unlisted is denied."""
        for pattern in self.deny:
            if fnmatch(tool, pattern):
                return Verdict.BLOCK
        if self.allow:
            if not any(fnmatch(tool, p) for p in self.allow):
                return Verdict.BLOCK
        return None


@dataclass
class Policy:
    """Parsed policy document."""

    enforcement: bool = False
    allow_tools: list[str] = field(default_factory=list)
    deny_tools: list[str] = field(default_factory=list)
    roles: dict[str, RoleRule] = field(default_factory=dict)
    sinks: dict[str, list[str]] = field(default_factory=lambda: {
        k: list(v) for k, v in DEFAULT_SINKS.items()
    })
    path_denylist: list[str] = field(default_factory=list)
    trusted_read_paths: list[str] = field(default_factory=lambda: list(DEFAULT_TRUSTED_READ_PATHS))
    untrusted_tools: list[str] = field(default_factory=lambda: [
        "web.*", "*search*", "*fetch*", "*browse*", "email.read*", "*inbox*", "rag.*",
    ])
    quarantine_ttl_hours: dict[str, int] = field(default_factory=lambda: {
        "default": 24, "reviewed": 0,   # 0 == indefinite-but-flagged
    })
    allow_below: float = 0.25
    block_above: float = 0.75
    exfiltration_on_taint: str = "REVIEW"   # or "BLOCK"
    egress_allowlist: list[str] = field(default_factory=list)
    # Stage 7 detectors. Each computes and logs by default and only stops a call
    # when `enforcement` is on; `enabled: false` switches one off entirely.
    propagation_enabled: bool = True
    classification: ClassificationConfig = field(default_factory=ClassificationConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    alignment: AlignmentConfig = field(default_factory=AlignmentConfig)
    financial: FinancialConfig = field(default_factory=FinancialConfig)
    hooks: HooksConfig = field(default_factory=HooksConfig)
    # Rules from HARD_RULES that block even when `enforcement` is false.
    hard_enforce: list[str] = field(default_factory=list)
    # F2: workspace labels (folder names) whose hook traffic is development of
    # AgentGuard itself - left out of report, --fp-review and precision unless
    # --include-dev is given. Defaults to this repository's folder name.
    dev_workspaces: list[str] = field(default_factory=lambda: ["agentgaurd"])
    source_path: Path | None = None

    # --- tool-level rules (checked before scoring) -------------------------
    def check_tool(self, tool: str) -> Verdict | None:
        for pattern in self.deny_tools:
            if fnmatch(tool, pattern):
                return Verdict.BLOCK
        if self.allow_tools and not any(fnmatch(tool, p) for p in self.allow_tools):
            return Verdict.BLOCK
        return None

    def check_role(self, role: str | None, tool: str) -> Verdict | None:
        if not role:
            return None
        rule = self.roles.get(role)
        if rule is None:
            return None
        return rule.check(tool)

    # --- sink classification ----------------------------------------------
    def sink_tier(self, tool: str) -> str:
        """Persistence is checked first: a `memory_save` that also matches an
        exfiltration glob must route to the ledger, not the egress path."""
        for pattern in self.sinks.get(TIER_PERSISTENCE, []):
            if fnmatch(tool, pattern):
                return TIER_PERSISTENCE
        for pattern in self.sinks.get(TIER_EXFILTRATION, []):
            if fnmatch(tool, pattern):
                return TIER_EXFILTRATION
        return TIER_ORDINARY

    def sink_tiers(self, tool: str) -> list[str]:
        """Every tier a tool belongs to: its primary tier plus any extra tier.

        `sink_tier()` keeps returning exactly one tier for the Stage 2.5 logic;
        this is what the Stage 7 detectors consult, so that e.g. `email.send` is
        treated as both exfiltration and propagation and the stricter verdict wins.
        """
        tiers = [self.sink_tier(tool)]
        for tier in EXTRA_TIERS:
            if any(fnmatch(tool, p) for p in self.sinks.get(tier, [])):
                tiers.append(tier)
        return tiers

    def is_untrusted_source(self, tool: str) -> bool:
        return any(fnmatch(tool, p) for p in self.untrusted_tools)

    def ttl_hours(self, key: str = "default") -> int:
        return int(self.quarantine_ttl_hours.get(key, self.quarantine_ttl_hours.get("default", 24)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "enforcement": self.enforcement,
            "allow_tools": self.allow_tools,
            "deny_tools": self.deny_tools,
            "roles": {k: {"allow": v.allow, "deny": v.deny, "scope": v.scope}
                      for k, v in self.roles.items()},
            "sinks": self.sinks,
            "trusted_read_paths": self.trusted_read_paths,
            "untrusted_tools": self.untrusted_tools,
            "quarantine_ttl_hours": self.quarantine_ttl_hours,
            "allow_below": self.allow_below,
            "block_above": self.block_above,
            "exfiltration_on_taint": self.exfiltration_on_taint,
            "propagation_enabled": self.propagation_enabled,
        }


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def from_dict(data: dict[str, Any]) -> Policy:
    p = Policy()
    if not data:
        return p

    p.enforcement = bool(data.get("enforcement", False))

    tools = data.get("tools") or {}
    p.allow_tools = _as_list(tools.get("allow"))
    p.deny_tools = _as_list(tools.get("deny"))

    for role, rules in (data.get("roles") or {}).items():
        rules = rules or {}
        p.roles[str(role)] = RoleRule(
            allow=_as_list(rules.get("allow")), deny=_as_list(rules.get("deny")),
            scope=_as_list(rules.get("scope")),
        )

    sinks = data.get("sinks") or {}
    if sinks:
        merged = {k: list(v) for k, v in DEFAULT_SINKS.items()}
        for tier in (TIER_EXFILTRATION, TIER_PERSISTENCE, *EXTRA_TIERS):
            extra = _as_list(sinks.get(tier))
            if extra:
                if sinks.get("replace_defaults"):
                    merged[tier] = extra
                else:
                    merged[tier] = list(dict.fromkeys(merged.get(tier, []) + extra))
        p.sinks = merged

    p.path_denylist = _as_list((data.get("paths") or {}).get("deny"))
    trusted = _as_list((data.get("paths") or {}).get("trusted_read"))
    if trusted:
        p.trusted_read_paths = trusted

    taint = data.get("taint") or {}
    untrusted = _as_list(taint.get("untrusted_tools"))
    if untrusted:
        p.untrusted_tools = untrusted

    quarantine = data.get("quarantine") or {}
    ttl = quarantine.get("ttl_hours")
    if isinstance(ttl, dict):
        p.quarantine_ttl_hours.update({str(k): int(v) for k, v in ttl.items()})
    elif ttl is not None:
        p.quarantine_ttl_hours["default"] = int(ttl)

    thresholds = data.get("thresholds") or {}
    p.allow_below = float(thresholds.get("allow_below", p.allow_below))
    p.block_above = float(thresholds.get("block_above", p.block_above))

    p.exfiltration_on_taint = str(
        (data.get("taint") or {}).get("on_exfiltration", p.exfiltration_on_taint)
    ).upper()
    p.egress_allowlist = _as_list((data.get("egress") or {}).get("allow_hosts"))

    propagation = data.get("propagation") or {}
    p.propagation_enabled = bool(propagation.get("enabled", p.propagation_enabled))

    if data.get("classification"):
        p.classification = _classification_from_dict(data["classification"])

    scope = data.get("scope") or {}
    p.scope.enabled = bool(scope.get("enabled", p.scope.enabled))
    reserved = _as_list(scope.get("reserved_tools"))
    if reserved:
        # the built-in namespace is always reserved; config can only add to it
        p.scope.reserved_tools = list(dict.fromkeys(["agentguard*", *reserved]))

    alignment = data.get("alignment") or {}
    a = p.alignment
    a.auditor = str(alignment.get("auditor", a.auditor)).lower()
    a.endpoint = str(alignment.get("endpoint", a.endpoint))
    a.model = str(alignment.get("model", a.model))
    a.allow_remote = bool(alignment.get("allow_remote", a.allow_remote))
    a.history = int(alignment.get("history", a.history))
    a.timeout_seconds = float(alignment.get("timeout_seconds", a.timeout_seconds))

    financial = data.get("financial") or {}
    f = p.financial
    f.enabled = bool(financial.get("enabled", f.enabled))
    cap = financial.get("session_cap")
    if isinstance(cap, dict):
        f.session_cap = float(cap["amount"]) if cap.get("amount") is not None else None
        f.cap_currency = str(cap["currency"]).upper() if cap.get("currency") else None
    elif cap is not None:
        f.session_cap = float(cap)

    if data.get("hooks"):
        p.hooks = _hooks_from_dict(data["hooks"])

    if "hard_enforce" in data:
        rules = _as_list(data.get("hard_enforce"))
        unknown = [r for r in rules if r not in HARD_RULES]
        if unknown:
            raise ValueError(f"hard_enforce: unknown rule(s) {unknown}; "
                             f"choose from {list(HARD_RULES)}")
        p.hard_enforce = list(dict.fromkeys(rules))

    if "dev_workspaces" in data:
        p.dev_workspaces = _as_list(data.get("dev_workspaces"))
    return p


def find_policy_file(start: Path | None = None) -> Path | None:
    """Look for the policy file in the project dir, then walk up to the root."""
    cur = (start or Path.cwd()).resolve()
    for directory in [cur, *cur.parents]:
        candidate = directory / DEFAULT_POLICY_FILENAME
        if candidate.is_file():
            return candidate
    return None


def load(path: str | Path | None = None) -> Policy:
    """Load a policy file, or return safe defaults if none exists."""
    if path is None:
        found = find_policy_file()
        if found is None:
            return Policy()
        path = found
    p = Path(path)
    if not p.is_file():
        return Policy()
    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    policy = from_dict(data)
    policy.source_path = p
    return policy
