"""Claude Code hook integration - what AgentGuard sees of Claude Code's own tools.

The MCP gateway only sees MCP traffic. Claude Code's built-in tools (Bash,
PowerShell, Read, Write, Edit, WebFetch, WebSearch, ...) never go through MCP,
and for most people they are where the risk actually is. Claude Code's
`PreToolUse` / `PostToolUse` hooks deliver those calls here, and this module maps
them onto the same scanner, policy, taint, sink, propagation and DLP machinery the
gateway uses, so a decision means the same thing whichever surface saw the call.

  PreToolUse   map the call -> gather evidence -> Decision -> audit row
               (source=hook) -> response. The response depends on mode:
                 observe  always no decision: Claude Code's normal permission
                          flow applies, AgentGuard only records what it would do
                 enforce  BLOCK -> "deny", REVIEW -> "ask" (Claude Code's own
                          prompt is the review step), ALLOW -> no decision.
               AgentGuard never answers "allow": that would skip Claude Code's own
               permission prompts, which is not a gateway's decision to make.
  PostToolUse  untrusted results (WebFetch, WebSearch, untrusted MCP tools) are
               fingerprinted into the session's taint map; a result that matches
               a quarantined memory item has its taint re-attached; and a call
               that was sent to "ask" and then ran means a human approved it -
               the review item is cleared, which is what `report` counts as a
               false-positive candidate.

Sessions and the gateway
------------------------
Hook taint is keyed by Claude Code's `session_id`. The MCP gateway keys its own
taint by the MCP transport session, which Claude Code does not link to its
session id, so the two are bridged by correlation rather than identity: when a
hook sees a call to an MCP server that is routed through the gateway, it notes
(tool, argument hash) -> Claude session; when the gateway receives that same call
moments later, it looks the pair up and merges that session's taint into its own
check. See `CorrelationIndex` for the limits of that.

To avoid counting one call twice, a call to a gateway-routed MCP server is gated
and logged by the gateway alone; the hook only notes the correlation and, after
the call, records the result's taint into the Claude session.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from agentguard import audit, hardrules
from agentguard.audit import SOURCE_HOOK
from agentguard.classify import DataClassifier
from agentguard.decision import Decision, Signal, Verdict
from agentguard.financial import FinancialGuard
from agentguard.identity import AgentIdentity, RBACPolicy
from agentguard.locks import LockStore
from agentguard.policy import (
    TIER_EXFILTRATION,
    TIER_ORDINARY,
    TIER_PERSISTENCE,
    TIER_PROPAGATION,
    Policy,
)
from agentguard.propagation import PropagationDetector
from agentguard.quarantine import QuarantinedMemoryLedger
from agentguard.review_queue import KIND_MEMORY_PROMOTION, ReviewQueue
from agentguard.risk import W_UNKNOWN_DESTINATION, RiskEngine
from agentguard.scanner import (
    DEFAULT_PATH_DENYLIST,
    Finding,
    flatten,
    scan_arguments,
    scan_paths,
)
from agentguard.scope import ScopeStore
from agentguard.shellcmd import only_mentioned, only_temp_deletes
from agentguard.sinks import SinkClassifier
from agentguard.taint import UNTRUSTED, TaintMap, TaintRegistry
from agentguard.workspace import workspace_label

EVENT_PRE = "PreToolUse"
EVENT_POST = "PostToolUse"

#: Review-queue kind for a REVIEW that was sent to Claude Code's own prompt.
KIND_HOOK_ASK = "hook_ask"

SHELL_TOOLS = frozenset({"Bash", "PowerShell"})
#: File-writing tools and the input key that holds the written text.
WRITE_TOOLS: dict[str, tuple[str, ...]] = {
    "Write": ("content",),
    "Edit": ("new_string",),
    "MultiEdit": ("edits",),
    "NotebookEdit": ("new_source",),
}
READ_TOOLS = frozenset({"Read", "Glob", "Grep", "LS", "NotebookRead"})
#: Built-in tools whose input only goes to the user's own screen. Without this,
#: SendUserFile matched the `*send*` exfiltration glob.
USER_FACING_TOOLS = frozenset({"SendUserFile", "AskUserQuestion", "ExitPlanMode",
                               "EnterPlanMode", "TodoWrite", "TaskCreate", "TaskUpdate"})
LIST_TOOLS = frozenset({"Glob", "LS"})

_MCP_NAME = re.compile(r"^mcp__(?P<server>.+?)__(?P<tool>.+)$")
_URL_HOST = re.compile(r"(?i)\b(?:https?|ftp|sftp|wss?)://(?:[^@/\s'\"]+@)?(\[[^\]]+\]|[^/\s:'\"?#]+)")
# user@host:path (scp/rsync), not an email address inside a string
_SCP_HOST = re.compile(r"(?:^|\s)(?:[\w.-]+@)?([\w.-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3}):\S*",
                       re.IGNORECASE)
# netcat-style `nc host port`
_NC_HOST = re.compile(r"\b(?:nc|ncat|netcat|telnet)\s+(?:-\S+\s+)*([\w.-]+)\s+\d+", re.IGNORECASE)
_TOKEN = re.compile(r'"[^"]*"|\'[^\']*\'|[^\s|&;()<>]+')
# A regex escape (`\.env`, `\\.env\\.`, `a\|b`) marks a search pattern, not a
# path. A Windows path's `\.` follows a name character (`C:\proj\.env`).
_REGEX_TOKEN = re.compile(r"(?:^|[^A-Za-z0-9_:~])\\\.|\\\||\^\\|\\[sdwb]")


def _now() -> float:
    return time.monotonic()


def args_hash(tool: str, arguments: Any) -> str:
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{tool}\x00{canonical}".encode()).hexdigest()


def response_text(value: Any) -> str:
    """Every string in a tool result, joined - one text, fingerprinted as a whole.

    Joined rather than recorded leaf by leaf so that short structural strings in a
    result (a status word, a content type) don't become taint fingerprints of
    their own.
    """
    if isinstance(value, str):
        return value
    return "\n".join(text for _where, text in flatten(value) if text.strip())


#: Longest string kept per argument in the *audit summary*. The summary shows 300
#: characters in total, so redacting a whole 200-line file just to log its first
#: line doubled the cost of every large Write. Scanning always sees the full text.
LOG_CLIP = 1000


def _clip(value: Any, limit: int = LOG_CLIP) -> Any:
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + f"...(+{len(value) - limit} chars)"
    if isinstance(value, dict):
        return {k: _clip(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [_clip(v, limit) for v in value]
    return value


def claude_home() -> Path:
    """Where Claude Code keeps user settings: CLAUDE_CONFIG_DIR, else ~/.claude."""
    import os

    override = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(override) if override else Path.home() / ".claude"


def _posix_lower(path: str | Path) -> str:
    return str(path).replace("\\", "/").rstrip("/").lower()


# --- self-protection: shared by the hooks and the MCP gateway ---------------
# F5: it guards the LIVE setup only - the policy the daemon loaded (and the one
# recorded in agentguard.json), the live AGENTGUARD_HOME, the Claude Code user
# settings, and settings files that currently register AgentGuard's hooks. A
# second copy of agentguard.policy.yaml (the repository's) is ordinary work.
_SETTINGS_NAMES = ("settings.json", "settings.local.json")


def _live_policy_files(policy: Policy) -> list[Path]:
    files: list[Path] = []
    if policy.source_path:
        files.append(Path(policy.source_path))
    try:
        from agentguard import config as cfg

        if cfg.exists():
            recorded = cfg.load().policy_file
            if recorded:
                files.append(Path(recorded))
    except Exception:                                   # noqa: BLE001
        pass
    return files


def _protected_roots(policy: Policy) -> list[str]:
    from agentguard.config import agentguard_home

    roots = [_posix_lower(agentguard_home())]
    roots += [_posix_lower(claude_home() / name) for name in _SETTINGS_NAMES]
    for path in _live_policy_files(policy):
        roots.append(_posix_lower(path))
        try:
            roots.append(_posix_lower(path.resolve()))
        except OSError:
            pass
    return list(dict.fromkeys(roots))


def _command_forms(root: str) -> list[str]:
    """A protected absolute path, plus how a command might spell it via the home
    directory (~/..., $HOME/..., %USERPROFILE%/...)."""
    forms = [root]
    home = _posix_lower(Path.home())
    if root.startswith(home + "/"):
        rest = root[len(home):]
        forms += ["~" + rest, "$home" + rest, "${home}" + rest, "%userprofile%" + rest]
    return forms


def _registers_agentguard_hooks(path: str) -> bool:
    p = Path(path)
    if p.name.lower() not in _SETTINGS_NAMES or p.parent.name.lower() != ".claude":
        return False
    from agentguard.hookinstall import installed

    return bool(installed(p))


def protected_path(policy: Policy, path: str) -> bool:
    """Is `path` part of the live AgentGuard setup (see above)?"""
    norm = _posix_lower(path)
    for root in _protected_roots(policy):
        if norm == root or norm.startswith(root + "/"):
            return True
    if _registers_agentguard_hooks(path):
        return True
    return any(fnmatch(norm, g.lower()) for g in policy.hooks.self_protect_paths)


def disables_hooks(path: str, content: str) -> bool:
    """A Claude Code settings write that switches every hook off, wherever it is."""
    p = Path(str(path).replace("\\", "/"))
    return (p.name.lower() in _SETTINGS_NAMES and p.parent.name.lower() == ".claude"
            and "disableallhooks" in content.lower())


def protected_command(policy: Policy, command: str) -> bool:
    """Does a shell command touch the live setup, or stop/disable AgentGuard?"""
    if any(re.search(p, command, re.IGNORECASE) for p in policy.hooks.self_protect_commands):
        return True
    norm = command.replace("\\", "/").lower()
    for root in _protected_roots(policy):
        if any(form in norm for form in _command_forms(root)):
            return True
    markers = [g.lower().lstrip("*").lstrip("/") for g in policy.hooks.self_protect_paths]
    return any(marker and marker in norm for marker in markers)


_COMMAND_KEYS = ("command", "cmd", "script", "shell")


def mcp_touches_protected(policy: Policy, tiers: list[str], arguments: Any) -> bool:
    """Does an MCP call write to a protected file, or run a protected command?

    Writes are judged by tier (propagation/persistence: file writes, edits) and
    any path-like argument; commands by argument name, whatever the tool.
    """
    writes = TIER_PROPAGATION in tiers or TIER_PERSISTENCE in tiers
    leaves = flatten(arguments)
    content = "\n".join(v for _w, v in leaves)
    for where, value in leaves:
        key = where.rsplit(".", 1)[-1].split("[", 1)[0].lower()
        if key in _COMMAND_KEYS and protected_command(policy, value):
            return True
        if writes and ("/" in value or "\\" in value) and "\n" not in value \
                and len(value) < 1024 and (protected_path(policy, value)
                                           or disables_hooks(value, content)):
            return True
    return False


# --- correlation: the MCP gateway <-> Claude Code session bridge -----------
class CorrelationIndex:
    """Links a gateway MCP call to the Claude Code session that made it.

    The hook fires before Claude Code sends the MCP request, so the hook notes
    (tool, argument hash) -> Claude session, and the gateway looks the same pair
    up when the request arrives.

    Limits, stated rather than hidden: this is correlation, not identity. It needs
    hooks installed and the gateway running in the same daemon process; it only
    links calls within `window` seconds; and when two sessions make the identical
    call inside the window it refuses to guess and links neither.
    """

    def __init__(self, window: float = 30.0) -> None:
        self.window = window
        self._seen: dict[str, list[tuple[float, str]]] = {}
        self._lock = threading.Lock()

    def note(self, tool: str, arguments: Any, session_id: str, now: float | None = None) -> None:
        now = _now() if now is None else now
        key = args_hash(tool, arguments)
        with self._lock:
            entries = [e for e in self._seen.get(key, []) if now - e[0] <= self.window]
            entries.append((now, session_id))
            self._seen[key] = entries

    def lookup(self, tool: str, arguments: Any, now: float | None = None) -> str | None:
        now = _now() if now is None else now
        key = args_hash(tool, arguments)
        with self._lock:
            entries = [e for e in self._seen.get(key, []) if now - e[0] <= self.window]
            self._seen[key] = entries
        sessions = {sid for _ts, sid in entries}
        return sessions.pop() if len(sessions) == 1 else None


@dataclass
class HookBridge:
    """Attached to the gateway middleware as `hook_bridge` by the daemon."""

    correlation: CorrelationIndex
    taints: TaintRegistry

    def merge_into(self, tool: str, arguments: Any, taint: TaintMap) -> str | None:
        session = self.correlation.lookup(tool, arguments)
        if session is None:
            return None
        other = self.taints.get(session)
        if other is not None:
            taint.absorb(other, prefix="claude-code:")
        return session


# --- mapping Claude Code tools onto the existing model ----------------------
@dataclass
class MappedCall:
    tool: str                       # as Claude Code named it
    policy_tool: str                # name matched against policy globs
    arguments: dict[str, Any]       # what the scanners see (tool_input key names)
    tiers: list[str]
    signals: list[Signal] = field(default_factory=list)
    floors: list[tuple[Verdict, str]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    mcp_server: str | None = None
    via_gateway: bool = False
    self_protect: bool = False
    # Tools that only list names (Glob, LS): a credential *path* in their input
    # isn't a read of the credential, so `credential_files` doesn't apply.
    lists_only: bool = False
    # Shell calls: credential paths were judged token by token (read or only
    # named), so the whole-command path scan must not count them again.
    paths_by_token: bool = False


def _tokens(command: str) -> list[str]:
    out: list[str] = []
    for tok in _TOKEN.findall(command):
        tok = tok.strip("'\"")
        if "=" in tok and not tok.startswith(("/", "~", ".")):
            tok = tok.split("=", 1)[1]          # --file=path, VAR=path
        tok = tok.lstrip("@")                   # curl -d @file
        if tok:
            out.append(tok)
    return out


def _hosts(command: str) -> list[str]:
    hosts = [m.group(1).strip("[]").lower() for m in _URL_HOST.finditer(command)]
    hosts += [m.group(1).lower() for m in _SCP_HOST.finditer(command)]
    hosts += [m.group(1).lower() for m in _NC_HOST.finditer(command)]
    return list(dict.fromkeys(hosts))


def _host_allowed(host: str, allowed: list[str]) -> bool:
    return any(host == a.lower() or fnmatch(host, a.lower()) or host.endswith("." + a.lower())
               for a in allowed)


class HookEngine:
    """Evaluates Claude Code hook events. One instance per daemon."""

    def __init__(self, policy: Policy | None = None, *, db_path: str | None = None,
                 enforcement: bool | None = None,
                 identity: AgentIdentity | None = None,
                 correlation: CorrelationIndex | None = None) -> None:
        self.policy = policy or Policy()
        if enforcement is not None:
            self.policy.enforcement = enforcement
        self.db_path = db_path
        self.identity = identity or AgentIdentity.from_env()
        self.risk = RiskEngine(allow_below=self.policy.allow_below,
                               block_above=self.policy.block_above)
        self.rbac = RBACPolicy(self.policy)
        self.sinks = SinkClassifier(self.policy)
        self.ledger = QuarantinedMemoryLedger(db_path)
        self.queue = ReviewQueue(db_path)
        self.locks = LockStore(db_path)
        self.scopes = ScopeStore(db_path, self.policy)
        self.financial = FinancialGuard(self.policy, db_path)
        self.propagation = PropagationDetector(self.policy, self.ledger)
        self.classifier = DataClassifier(self.policy)
        self.taints = TaintRegistry()
        self.correlation = correlation or CorrelationIndex()
        self._denylist = list(self.policy.path_denylist) or list(DEFAULT_PATH_DENYLIST)
        from agentguard.versions import policy_version

        self.policy_version = policy_version(self.policy)
        self._asks: dict[str, int] = {}          # tool_use_id -> review item id
        self._lock = threading.Lock()
        # Recent decisions, in process, for tests and status. Bounded: the daemon
        # runs for days.
        self.events: deque[dict[str, Any]] = deque(maxlen=1000)

    # ------------------------------------------------------------------
    @property
    def enforcing(self) -> bool:
        return bool(self.policy.enforcement)

    def handle(self, payload: dict[str, Any]) -> dict[str, Any]:
        """One hook event in, one hook response out ({} = no decision)."""
        if not isinstance(payload, dict) or not self.policy.hooks.enabled:
            return {}
        event = payload.get("hook_event_name")
        with self._lock:
            if event == EVENT_PRE:
                return self._pre(payload)
            if event == EVENT_POST:
                return self._post(payload)
        return {}

    # ------------------------------------------------------------------
    # mapping
    # ------------------------------------------------------------------
    def map_call(self, tool: str, tool_input: dict[str, Any],
                 payload: dict[str, Any] | None = None) -> MappedCall:
        payload = payload or {}
        hooks = self.policy.hooks

        m = _MCP_NAME.match(tool)
        if m:
            server = (payload.get("mcp_server") or {}).get("name") or m.group("server")
            inner = m.group("tool")
            via = server in hooks.gateway_servers or m.group("server") in hooks.gateway_servers
            tiers = self.policy.sink_tiers(inner)
            # Self-protection for MCP tools came with hard enforcement, so it runs
            # only when that rule is listed: an empty list behaves as before.
            return MappedCall(tool, inner, dict(tool_input), tiers,
                              mcp_server=server, via_gateway=via,
                              self_protect=hooks.self_protection
                              and "self_protection" in self.policy.hard_enforce
                              and mcp_touches_protected(self.policy, tiers, tool_input))

        if tool in SHELL_TOOLS:
            return self._map_shell(tool, str(tool_input.get("command", "")))

        if tool in USER_FACING_TOOLS:
            # Shown to the user, not sent anywhere: never a sink, and naming a
            # credential path in a question isn't reading it.
            return MappedCall(tool, tool, dict(tool_input), [TIER_ORDINARY], lists_only=True)

        if tool in WRITE_TOOLS:
            args: dict[str, Any] = {}
            for key in ("file_path", "notebook_path", *WRITE_TOOLS[tool]):
                if key in tool_input:
                    args[key] = tool_input[key]
            call = MappedCall(tool, tool, args, [TIER_ORDINARY, TIER_PROPAGATION])
            path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
            written = "\n".join(v for _w, v in flatten({k: args[k] for k in args
                                                         if k in WRITE_TOOLS[tool]}))
            if path and (self._protected_path(path)
                         or (hooks.self_protection and disables_hooks(path, written))):
                call.self_protect = True
            return call

        if tool == "WebFetch":
            # The URL itself can carry data out (query strings), so untrusted
            # content appearing in it is an exfiltration-tier flow. The `prompt`
            # field is processed locally and is not sent to the site.
            return MappedCall(tool, tool, {"url": tool_input.get("url", "")},
                              [TIER_ORDINARY, TIER_EXFILTRATION])

        if tool in READ_TOOLS or tool == "WebSearch":
            return MappedCall(tool, tool, dict(tool_input), [TIER_ORDINARY],
                              lists_only=tool in LIST_TOOLS)

        # Anything else (Agent, AskUserQuestion, new tools): scan the input, and
        # let the policy's sink globs place it, so custom names stay configurable.
        return MappedCall(tool, tool, dict(tool_input), self.policy.sink_tiers(tool))

    def _map_shell(self, tool: str, command: str) -> MappedCall:
        hooks = self.policy.hooks
        call = MappedCall(tool, tool, {"command": command}, [TIER_ORDINARY])
        call.paths_by_token = True

        # Credential paths anywhere in the command line, token by token - the
        # whole command never "looks like a path", so the argument-level path
        # scan alone would miss `cat ~/.ssh/id_rsa`. A path that is only named
        # (`test -f .env`, `docker compose --env-file .env build`) doesn't put the
        # file's contents in front of the agent: logged, not counted as a read.
        mentioned: list[str] = []
        for tok in _tokens(command):
            if _REGEX_TOKEN.search(tok):
                continue                    # grep "\.env": a pattern, not a path
            found = scan_paths(tok, "command", self._denylist)
            if found and only_mentioned(command, tok):
                mentioned.append(tok)
                continue
            call.findings.extend(found)
        if mentioned:
            call.signals.append(Signal(
                "credpath:referenced", 0.0,
                f"credential path named but not read: {', '.join(mentioned[:3])}",
            ))

        def matches(kind: str) -> list[str]:
            return [p for p in hooks.bash.get(kind, [])
                    if re.search(p, command, re.IGNORECASE)]

        if matches("exfiltration"):
            allowed = [*hooks.allow_hosts, *self.policy.egress_allowlist]
            hosts = _hosts(command)
            unlisted = [h for h in hosts if not _host_allowed(h, allowed)]
            if unlisted or not hosts:
                call.tiers.append(TIER_EXFILTRATION)
            if unlisted:
                call.signals.append(Signal(
                    "hook:egress_unlisted_host", W_UNKNOWN_DESTINATION,
                    f"network command to host(s) not in the egress allowlist: "
                    f"{', '.join(unlisted[:5])}",
                ))
        if matches("propagation"):
            call.tiers.append(TIER_PROPAGATION)
        destructive = matches("destructive")
        starts = [m.start() for p in destructive for m in re.finditer(p, command, re.IGNORECASE)]
        if destructive and hooks.temp_deletes_ok and only_temp_deletes(command, starts):
            call.signals.append(Signal(
                "hook:delete_in_temp", 0.0,
                "recursive delete; every target is inside a temp directory",
            ))
        elif destructive:
            call.signals.append(Signal(
                "hook:destructive_command", 0.0,
                f"recursive delete or disk-level command (pattern {destructive[0]!r})",
            ))
            call.floors.append((Verdict.REVIEW, "destructive command"))
        if self._protected_command(command):
            call.self_protect = True
        return call

    # --- self-protection (A6) --------------------------------------------
    def _protected_path(self, path: str) -> bool:
        return self.policy.hooks.self_protection and protected_path(self.policy, path)

    def _protected_command(self, command: str) -> bool:
        return self.policy.hooks.self_protection and protected_command(self.policy, command)

    # ------------------------------------------------------------------
    # PreToolUse
    # ------------------------------------------------------------------
    def _pre(self, payload: dict[str, Any]) -> dict[str, Any]:
        session = str(payload.get("session_id") or "unknown-session")
        tool = str(payload.get("tool_name") or "")
        tool_input = payload.get("tool_input") or {}
        if not isinstance(tool_input, dict):
            tool_input = {"value": tool_input}
        call = self.map_call(tool, tool_input, payload)

        if call.via_gateway:
            # The gateway gates and logs this call; recording it here too would
            # count it twice. Note it so the gateway can find this session's taint.
            self.correlation.note(call.policy_tool, tool_input, session)
            self.events.append({"event": EVENT_PRE, "tool": tool, "deduped": True})
            return {}

        taint = self.taints.for_session(session)
        extra: list[Signal] = list(call.signals)
        floors: list[tuple[Verdict, str]] = list(call.floors)
        override: str | None = None

        # --- absolute rules first: locks, explicit deny, RBAC ----------------
        lock = self.locks.active_for(session)
        if lock is not None:
            name = "lock:global" if lock.is_global else "lock:session"
            extra.append(Signal(name, 1.0, f"locked by {lock.locked_by}: {lock.reason}"))
            floors.append((Verdict.BLOCK, f"locked: {lock.reason}"))
            override = "lock"
        if self.policy.check_tool(call.policy_tool) is Verdict.BLOCK:
            extra.append(Signal("policy:deny", 1.0, f"policy denies tool '{call.policy_tool}'"))
            floors.append((Verdict.BLOCK, "policy deny"))
            override = override or "policy_deny"
        # Role allow-lists are written in MCP tool names ("filesystem.*"), so they
        # apply to MCP calls only; applied to built-ins, a `coder` role's allow
        # list would block every Bash and Read call.
        rbac_verdict, rbac_why = (self.rbac.check(self.identity, call.policy_tool)
                                  if call.mcp_server is not None else (None, ""))
        if rbac_verdict is Verdict.BLOCK:
            extra.append(Signal("rbac:deny", 1.0, rbac_why))
            floors.append((Verdict.BLOCK, rbac_why))
            override = override or "rbac_deny"

        # --- evidence ------------------------------------------------------
        scan = scan_arguments(call.arguments, self._denylist)
        if call.paths_by_token or call.tool in USER_FACING_TOOLS:
            # user-facing tools: a path in a question to the user isn't a file access
            scan.findings = [f for f in scan.findings if not (
                f.kind == "path" and (f.where == "command" or call.tool in USER_FACING_TOOLS))]
        known = {(f.kind, f.label, f.where) for f in scan.findings}
        for f in call.findings:
            if (f.kind, f.label, f.where) not in known:
                scan.findings.append(f)
                known.add((f.kind, f.label, f.where))

        primary = next((t for t in (TIER_PERSISTENCE, TIER_EXFILTRATION) if t in call.tiers),
                       TIER_ORDINARY)
        assessment = self.sinks.assess_tier(primary, call.arguments, taint)
        extra.extend(assessment.signals)
        if assessment.verdict_floor is not Verdict.ALLOW:
            floors.append((assessment.verdict_floor, f"sink tier: {primary}"))

        prop = self.propagation.assess(tool, call.arguments, taint, call.tiers,
                                       assessment.overlap, scan)
        extra.extend(prop.signals)
        floors.append((prop.verdict_floor, "propagation: replication"))

        dlp = self.classifier.assess(tool, call.arguments, call.tiers,
                                     self.identity.role, scan, enforcing=self.enforcing)
        extra.extend(dlp.signals)
        floors.append((dlp.verdict_floor, f"dlp: {dlp.label} over limit"))

        scope = self.scopes.effective(session, self.identity.role)
        if scope is not None and not (scope.allows(tool) or scope.allows(call.policy_tool)):
            extra.append(Signal("scope:outside", 0.0,
                                f"'{tool}' is outside the declared task scope "
                                f"[{', '.join(scope.tools)}] ({scope.source})"))
            floors.append((Verdict.REVIEW, "scope: outside"))

        fin = self.financial.assess(call.policy_tool, call.arguments, call.tiers, session)
        extra.extend(fin.signals)
        floors.append((fin.verdict_floor, "financial"))

        if call.self_protect:
            extra.append(Signal(
                "selfprotect:tamper", 0.0,
                f"'{tool}' touches AgentGuard's own configuration, audit data, the "
                f"Claude Code settings that register its hooks, or its daemon",
            ))
            floors.append((Verdict.REVIEW, "self-protection"))

        decision = self.risk.evaluate(scan, extra)
        for floor, label in floors:
            if floor is not Verdict.ALLOW:
                decision.verdict = decision.verdict.escalate(floor)
                decision.reason = f"{decision.reason} | {label}"
        decision.override = override

        # Hard-enforced rules (policy `hard_enforce`): blocked in every mode.
        hard = hardrules.match(self.policy, decision.signal_names, call.tiers,
                               lists_only=call.lists_only)
        if hard:
            for rule in hard:
                decision.signals.append(Signal(
                    f"{hardrules.SIGNAL_PREFIX}{rule}", 0.0,
                    f"hard-enforced rule '{rule}': blocked even in observe mode"))
            decision.verdict = Verdict.BLOCK
            decision.override = "hard_enforce"
            decision.reason = f"{decision.reason} | hard-enforced: {', '.join(hard)}"

        # A tainted write to durable memory (an MCP memory tool not behind the
        # gateway): hold a copy in the quarantine ledger, as the gateway does.
        detail_extra = ""
        if assessment.quarantine and decision.verdict is not Verdict.BLOCK:
            content = "\n".join(text for _w, text in flatten(call.arguments))
            item = self.ledger.quarantine(
                content=content, tool=tool, session_id=session,
                source_tools=assessment.overlap.sources,
                fingerprints=taint.fingerprints_for(content),
                ttl_hours=self.policy.ttl_hours("default"),
                extra_provenance={"arguments": tool_input, "via": "claude-code-hook"},
            )
            self.queue.enqueue(kind=KIND_MEMORY_PROMOTION, tool=tool,
                               payload={"quarantine_id": item, "content": content[:2000],
                                        "source_tools": assessment.overlap.sources},
                               score=decision.score,
                               reason="memory write derived from untrusted content",
                               session_id=session, agent=self._agent(payload))
            decision.verdict = decision.verdict.escalate(Verdict.REVIEW)
            decision.override = decision.override or "quarantined"
            detail_extra = f"; quarantined as memory item #{item}"

        return self._respond(payload, call, decision, dlp, detail_extra)

    def _agent(self, payload: dict[str, Any]) -> str:
        agent_type = payload.get("agent_type")
        return f"claude-code/{agent_type}" if payload.get("agent_id") and agent_type \
            else "claude-code"

    def _respond(self, payload: dict[str, Any], call: MappedCall, decision: Decision,
                 dlp: Any, detail_extra: str) -> dict[str, Any]:
        session = str(payload.get("session_id") or "unknown-session")
        tool_use_id = payload.get("tool_use_id")
        tool_input = payload.get("tool_input") or {}
        sp = call.self_protect
        hard = decision.override == "hard_enforce"

        response: dict[str, Any] = {}
        outcome = "no decision"
        if hard:
            outcome = "deny"                       # every mode, by definition
        elif self.enforcing:
            if decision.verdict is Verdict.BLOCK or (decision.verdict is Verdict.REVIEW and sp):
                outcome = "deny"
            elif decision.verdict is Verdict.REVIEW or dlp.redacted_arguments is not None:
                outcome = "ask"
        would = ("deny" if decision.verdict is Verdict.BLOCK or
                 (decision.verdict is Verdict.REVIEW and sp) else
                 "ask" if decision.verdict is Verdict.REVIEW else "no decision")

        review_id = None
        if outcome == "ask":
            from agentguard.audit import digest_args
            from agentguard.scanner import redact_arguments

            review_id = self.queue.enqueue(
                kind=KIND_HOOK_ASK, tool=call.tool,
                payload={"tool_use_id": tool_use_id,
                         "workspace": workspace_label(payload.get("cwd")),
                         "args_digest": digest_args(_clip(tool_input)),
                         "arguments": redact_arguments(_clip(tool_input)),
                         "signals": [s.to_dict() for s in decision.signals]},
                score=decision.score, reason=decision.reason,
                session_id=session, agent=self._agent(payload),
            )
            if tool_use_id:
                self._asks[str(tool_use_id)] = review_id

        reason = (f"AgentGuard: {decision.reason} (score {decision.score:.2f})"
                  + (f" - review #{review_id}" if review_id else ""))
        if hard:
            reason = (f"AgentGuard hard-enforced rule - blocked even in observe mode: "
                      f"{decision.reason} (score {decision.score:.2f})")
        if outcome in ("deny", "ask"):
            out: dict[str, Any] = {"hookEventName": EVENT_PRE,
                                   "permissionDecision": outcome,
                                   "permissionDecisionReason": reason}
            if outcome == "ask" and dlp.redacted_arguments is not None:
                out["updatedInput"] = {**tool_input, **dlp.redacted_arguments}
            response = {"hookSpecificOutput": out}

        mode = "enforce" if self.enforcing else "observe"
        detail = (f"claude-code {mode}: {outcome}"
                  + (" (hard-enforced)" if hard else
                     "" if self.enforcing else f" (would {would})")
                  + (f"; tool_use_id {tool_use_id}" if tool_use_id else "")
                  + (f"; subagent {payload.get('agent_type')}" if payload.get("agent_id") else "")
                  + detail_extra)
        audit.record(stage="TOOL_PREPARE", decision=decision, tool=call.tool,
                     arguments=_clip(tool_input), session_id=session,
                     agent=self._agent(payload), role=self.identity.role,
                     detail=detail, db_path=self.db_path, source=SOURCE_HOOK,
                     policy_version=self.policy_version, mode=mode,
                     workspace=workspace_label(payload.get("cwd")))
        self.events.append({"event": EVENT_PRE, "tool": call.tool,
                            "verdict": decision.verdict.value, "outcome": outcome,
                            "would": would, "signals": decision.signal_names,
                            "review_id": review_id})
        return response

    # ------------------------------------------------------------------
    # PostToolUse
    # ------------------------------------------------------------------
    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        session = str(payload.get("session_id") or "unknown-session")
        tool = str(payload.get("tool_name") or "")
        tool_use_id = payload.get("tool_use_id")
        tool_input = payload.get("tool_input") or {}
        if not isinstance(tool_input, dict):
            tool_input = {"value": tool_input}
        call = self.map_call(tool, tool_input, payload)
        taint = self.taints.for_session(session)

        # A call we sent to "ask" ran, so a human approved it at Claude Code's
        # prompt: that is a human overruling the gateway - a false-positive
        # candidate for `report`.
        review_id = self._asks.pop(str(tool_use_id), None) if tool_use_id else None
        if review_id is None and tool_use_id:
            review_id = self._find_ask(str(tool_use_id))
        if review_id is not None:
            self.queue.approve(review_id, by="claude-code-prompt")
            self._log_result(payload, call, "hook:ask_approved",
                             f"approved at Claude Code's permission prompt (review #{review_id})")

        text = response_text(payload.get("tool_response"))
        if not text.strip():
            return {}

        # Taint survives the memory boundary here too.
        if self.ledger.list(status=None, include_expired=True):
            recalled = self.ledger.recall_taint(text)
            if recalled is not None:
                taint.record(f"quarantine:{recalled.id}", text, label=UNTRUSTED)
                if not call.via_gateway:
                    self._log_result(payload, call, "taint:recall_reattached",
                                     f"result matches quarantined memory #{recalled.id}")
                return {}

        if self._untrusted(call):
            rec = taint.record(tool, text, label=UNTRUSTED)
            # A gateway-routed call's result is already a gateway taint event.
            if not call.via_gateway:
                self._log_result(payload, call, "taint:recorded",
                                 f"{len(rec.fingerprints)} fingerprints from untrusted "
                                 f"source '{tool}'")
        return {}

    def _untrusted(self, call: MappedCall) -> bool:
        if call.mcp_server is not None:
            return self.policy.is_untrusted_source(call.policy_tool)
        return any(fnmatch(call.tool, p) for p in self.policy.hooks.untrusted_tools)

    def _find_ask(self, tool_use_id: str) -> int | None:
        """Look a pending ask up in the queue - survives a daemon restart."""
        for item in self.queue.list("pending"):
            if item.kind == KIND_HOOK_ASK and item.payload.get("tool_use_id") == tool_use_id:
                return item.id
        return None

    def _log_result(self, payload: dict[str, Any], call: MappedCall, signal: str,
                    detail: str) -> None:
        audit.record(
            stage="TOOL_RESULT",
            decision=Decision(Verdict.ALLOW, 0.0, [Signal(signal, 0.0, detail)], reason=detail),
            tool=call.tool, session_id=str(payload.get("session_id") or "unknown-session"),
            agent=self._agent(payload), role=self.identity.role, detail=detail,
            db_path=self.db_path, source=SOURCE_HOOK,
            policy_version=self.policy_version,
            mode="enforce" if self.enforcing else "observe",
            workspace=workspace_label(payload.get("cwd")),
        )
