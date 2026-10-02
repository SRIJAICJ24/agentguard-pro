"""The AgentGuard middleware - every control, in order, on the request path.

This is the whole gateway in one class. FastMCP's `on_call_tool` hook straddles
the call, which maps cleanly onto the design's lifecycle:

  TOOL_PREPARE   before call_next   - policy, RBAC, pinning, scanner, sinks, velocity
  TOOL_EXECUTE   call_next          - forwarded upstream only if permitted
  TOOL_RESULT    after call_next    - taint classification, quarantine recall hook

Ordering is deliberate. Cheap, absolute checks (kill switch, explicit policy deny,
RBAC) run before anything expensive, and before any score is computed - a rule is
not evidence to be weighed against other evidence. Scoring runs next, then taint
and sink analysis, which can only raise the verdict, never lower it.

Enforcement
-----------
With `enforcement: false` (the default) every control still runs and every decision
is still logged, but nothing is actually stopped. This is how the false-positive
rate gets measured on real traffic before the gateway is allowed to interrupt work.
"""

from __future__ import annotations

import asyncio
import json
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext

from agentguard import audit, hardrules
from agentguard.alignment import AlignmentAuditor, build_auditor
from agentguard.behavior import BehaviorMonitor
from agentguard.classify import DataClassifier
from agentguard.decision import Decision, Signal, Verdict
from agentguard.financial import RECEIPT_STAGE, FinancialGuard
from agentguard.identity import AgentIdentity, RBACPolicy
from agentguard.locks import LockStore
from agentguard.pinning import ToolPinStore
from agentguard.propagation import PropagationDetector
from agentguard.policy import (
    TIER_EXFILTRATION,
    TIER_ORDINARY,
    TIER_PERSISTENCE,
    Policy,
)
from agentguard.quarantine import QuarantinedMemoryLedger
from agentguard.review_queue import KIND_TOOL_CALL, ReviewQueue
from agentguard.risk import W_PIN_MISMATCH, RiskEngine
from agentguard.scanner import DEFAULT_PATH_DENYLIST, scan_arguments
from agentguard.scope import ScopeStore, TaskScope
from agentguard.hooks import mcp_touches_protected
from agentguard.sinks import SinkClassifier
from agentguard.taint import TRUSTED, UNTRUSTED, TaintRegistry


def _result_text(result: Any) -> str:
    """Best-effort extraction of text from a ToolResult for taint purposes."""
    parts: list[str] = []
    content = getattr(result, "content", None)
    if content:
        for block in content:
            text = getattr(block, "text", None)
            if text:
                parts.append(str(text))
    if not parts:
        data = getattr(result, "data", None)
        if data is not None:
            parts.append(data if isinstance(data, str) else json.dumps(data, default=str))
    return "\n".join(parts)


@dataclass
class GuardStats:
    """Lightweight in-process counters, mostly for tests and `status`."""

    calls: int = 0
    allowed: int = 0
    blocked: int = 0
    review: int = 0
    quarantined: int = 0
    taint_records: int = 0
    observed_only: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)


class AgentGuardMiddleware(Middleware):
    """Intercepts every tool call and tool result flowing through the proxy."""

    def __init__(
        self,
        policy: Policy | None = None,
        *,
        identity: AgentIdentity | None = None,
        db_path: str | None = None,
        enforcement: bool | None = None,
    ) -> None:
        self.policy = policy or Policy()
        if enforcement is not None:
            self.policy.enforcement = enforcement
        self.identity = identity or AgentIdentity.from_env()
        self.db_path = db_path

        self.risk = RiskEngine(allow_below=self.policy.allow_below,
                               block_above=self.policy.block_above)
        self.rbac = RBACPolicy(self.policy)
        self.pins = ToolPinStore(db_path)
        self.queue = ReviewQueue(db_path)
        self.ledger = QuarantinedMemoryLedger(db_path)
        self.sinks = SinkClassifier(self.policy)
        self.propagation = PropagationDetector(self.policy, self.ledger)
        self.classifier = DataClassifier(self.policy)
        from agentguard.versions import policy_version

        # Recorded on every audit row, so a mid-week policy edit is visible.
        self.policy_version = policy_version(self.policy)
        self.scopes = ScopeStore(db_path, self.policy)
        self.financial = FinancialGuard(self.policy, db_path)
        self.locks = LockStore(db_path)
        self.auditor: AlignmentAuditor = build_auditor(self.policy.alignment)
        # Last N calls per session, kept only when an auditor is enabled.
        self._recent: dict[str, deque[dict[str, Any]]] = {}
        self.taints = TaintRegistry()
        self.behavior = BehaviorMonitor()
        self.stats = GuardStats()

        self._denylist = list(self.policy.path_denylist) or list(DEFAULT_PATH_DENYLIST)
        # Tools whose description changed and have not been re-approved.
        self._pin_alerts: dict[str, str] = {}

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _session_id(self, context: MiddlewareContext[Any]) -> str:
        fc = getattr(context, "fastmcp_context", None)
        sid = getattr(fc, "session_id", None) if fc else None
        return str(sid) if sid else self.identity.session_id

    def _log(self, stage: str, decision: Decision, tool: str | None = None,
             arguments: Any = None, session_id: str | None = None,
             detail: str | None = None) -> int:
        row_id = audit.record(
            stage=stage, decision=decision, tool=tool, arguments=arguments,
            session_id=session_id or self.identity.session_id,
            agent=self.identity.name, role=self.identity.role,
            detail=detail, db_path=self.db_path,
            policy_version=self.policy_version,
            mode="enforce" if self._enforced() else "observe",
        )
        self.stats.events.append({
            "id": row_id, "stage": stage, "tool": tool,
            "verdict": decision.verdict.value, "score": round(decision.score, 3),
            "reason": decision.reason, "detail": detail,
            "signals": decision.signal_names, "override": decision.override,
        })
        return row_id

    def _enforced(self) -> bool:
        return bool(self.policy.enforcement)

    # ------------------------------------------------------------------
    # on_list_tools - tool pinning (rug-pull detection)
    # ------------------------------------------------------------------
    async def on_list_tools(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        tools = await call_next(context)
        session_id = self._session_id(context)
        for tool in tools:
            schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", None)
            check = self.pins.check(tool.name, tool.description, schema)
            if check.mismatch:
                self._pin_alerts[tool.name] = check.diff or "description changed"
                self._log(
                    "TOOL_PIN", Decision(
                        Verdict.REVIEW, W_PIN_MISMATCH,
                        [Signal("pin:mismatch", W_PIN_MISMATCH,
                                f"description/schema of '{tool.name}' changed since it "
                                f"was pinned at {check.pinned_at}")],
                        reason="tool definition changed after approval (possible rug pull)",
                        override="pin_mismatch",
                    ),
                    tool=tool.name, session_id=session_id, detail=check.diff,
                )
        return tools

    # ------------------------------------------------------------------
    # on_call_tool - the full pipeline
    # ------------------------------------------------------------------
    async def on_call_tool(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        tool = context.message.name
        arguments = context.message.arguments or {}
        session_id = self._session_id(context)
        taint = self.taints.for_session(session_id)

        # Claude Code hook bridge (set by the daemon): if a hook saw this exact
        # call a moment ago, fold that Claude Code session's taint into ours, so
        # a WebFetch result can't be laundered through an MCP egress tool.
        bridge = getattr(self, "hook_bridge", None)
        if bridge is not None:
            bridge.merge_into(tool, arguments, taint)

        self.stats.calls += 1

        # --- 1. kill switch / locks: absolute, checked first --------------
        # A lock is a human command, not a detector, so it stops the call even in
        # observe mode. The in-process kill switch and the CLI-set locks in the
        # database (`agentguard lock`) are the same rule from two places.
        locked = self.behavior.is_locked(session_id)
        db_lock = None if locked else self.locks.active_for(session_id)
        if locked or db_lock:
            if locked:
                signal = Signal("session:locked", 1.0, locked)
                reason, override = f"session locked: {locked}", "kill_switch"
            else:
                name = "lock:global" if db_lock.is_global else "lock:session"
                signal = Signal(name, 1.0,
                                f"{'all sessions' if db_lock.is_global else 'session'} "
                                f"locked by {db_lock.locked_by} at {db_lock.locked_at}: "
                                f"{db_lock.reason}")
                reason, override = f"locked: {db_lock.reason}", "lock"
            decision = Decision(Verdict.BLOCK, 1.0, [signal], reason=reason,
                                override=override)
            self._block(decision, tool, arguments, session_id, absolute=True)

        # --- 2. explicit policy deny (rule, not evidence) -----------------
        if self.policy.check_tool(tool) is Verdict.BLOCK:
            decision = Decision(
                Verdict.BLOCK, 1.0,
                [Signal("policy:deny", 1.0, f"policy denies tool '{tool}'")],
                reason=f"policy explicitly denies '{tool}'", override="policy_deny",
            )
            self._block(decision, tool, arguments, session_id)
            return await self._passthrough(context, tool, session_id, taint, call_next)

        # --- 3. RBAC ------------------------------------------------------
        rbac_verdict, rbac_why = self.rbac.check(self.identity, tool)
        if rbac_verdict is Verdict.BLOCK:
            decision = Decision(
                Verdict.BLOCK, 1.0,
                [Signal("rbac:deny", 1.0, rbac_why)],
                reason=rbac_why, override="rbac_deny",
            )
            self._block(decision, tool, arguments, session_id)
            return await self._passthrough(context, tool, session_id, taint, call_next)

        # --- 3b. AgentGuard's own control plane is never a tool -----------
        # The task scope (and every other gateway setting) is changed from the
        # CLI only. A call into the reserved namespace is someone trying to reach
        # the controls through the channel the controls are guarding.
        if self.scopes.is_reserved(tool):
            decision = Decision(
                Verdict.BLOCK, 1.0,
                [Signal("scope:tamper_attempt", 1.0,
                        f"'{tool}' is in AgentGuard's reserved control-plane namespace; "
                        f"scope and policy can only be changed from the CLI")],
                reason=f"control-plane call '{tool}' rejected", override="scope_tamper",
            )
            self._block(decision, tool, arguments, session_id)
            return await self._passthrough(context, tool, session_id, taint, call_next)

        # --- 4. gather evidence -------------------------------------------
        scan = scan_arguments(arguments, self._denylist)
        extra: list[Signal] = []

        # 4a. pinning: a changed tool forces REVIEW regardless of score
        pin_diff = self._pin_alerts.get(tool)
        if pin_diff:
            extra.append(Signal(
                "pin:mismatch", W_PIN_MISMATCH,
                f"tool '{tool}' description changed since approval",
            ))

        # 4b. velocity
        bh = self.behavior.observe(self.identity.name, tool)
        extra.extend(bh.signals)

        # 4c. taint + sink tier
        assessment = self.sinks.assess(tool, arguments, taint)
        assessment.tiers = self.policy.sink_tiers(tool)
        extra.extend(assessment.signals)

        # Stage 7 detectors. Each contributes signals plus an optional verdict
        # floor, labelled so the audit reason says which detector raised it.
        floors: list[tuple[Verdict, str]] = []

        # 4d. propagation (self-replicating injection)
        prop = self.propagation.assess(tool, arguments, taint,
                                       assessment.tiers, assessment.overlap, scan)
        extra.extend(prop.signals)
        floors.append((prop.verdict_floor, "propagation: replication"))

        # 4e. volume-aware DLP / data classification
        dlp = self.classifier.assess(tool, arguments, assessment.tiers,
                                     self.identity.role, scan,
                                     enforcing=self._enforced())
        extra.extend(dlp.signals)
        floors.append((dlp.verdict_floor, f"dlp: {dlp.label} over limit"))

        # 4f. declared task scope
        scope = self.scopes.effective(session_id, self.identity.role)
        if scope is not None and not scope.allows(tool):
            extra.append(Signal(
                "scope:outside", 0.0,
                f"'{tool}' is outside the declared task scope "
                f"[{', '.join(scope.tools)}] ({scope.source})",
            ))
            floors.append((Verdict.REVIEW, "scope: outside"))

        # 4h. financial tier: always a human decision
        fin = self.financial.assess(tool, arguments, assessment.tiers, session_id)
        extra.extend(fin.signals)
        floors.append((fin.verdict_floor, "financial"))

        # 4i. self-protection for MCP calls: writes to AgentGuard's own config,
        # policy, audit data or hook settings. It arrived with hard enforcement and
        # runs only when `self_protection` is listed, so an empty list behaves as
        # before.
        if "self_protection" in self.policy.hard_enforce and \
                mcp_touches_protected(self.policy, assessment.tiers, arguments):
            extra.append(Signal(
                "selfprotect:tamper", 0.0,
                f"'{tool}' writes to AgentGuard's own configuration, audit data or the "
                f"Claude Code settings that register its hooks",
            ))
            floors.append((Verdict.REVIEW, "self-protection"))

        decision = self.risk.evaluate(scan, extra)

        # Floors raise the verdict; they never lower it.
        if assessment.verdict_floor is not Verdict.ALLOW:
            decision.verdict = decision.verdict.escalate(assessment.verdict_floor)
            decision.reason = f"{decision.reason} | sink tier: {assessment.tier}"
        for floor, label in floors:
            if floor is not Verdict.ALLOW:
                decision.verdict = decision.verdict.escalate(floor)
                decision.reason = f"{decision.reason} | {label}"

        # 4g. deep path: optional model-based alignment audit
        if self.auditor.enabled:
            await self._alignment_check(decision, tool, arguments, session_id,
                                        scope, assessment.tiers)
        if pin_diff:
            decision.verdict = decision.verdict.escalate(Verdict.REVIEW)
            decision.override = "pin_mismatch"

        # --- 4j. hard-enforced rules: refused in every mode ---------------
        hard = hardrules.match(self.policy, decision.signal_names, assessment.tiers)
        if hard:
            for rule in hard:
                decision.signals.append(Signal(
                    f"{hardrules.SIGNAL_PREFIX}{rule}", 0.0,
                    f"hard-enforced rule '{rule}': blocked even in observe mode"))
            decision.verdict = Verdict.BLOCK
            decision.override = "hard_enforce"
            decision.reason = f"{decision.reason} | hard-enforced: {', '.join(hard)}"
            self._block(decision, tool, arguments, session_id, absolute=True,
                        detail=f"hard-enforced: {', '.join(hard)}")

        # --- 5. persistence tier: route to the quarantine ledger ----------
        # Checked before BLOCK/REVIEW handling because quarantining is the correct
        # outcome here - the write is redirected, not refused.
        if assessment.tier == TIER_PERSISTENCE and assessment.quarantine \
                and decision.verdict is not Verdict.BLOCK:
            self._quarantine_write(
                decision, tool, arguments, session_id, assessment, taint
            )
            return await self._passthrough(context, tool, session_id, taint, call_next)

        # --- 6. terminal verdicts -----------------------------------------
        if decision.verdict is Verdict.BLOCK:
            self._block(decision, tool, arguments, session_id)
            return await self._passthrough(context, tool, session_id, taint, call_next)

        receipt: dict[str, Any] | None = None
        if decision.verdict is Verdict.REVIEW:
            approval = self.queue.find_approval(tool, arguments, session_id)
            if approval is not None:
                self.queue.consume(approval.id)
                if fin.transaction is not None:
                    receipt = self.financial.receipt(
                        tool=tool, arguments=arguments, txn=fin.transaction,
                        agent=self.identity.name, role=self.identity.role,
                        session_id=session_id, approval_id=approval.id,
                        approver=approval.resolved_by,
                    )
                decision.reason = f"proceeding on human approval #{approval.id}"
                self._log("TOOL_PREPARE", Decision(
                    Verdict.ALLOW, decision.score, decision.signals,
                    reason=decision.reason, override="human_approved",
                ), tool=tool, arguments=arguments, session_id=session_id)
            else:
                self._hold_for_review(decision, tool, arguments, session_id, assessment)
        else:
            self._log("TOOL_PREPARE", decision, tool=tool,
                      arguments=arguments, session_id=session_id)

        self.stats.allowed += 1

        # An untainted persistence write is genuine trusted memory. Recording it
        # here is what makes the trusted/quarantined split visible side by side in
        # the dashboard, instead of quarantine looking like the only outcome.
        if assessment.tier == TIER_PERSISTENCE and not assessment.quarantine:
            from agentguard.scanner import flatten
            content = "\n".join(text for _w, text in flatten(arguments))
            self.ledger.save_trusted(content, session_id, origin=f"direct:{tool}")

        # --- 7. TOOL_EXECUTE ----------------------------------------------
        if dlp.redacted_arguments is not None:
            # Only the redacted form ever reaches the upstream server.
            context = context.copy(message=context.message.model_copy(
                update={"arguments": dlp.redacted_arguments}))
        result = await call_next(context)

        # An approved payment went through: its receipt joins the hash chain.
        # Written after the upstream call returns, so a payment that failed
        # upstream does not leave a receipt claiming it happened.
        if receipt is not None:
            self._log(
                RECEIPT_STAGE,
                Decision(Verdict.ALLOW, 0.0,
                         [Signal("financial:receipt", 0.0,
                                 f"{fin.transaction.describe()} approved by "
                                 f"{receipt['approver']} (review #{receipt['approval_id']})")],
                         reason=f"payment receipt: {fin.transaction.describe()}",
                         override="receipt"),
                tool=tool, arguments=arguments, session_id=session_id,
                detail=json.dumps(receipt, sort_keys=True),
            )

        # --- 8. TOOL_RESULT: taint classification + recall hook -----------
        self._handle_result(result, tool, session_id, taint)
        return result

    # ------------------------------------------------------------------
    # deep path
    # ------------------------------------------------------------------
    async def _alignment_check(self, decision: Decision, tool: str, arguments: Any,
                               session_id: str, scope: TaskScope | None,
                               tiers: list[str]) -> None:
        """Ask the AlignmentAuditor whether this call serves the declared goal.

        Deep path only: there must be a human-declared goal, and the call must
        already be suspicious or be heading for a sink. The judgment can raise the
        verdict to REVIEW; it never lowers one, and a failure fails open.
        """
        from agentguard.audit import digest_args
        from agentguard.risk import W_ALIGNMENT

        recent = self._recent.setdefault(
            session_id, deque(maxlen=max(1, self.policy.alignment.history)))
        proposed = {"tool": tool, "args": digest_args(arguments, limit=400)}
        history = list(recent)
        recent.append(proposed)

        if scope is None or not scope.goal:
            return
        if decision.verdict is Verdict.ALLOW and all(t == TIER_ORDINARY for t in tiers):
            return
        try:
            judgment = await asyncio.to_thread(
                self.auditor.judge, scope.goal, history, proposed)
        except Exception as exc:                            # noqa: BLE001
            decision.signals.append(Signal(
                "alignment:unavailable", 0.0,
                f"alignment auditor failed ({type(exc).__name__}: {str(exc)[:120]}); "
                f"failing open",
            ))
            return
        if judgment is None or judgment.aligned:
            return
        decision.signals.append(Signal(
            "alignment:misaligned", W_ALIGNMENT,
            f"auditor judged '{tool}' misaligned with the declared goal "
            f"{scope.goal!r}: {judgment.reason}",
        ))
        decision.score = min(1.0, decision.score + W_ALIGNMENT)
        decision.verdict = decision.verdict.escalate(Verdict.REVIEW)
        decision.reason = f"{decision.reason} | alignment: misaligned"

    # ------------------------------------------------------------------
    # terminal handlers
    # ------------------------------------------------------------------
    async def _passthrough(self, context: Any, tool: str, session_id: str,
                           taint: Any, call_next: Any) -> Any:
        """Observe mode: the decision is already logged, now let the call happen.

        Only reached when enforcement is off - the enforcing paths raise before
        getting here. The result is still taint-classified, because observe mode
        must produce a realistic picture of what the taint engine would do.
        """
        result = await call_next(context)
        self._handle_result(result, tool, session_id, taint)
        return result

    def _block(self, decision: Decision, tool: str, arguments: Any,
               session_id: str, absolute: bool = False, detail: str | None = None) -> None:
        """Log a BLOCK and, when enforcing (or `absolute`), stop the call by raising."""
        self._log("TOOL_PREPARE", decision, tool=tool, arguments=arguments,
                  session_id=session_id, detail=detail)
        self.stats.blocked += 1
        if absolute and decision.override == "hard_enforce":
            raise ToolError(
                f"AgentGuard blocked '{tool}' (hard-enforced rule - blocked even in "
                f"observe mode): {decision.reason}"
            )
        if absolute:
            raise ToolError(
                f"AgentGuard blocked '{tool}': {decision.reason}. "
                f"Release with `agentguard unlock` once it is safe."
            )
        if self._enforced():
            raise ToolError(
                f"AgentGuard blocked '{tool}': {decision.reason} "
                f"(score {decision.score:.2f}). Review with `agentguard audit --last 5`."
            )
        self.stats.observed_only += 1

    def _hold_for_review(self, decision: Decision, tool: str, arguments: Any,
                         session_id: str, assessment: Any) -> None:
        from agentguard.audit import digest_args
        from agentguard.scanner import redact_arguments

        item_id = self.queue.enqueue(
            kind=KIND_TOOL_CALL, tool=tool,
            payload={
                "args_digest": digest_args(arguments),
                # Redacted: a reviewer needs to see the shape of the call, not the
                # credential it was carrying.
                "arguments": redact_arguments(arguments),
                "signals": [s.to_dict() for s in decision.signals],
                "sink_tier": assessment.tier if assessment else None,
            },
            score=decision.score, reason=decision.reason,
            session_id=session_id, agent=self.identity.name,
        )
        self._log("TOOL_PREPARE", decision, tool=tool, arguments=arguments,
                  session_id=session_id, detail=f"queued for review as #{item_id}")
        self.stats.review += 1
        if self._enforced():
            raise ToolError(
                f"AgentGuard held '{tool}' for review (#{item_id}): {decision.reason}. "
                f"Approve with `agentguard review approve {item_id}`."
            )
        self.stats.observed_only += 1

    def _quarantine_write(self, decision: Decision, tool: str, arguments: Any,
                          session_id: str, assessment: Any, taint: Any) -> None:
        """Hold a tainted memory write in the ledger instead of forwarding it."""
        from agentguard.scanner import flatten

        content = "\n".join(text for _w, text in flatten(arguments))
        fingerprints = taint.fingerprints_for(content)
        ttl = self.policy.ttl_hours("default")

        item_id = self.ledger.quarantine(
            content=content, tool=tool, session_id=session_id,
            source_tools=assessment.overlap.sources,
            fingerprints=fingerprints, ttl_hours=ttl,
            extra_provenance={"arguments": arguments,
                              "signals": [s.to_dict() for s in decision.signals]},
        )
        self.queue.enqueue(
            kind="memory_promotion", tool=tool,
            payload={"quarantine_id": item_id, "content": content[:2000],
                     "source_tools": assessment.overlap.sources},
            score=decision.score,
            reason="memory write derived from untrusted content",
            session_id=session_id, agent=self.identity.name,
        )
        quarantine_decision = Decision(
            Verdict.REVIEW, decision.score, decision.signals,
            reason=(f"persistence-tier write quarantined as #{item_id} "
                    f"(sources: {', '.join(assessment.overlap.sources) or 'unknown'})"),
            override="quarantined",
        )
        self._log("TOOL_PREPARE", quarantine_decision, tool=tool, arguments=arguments,
                  session_id=session_id,
                  detail=f"quarantined memory item #{item_id}, ttl {ttl}h")
        self.stats.quarantined += 1

        if self._enforced():
            # The agent is told the write was held, not that it succeeded - it must
            # not believe the fact is now in trusted memory.
            raise ToolError(
                f"AgentGuard quarantined this memory write (item #{item_id}): the "
                f"content derives from untrusted source(s) "
                f"{assessment.overlap.sources}. It was NOT saved to trusted memory. "
                f"Promote with `agentguard memory promote {item_id}` after review."
            )
        self.stats.observed_only += 1

    # ------------------------------------------------------------------
    # TOOL_RESULT handling
    # ------------------------------------------------------------------
    def _handle_result(self, result: Any, tool: str, session_id: str, taint: Any) -> None:
        text = _result_text(result)
        if not text:
            return

        label = taint.classify_source(
            tool, self.policy.untrusted_tools, self.policy.trusted_read_paths
        )

        # The recall hook: if returned content matches a quarantined item, its taint
        # is re-attached here. This is what stops the write-in-session-A,
        # exfiltrate-in-session-B chain, and it runs on every result rather than only
        # on tools we guessed were "memory reads".
        recalled = self.ledger.recall_taint(text)
        if recalled is not None:
            taint.record(f"quarantine:{recalled.id}", text, label=UNTRUSTED)
            self.stats.taint_records += 1
            self._log(
                "TOOL_RESULT",
                Decision(Verdict.ALLOW, 0.0,
                         [Signal("taint:recall_reattached", 0.0,
                                 f"content recalled via '{tool}' matches quarantined "
                                 f"item #{recalled.id} (sources: "
                                 f"{', '.join(recalled.source_tools) or 'unknown'}); "
                                 f"taint re-attached")],
                         reason="quarantined memory recalled - taint re-attached",
                         override="recall_retaint"),
                tool=tool, session_id=session_id,
                detail=f"quarantine item #{recalled.id}",
            )
            return

        if label == UNTRUSTED:
            rec = taint.record(tool, text, label=UNTRUSTED)
            self.stats.taint_records += 1
            self._log(
                "TOOL_RESULT",
                Decision(Verdict.ALLOW, 0.0,
                         [Signal("taint:recorded", 0.0,
                                 f"{len(rec.fingerprints)} fingerprints from untrusted "
                                 f"source '{tool}'")],
                         reason=f"untrusted result from '{tool}' fingerprinted"),
                tool=tool, session_id=session_id,
            )

    # ------------------------------------------------------------------
    def taint_map(self, session_id: str | None = None):  # type: ignore[no-untyped-def]
        return self.taints.for_session(session_id or self.identity.session_id)
