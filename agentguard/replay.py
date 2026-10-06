"""Replay past Claude Code sessions through the hook engine - measure before installing.

Claude Code keeps a transcript of every session under `<config dir>/projects/`
(CLAUDE_CONFIG_DIR, or ~/.claude). Each tool call is in there with its input, and
each result with its output. `agentguard replay` feeds them, in order, through the
same HookEngine the live hook uses (PreToolUse for the call, PostToolUse for the
result, so taint tracking works as it would have) and reports what would have
been flagged.

Nothing is written outside a temporary database that is deleted afterwards: the
transcripts are only read, and the real audit log is not touched. Example
excerpts are redacted (secrets, home paths, user names) before printing.

This is how the week 2 accuracy numbers were measured; anyone can reproduce the
measurement on their own history, with their own policy, in a minute.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator


def projects_dir() -> Path:
    base = os.environ.get("CLAUDE_CONFIG_DIR")
    return (Path(base) if base else Path.home() / ".claude") / "projects"


@dataclass
class ReplayExample:
    project: str
    tool: str
    verdict: str
    signals: list[str]
    excerpt: str


@dataclass
class ReplayResult:
    calls: int = 0
    sessions: int = 0
    verdicts: Counter = field(default_factory=Counter)
    signals: Counter = field(default_factory=Counter)
    hard: Counter = field(default_factory=Counter)
    by_project: dict[str, Counter] = field(default_factory=dict)
    examples: list[ReplayExample] = field(default_factory=list)

    @property
    def flagged(self) -> int:
        return self.verdicts["REVIEW"] + self.verdicts["BLOCK"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "calls": self.calls, "sessions": self.sessions, "flagged": self.flagged,
            "verdicts": dict(self.verdicts), "hard_enforced": dict(self.hard),
            "signals": dict(self.signals.most_common()),
            "by_project": {p: dict(c) for p, c in self.by_project.items()},
            "examples": [e.__dict__ for e in self.examples],
        }


def _result_text(block: dict[str, Any]) -> str:
    content = block.get("content")
    if isinstance(content, list):
        return "\n".join(str(c.get("text", "")) for c in content if isinstance(c, dict))
    return str(content or "")


def iter_events(path: Path) -> Iterator[dict[str, Any]]:
    """Hook payloads (PreToolUse, then PostToolUse) reconstructed from one transcript."""
    pending: dict[str, dict[str, Any]] = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            message = entry.get("message") if isinstance(entry, dict) else None
            content = message.get("content") if isinstance(message, dict) else None
            if not isinstance(content, list):
                continue
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_use":
                    payload = {"hook_event_name": "PreToolUse",
                               "session_id": entry.get("sessionId") or path.stem,
                               "cwd": entry.get("cwd"), "tool_name": block.get("name"),
                               "tool_input": block.get("input") or {},
                               "tool_use_id": block.get("id")}
                    pending[str(block.get("id"))] = payload
                    yield payload
                elif block.get("type") == "tool_result":
                    pre = pending.pop(str(block.get("tool_use_id")), None)
                    if pre is not None:
                        yield {**pre, "hook_event_name": "PostToolUse",
                               "tool_response": _result_text(block)}


def run(policy: Any, root: Path | None = None, *, skip: tuple[str, ...] = (),
        only: tuple[str, ...] = (), examples: int = 0) -> ReplayResult:
    from agentguard.export import scrub, usernames
    from agentguard.hooks import HookEngine

    root = root or projects_dir()
    result = ReplayResult()
    names = usernames()
    work = Path(tempfile.mkdtemp(prefix="agentguard-replay-"))
    try:
        engine = HookEngine(policy, db_path=str(work / "replay.db"))
        projects = sorted(p for p in root.iterdir() if p.is_dir()) if root.is_dir() else []
        for project in projects:
            if project.name in skip or (only and project.name not in only):
                continue
            per = result.by_project.setdefault(project.name, Counter())
            for transcript in sorted(project.glob("*.jsonl")):
                result.sessions += 1
                for payload in iter_events(transcript):
                    engine.handle(payload)
                    if payload["hook_event_name"] != "PreToolUse":
                        continue
                    event = engine.events[-1] if engine.events else {}
                    if event.get("deduped") or "verdict" not in event:
                        continue
                    verdict = event["verdict"]
                    result.calls += 1
                    result.verdicts[verdict] += 1
                    per[verdict] += 1
                    for name in event["signals"]:
                        result.signals[name] += 1
                        if name.startswith("hard_enforce:"):
                            result.hard[name.split(":", 1)[1]] += 1
                    if verdict != "ALLOW" and len(result.examples) < examples:
                        raw = json.dumps(payload.get("tool_input"), ensure_ascii=False)
                        result.examples.append(ReplayExample(
                            project=scrub(project.name, names), tool=str(payload["tool_name"]),
                            verdict=verdict, signals=list(event["signals"]),
                            excerpt=scrub(raw[:400], names)[:200]))
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)


def render(result: ReplayResult, root: Path) -> str:
    total = result.calls or 1
    lines = [
        f"AgentGuard replay of {root}",
        f"  {result.calls} tool calls in {result.sessions} sessions "
        f"(nothing was written outside a temporary database)",
        "",
        f"  ALLOW   {result.verdicts['ALLOW']:>6}  ({result.verdicts['ALLOW'] / total:.1%})",
        f"  REVIEW  {result.verdicts['REVIEW']:>6}  ({result.verdicts['REVIEW'] / total:.1%})",
        f"  BLOCK   {result.verdicts['BLOCK']:>6}  ({result.verdicts['BLOCK'] / total:.1%})",
    ]
    if result.hard:
        lines += ["", "  would be blocked even in observe mode (hard_enforce):"]
        lines += [f"    {rule:<22} {n}" for rule, n in result.hard.most_common()]
    shown = [(s, n) for s, n in result.signals.most_common() if not s.startswith("hard_enforce:")]
    if shown:
        lines += ["", "  signals (a call can carry several; weight-0 ones are logged only):"]
        lines += [f"    {s:<44} {n}" for s, n in shown[:20]]
    if result.examples:
        lines += ["", "  flagged examples (redacted):"]
        for e in result.examples:
            lines.append(f"    [{e.verdict}] {e.project} {e.tool}: {', '.join(e.signals[:4])}")
            lines.append(f"        {e.excerpt}")
    lines += ["", "  These are your own past sessions, so most flags are likely false alarms -",
              "  that's the number to look at before switching on enforce mode."]
    return "\n".join(lines)
