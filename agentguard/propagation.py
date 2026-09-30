"""Propagation (worm) detection - Stage 7A.

A self-replicating prompt injection does not need to exfiltrate anything. It
only needs the agent to copy it somewhere the *next* agent will read: a file, a
commit, a PR comment, a chat message, an email. Each copy is a new infection
point, so the damage compounds across agents rather than within one session.

The replication signature is the conjunction of three things, all required:

  1. the outgoing content overlaps untrusted content - from this session's taint
     map, or rehydrated from the Quarantined Memory Ledger;
  2. the *overlapping region itself* contains instruction-like text aimed at an
     AI reader (the scanner's injection patterns plus self-propagation phrasing);
  3. the destination is a propagation-tier sink.

Any one alone is normal: agents quote web pages into notes all the time (1+3),
and a user's own instructions are not attacker text (2+3). Only 1+2+3 raises
`propagation:replication`; overlap alone is logged as `propagation:taint_overlap`.

Code comments are checked on their own. An injection hidden in a comment inside a
large source file is otherwise one small region of a big argument, and a
multi-line `#` comment breaks a sentence across lines where the phrasing patterns
cannot see it whole. Extracting each comment block rejoins it.

Cost is kept off the common path: the cheap regex pass runs first, and the
region computation and ledger fallback only run when it finds something.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from agentguard.decision import Signal, Verdict
from agentguard.policy import TIER_PROPAGATION, Policy
from agentguard.risk import W_PROPAGATION
from agentguard.scanner import (
    ScanResult,
    flatten,
    scan_injection,
    scan_propagation_phrasing,
)
from agentguard.taint import TaintMap, TaintOverlap, UNTRUSTED, overlap_regions, shingles

CODE_EXTENSIONS = frozenset({
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".java", ".kt",
    ".go", ".rs", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".rb", ".php", ".sh",
    ".bash", ".ps1", ".swift", ".scala", ".lua", ".pl", ".r", ".sql", ".html",
    ".htm", ".xml", ".vue", ".svelte", ".css", ".scss", ".yaml", ".yml", ".toml",
    ".tf", ".dockerfile",
})

# Argument keys that name the file being written.
_PATH_KEYS = ("path", "file_path", "filepath", "filename", "file", "target")

_CODE_LINE = re.compile(
    r"(?m)^\s*(def |class |import |from \S+ import |function |const |let |var |"
    r"#include|public |private |package |fn |func |return\b)"
)

_LINE_COMMENT = re.compile(r"(?:^|\s)(?:#(?![!{])|//)\s?(.*)$")
_BLOCK_COMMENT = re.compile(r"/\*(.*?)\*/", re.S)
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_DOCSTRING = re.compile(r'("""|\'\'\')(.*?)\1', re.S)


def looks_like_code(text: str, path: str | None = None) -> bool:
    """Is this argument source code? Path extension first, then a line heuristic."""
    if path:
        suffix = PurePosixPath(path.replace("\\", "/")).suffix.lower()
        if suffix in CODE_EXTENSIONS:
            return True
        if suffix:          # a known non-code extension (.md, .txt) - trust it
            return False
    return "\n" in text and len(_CODE_LINE.findall(text)) >= 2


def extract_comments(text: str) -> list[str]:
    """Comment text from source code, one string per comment block.

    Consecutive single-line comments (`#`, `//`) are joined into one block, so a
    sentence split over several comment lines is seen whole.
    """
    blocks: list[str] = []
    run: list[str] = []
    for line in text.splitlines():
        m = _LINE_COMMENT.search(line) if ("#" in line or "//" in line) else None
        body = m.group(1).strip() if m else ""
        full_line = bool(m) and line.lstrip().startswith(("#", "//"))
        if body and full_line:
            run.append(body)
            continue
        if run:
            blocks.append(" ".join(run))
            run = []
        if body:                 # trailing comment after code: its own block
            blocks.append(body)
    if run:
        blocks.append(" ".join(run))

    for rx, group in ((_BLOCK_COMMENT, 1), (_HTML_COMMENT, 1), (_DOCSTRING, 2)):
        for m in rx.finditer(text):
            body = " ".join(
                ln.strip().lstrip("*").strip() for ln in m.group(group).splitlines()
            ).strip()
            if body:
                blocks.append(body)
    return blocks


def _instruction_labels(text: str) -> list[str]:
    return [f.label for f in (*scan_injection(text), *scan_propagation_phrasing(text))]


@dataclass
class PropagationAssessment:
    signals: list[Signal] = field(default_factory=list)
    verdict_floor: Verdict = Verdict.ALLOW
    replicated: bool = False


class PropagationDetector:
    """Decides whether a propagation-tier call is carrying a replicating payload."""

    def __init__(self, policy: Policy, ledger: Any = None) -> None:
        self.policy = policy
        self.ledger = ledger

    def _units(self, arguments: Any) -> list[tuple[str, str]]:
        """Argument leaves, plus each comment block of any leaf that is code."""
        leaves = flatten(arguments)
        path_where, path = None, None
        for where, text in leaves:
            if where.rsplit(".", 1)[-1].lower() in _PATH_KEYS:
                path_where, path = where, text
                break
        units = list(leaves)
        for where, text in leaves:
            if where == path_where or len(text) < 20:
                continue
            if looks_like_code(text, path):
                units.extend(
                    (f"{where}#comment{i}", c) for i, c in enumerate(extract_comments(text))
                )
        return units

    def _regions(self, text: str, taint: TaintMap) -> tuple[list[str], list[str]]:
        """Untrusted regions of `text`, and which sources they came from.

        Session taint first; if none, the quarantine ledger - content written to
        memory in an earlier session is still attacker text, and must not lose its
        label just because this session never recalled it through the gateway.
        """
        regions = taint.overlap_regions(text)
        if regions:
            hit = taint.check(text)
            return regions, hit.sources or taint.sources
        if self.ledger is None:
            return [], []
        item = self.ledger.recall_taint(text)
        if item is None:
            return [], []
        source = f"quarantine:{item.id}"
        taint.record(source, item.content, label=UNTRUSTED)
        return overlap_regions(text, shingles(item.content)), [source]

    def assess(self, tool: str, arguments: Any, taint: TaintMap,
               tiers: list[str], overlap: TaintOverlap | None = None,
               scan: ScanResult | None = None) -> PropagationAssessment:
        out = PropagationAssessment()
        if not self.policy.propagation_enabled or TIER_PROPAGATION not in tiers:
            return out

        # The fast-path scanner already ran the injection patterns over every
        # argument leaf; reuse that instead of rescanning a large file body.
        scanned: dict[str, list[str]] | None = None
        if scan is not None:
            scanned = {}
            for f in scan.injections:
                scanned.setdefault(f.where, []).append(f.label)

        for where, text in self._units(arguments):
            if scanned is not None and "#comment" not in where:
                labels = scanned.get(where, []) + \
                    [f.label for f in scan_propagation_phrasing(text)]
            else:
                labels = _instruction_labels(text)
            if not labels:
                continue                       # common path: nothing instruction-like
            regions, sources = self._regions(text, taint)
            for region in regions:
                labels = _instruction_labels(region)
                if not labels:
                    continue
                location = "a code comment" if "#comment" in where else f"`{where}`"
                out.replicated = True
                out.verdict_floor = Verdict.REVIEW
                out.signals.append(Signal(
                    "propagation:replication", W_PROPAGATION,
                    f"untrusted text from [{', '.join(sources) or 'unknown'}] containing "
                    f"AI-addressed instructions ({', '.join(sorted(set(labels)))}) is "
                    f"being written by '{tool}' to a propagation sink, in {location}",
                ))
                return out

        if overlap is not None and overlap.tainted:
            out.signals.append(Signal(
                "propagation:taint_overlap", 0.0,
                f"untrusted content from [{', '.join(overlap.sources) or 'unknown'}] "
                f"written to propagation sink '{tool}' with no instruction text "
                f"(logged only)",
            ))
        return out
