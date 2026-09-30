"""Taint tracking: where content came from, and where it is trying to go.

Most gateways only inspect tool *calls*. The interesting attacks arrive in tool
*results* - a web page or email carrying instructions the agent then acts on. So
the taint engine hooks TOOL_RESULT, classifies the source, and fingerprints
untrusted content into a session-scoped map. Later, every outgoing tool call's
arguments are checked for overlap against that map.

Fingerprinting uses hashed n-gram shingles, not embeddings: it is deterministic,
needs no model call, and runs in microseconds, which is what makes it usable on a
live request path.

Known limitation (deliberate, documented rather than hidden)
-----------------------------------------------------------
Shingles match verbatim and near-verbatim reuse. If the agent heavily paraphrases
untrusted content before putting it in an argument, overlap can fall below the
threshold and the flow is missed. This engine is therefore a strong control
against copy-through - which is how the documented memory-poisoning and
exfiltration chains actually behave - not a guarantee against a model that
rewrites text from scratch. Lowering SHINGLE_SIZE raises recall and false
positives together; the defaults were chosen to keep prose from colliding.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatch
from typing import Any, Iterable

# 5-word shingles: long enough that ordinary English phrases do not collide by
# chance, short enough to survive light editing of the copied text.
SHINGLE_SIZE = 5

# How much overlap counts as "this argument contains untrusted content".
# A single shared 5-gram is already strong evidence of copy-through.
MIN_SHARED_SHINGLES = 1

# Fraction-based alternative for long arguments, used alongside the absolute
# minimum so that a large document sharing one stock phrase is not flagged.
MIN_OVERLAP_RATIO = 0.02

TRUSTED = "TRUSTED"
UNTRUSTED = "UNTRUSTED"

_WORD_RE = re.compile(r"[a-z0-9]+")
# Same tokens as _WORD_RE, matched against un-lowered text so spans map back.
_WORD_SPAN_RE = re.compile(r"[a-zA-Z0-9]+")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def normalise(text: str) -> list[str]:
    """Lowercase word tokens - strips punctuation and casing so that trivial
    reformatting of copied text does not defeat the fingerprint."""
    return _WORD_RE.findall(text.lower())


def shingles(text: str, size: int = SHINGLE_SIZE) -> set[str]:
    """Hashed n-gram shingle set for a piece of text.

    Short texts (fewer than `size` tokens) collapse to a single whole-text
    shingle, so small payloads are still trackable.
    """
    words = normalise(text)
    if not words:
        return set()
    if len(words) < size:
        joined = " ".join(words)
        return {hashlib.sha256(joined.encode()).hexdigest()[:16]}
    out: set[str] = set()
    for i in range(len(words) - size + 1):
        gram = " ".join(words[i:i + size])
        out.add(hashlib.sha256(gram.encode()).hexdigest()[:16])
    return out


def _gram_hash(gram: str) -> str:
    return hashlib.sha256(gram.encode()).hexdigest()[:16]


def overlap_regions(text: str, known: Iterable[str] | set[str],
                    size: int = SHINGLE_SIZE) -> list[str]:
    """The spans of `text` that are covered by known shingles, as substrings.

    `check()` answers "does this text contain untrusted content"; this answers
    "which part of it". Stage 7A needs the second question: instruction-like text
    only counts as evidence of replication when it sits *inside* the copied
    untrusted region, not merely somewhere in the same argument as it.

    Words are located in the original text (case-insensitively, same tokenisation
    as `normalise`) so the returned substrings keep their original punctuation and
    line breaks, which the phrasing patterns rely on.
    """
    known = known if isinstance(known, (set, frozenset)) else set(known)
    if not known:
        return []
    matches = list(_WORD_SPAN_RE.finditer(text))
    words = [m.group(0).lower() for m in matches]
    if not words:
        return []
    if len(words) < size:
        return [text] if _gram_hash(" ".join(words)) in known else []

    covered = [False] * len(words)
    for i in range(len(words) - size + 1):
        if _gram_hash(" ".join(words[i:i + size])) in known:
            for j in range(i, i + size):
                covered[j] = True

    regions: list[str] = []
    i = 0
    while i < len(words):
        if not covered[i]:
            i += 1
            continue
        j = i
        while j + 1 < len(words) and covered[j + 1]:
            j += 1
        regions.append(text[matches[i].start():matches[j].end()])
        i = j + 1
    return regions


@dataclass
class TaintRecord:
    """One untrusted result observed flowing into the session."""

    source_tool: str
    fingerprints: set[str]
    timestamp: datetime = field(default_factory=_now)
    label: str = UNTRUSTED
    excerpt: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_tool": self.source_tool,
            "label": self.label,
            "timestamp": self.timestamp.isoformat(),
            "fingerprint_count": len(self.fingerprints),
            "excerpt": self.excerpt[:160],
        }


@dataclass
class TaintOverlap:
    """The result of checking one argument payload against the taint map."""

    tainted: bool
    shared: set[str] = field(default_factory=set)
    sources: list[str] = field(default_factory=list)
    ratio: float = 0.0

    def __bool__(self) -> bool:
        return self.tainted

    def to_dict(self) -> dict[str, Any]:
        return {
            "tainted": self.tainted,
            "shared_shingles": len(self.shared),
            "sources": self.sources,
            "ratio": round(self.ratio, 4),
        }


class TaintMap:
    """Session-scoped store of untrusted content fingerprints."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.records: list[TaintRecord] = []
        self._index: dict[str, set[str]] = {}   # fingerprint -> source tools

    # --- source classification -------------------------------------------
    @staticmethod
    def classify_source(
        tool: str,
        untrusted_patterns: Iterable[str],
        trusted_patterns: Iterable[str] = (),
    ) -> str:
        """Decide whether a tool's output is TRUSTED or UNTRUSTED.

        Untrusted wins ties: a tool matching both lists is treated as untrusted,
        because misclassifying attacker-controlled content as trusted is the more
        expensive mistake.
        """
        for pattern in untrusted_patterns:
            if fnmatch(tool, pattern):
                return UNTRUSTED
        for pattern in trusted_patterns:
            if fnmatch(tool, pattern):
                return TRUSTED
        return TRUSTED

    # --- recording --------------------------------------------------------
    def record(self, source_tool: str, content: str, label: str = UNTRUSTED) -> TaintRecord:
        """Fingerprint an untrusted result and index it against this session."""
        fps = shingles(content)
        rec = TaintRecord(
            source_tool=source_tool,
            fingerprints=fps,
            label=label,
            excerpt=" ".join(content.split())[:200],
        )
        self.records.append(rec)
        for fp in fps:
            self._index.setdefault(fp, set()).add(source_tool)
        return rec

    # --- checking ---------------------------------------------------------
    def check(self, text: str) -> TaintOverlap:
        """Does this text overlap any untrusted content seen this session?"""
        if not self._index:
            return TaintOverlap(False)
        fps = shingles(text)
        if not fps:
            return TaintOverlap(False)
        shared = fps & self._index.keys()
        if not shared:
            return TaintOverlap(False)

        ratio = len(shared) / len(fps)
        enough = len(shared) >= MIN_SHARED_SHINGLES and (
            len(fps) <= 50 or ratio >= MIN_OVERLAP_RATIO
        )
        sources = sorted({s for fp in shared for s in self._index[fp]})
        return TaintOverlap(tainted=enough, shared=set(shared), sources=sources, ratio=ratio)

    def check_arguments(self, arguments: Any) -> TaintOverlap:
        """Check every leaf of a tool-call argument structure."""
        from agentguard.scanner import flatten

        best = TaintOverlap(False)
        for _where, text in flatten(arguments):
            overlap = self.check(text)
            if overlap.tainted and len(overlap.shared) >= len(best.shared):
                best = overlap
            elif not best.tainted and overlap.shared:
                best = overlap
        return best

    def overlap_regions(self, text: str) -> list[str]:
        """Substrings of `text` copied from untrusted content seen this session."""
        return overlap_regions(text, self._index.keys())

    def fingerprints_for(self, text: str) -> set[str]:
        """The subset of this text's shingles that are known-untrusted."""
        return shingles(text) & self._index.keys()

    def __len__(self) -> int:
        return len(self.records)

    @property
    def sources(self) -> list[str]:
        return sorted({r.source_tool for r in self.records})


class TaintRegistry:
    """All live sessions' taint maps.

    Session-scoped by design: taint from one agent session must not leak into
    another. Cross-session persistence is the Quarantined Memory Ledger's job,
    which is exactly why the ledger re-attaches labels on recall.
    """

    def __init__(self) -> None:
        self._maps: dict[str, TaintMap] = {}

    def for_session(self, session_id: str) -> TaintMap:
        if session_id not in self._maps:
            self._maps[session_id] = TaintMap(session_id)
        return self._maps[session_id]

    def drop(self, session_id: str) -> None:
        self._maps.pop(session_id, None)

    @property
    def sessions(self) -> list[str]:
        return list(self._maps)

    def __len__(self) -> int:
        return len(self._maps)
