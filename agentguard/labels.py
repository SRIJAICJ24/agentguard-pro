"""Human labels for REVIEW/BLOCK decisions, and the precision they add up to.

`report` can count interruptions and the ones a human overruled, but only a person
can say whether an interruption was *right*. This module is where that judgment
goes:

  agentguard report --fp-review   walk the unlabeled REVIEW/BLOCK decisions one at
                                  a time and mark each tp / fp / unsure (or skip)
  agentguard report               precision = tp / (tp + fp), overall, by source
                                  and by signal, always printed with its n

Labels live in their own table (`fp_labels`), keyed by audit row id. The audit
log is hash-chained evidence of what the gateway decided; a label is a later
human opinion about it, and writing it into the chain would make the chain stop
meaning "this is what happened".

Precision per signal attributes a decision's label to every signal present in
that decision. A decision flagged by two signals counts toward both, so the
per-signal numbers answer "when this signal fires, how often is it right", not
"which signal was responsible".
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agentguard.db import connect

LABEL_TP = "tp"
LABEL_FP = "fp"
LABEL_UNSURE = "unsure"
LABELS = (LABEL_TP, LABEL_FP, LABEL_UNSURE)

#: Below this many tp+fp labels a precision figure is noise, and says so.
MIN_TRUSTED_N = 20

INTERRUPT_VERDICTS = ("REVIEW", "BLOCK")
CALL_STAGE = "TOOL_PREPARE"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- storage ---------------------------------------------------------------
def set_label(audit_id: int, label: str, *, by: str = "human",
              db_path: str | Path | None = None) -> None:
    if label not in LABELS:
        raise ValueError(f"label must be one of {LABELS}, got {label!r}")
    conn = connect(db_path)
    conn.execute(
        """INSERT INTO fp_labels (audit_id, label, labeled_at, labeled_by)
           VALUES (?,?,?,?)
           ON CONFLICT(audit_id) DO UPDATE SET label=excluded.label,
             labeled_at=excluded.labeled_at, labeled_by=excluded.labeled_by""",
        (int(audit_id), label, _now(), by),
    )
    conn.commit()


def labels_for(ids: list[int], db_path: str | Path | None = None) -> dict[int, str]:
    if not ids:
        return {}
    conn = connect(db_path)
    out: dict[int, str] = {}
    for chunk in range(0, len(ids), 500):
        part = ids[chunk:chunk + 500]
        marks = ",".join("?" * len(part))
        for row in conn.execute(
            f"SELECT audit_id, label FROM fp_labels WHERE audit_id IN ({marks})", part
        ):
            out[int(row["audit_id"])] = row["label"]
    return out


def interruptions(since_iso: str | None = None,
                  db_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Every gated REVIEW/BLOCK decision in the window, oldest first."""
    conn = connect(db_path)
    sql = ("SELECT * FROM audit WHERE stage = ? AND verdict IN ('REVIEW','BLOCK')"
           + (" AND ts >= ?" if since_iso else "") + " ORDER BY id ASC")
    args: tuple[Any, ...] = (CALL_STAGE, since_iso) if since_iso else (CALL_STAGE,)
    return [dict(r) for r in conn.execute(sql, args)]


def unlabeled(since_iso: str | None = None,
              db_path: str | Path | None = None) -> list[dict[str, Any]]:
    rows = interruptions(since_iso, db_path)
    done = labels_for([r["id"] for r in rows], db_path)
    return [r for r in rows if r["id"] not in done]


# --- presentation ----------------------------------------------------------
def row_mode(row: dict[str, Any]) -> str | None:
    """observe | enforce | None. Rows before Phase E have no mode column value;
    hook rows still say it in their detail text."""
    mode = row.get("mode")
    if mode in ("observe", "enforce"):
        return mode
    detail = row.get("detail") or ""
    if "claude-code observe" in detail:
        return "observe"
    if "claude-code enforce" in detail:
        return "enforce"
    return None


def verdict_phrase(row: dict[str, Any]) -> str:
    """What the verdict meant at the time. In observe mode nothing was stopped."""
    verdict, mode = row.get("verdict"), row_mode(row)
    if verdict == "BLOCK" and any(s.startswith("hard_enforce:") for s in signal_names(row)):
        # A hard-enforced rule blocks in every mode, observe included.
        return "BLOCKED (hard-enforced rule - blocked even in observe mode)"
    if verdict == "BLOCK":
        return {"observe": "WOULD HAVE BLOCKED (observe mode - it ran)",
                "enforce": "BLOCKED"}.get(mode, "BLOCK (mode not recorded - in observe "
                                                "mode this means it would have been blocked)")
    if verdict == "REVIEW":
        return {"observe": "WOULD HAVE ASKED FOR REVIEW (observe mode - it ran)",
                "enforce": "HELD FOR REVIEW"}.get(mode, "REVIEW (mode not recorded)")
    return str(verdict)


def signal_names(row: dict[str, Any]) -> list[str]:
    try:
        return [s["name"] for s in json.loads(row.get("signals") or "[]")
                if isinstance(s, dict) and s.get("name")]
    except (ValueError, TypeError):
        return []


def render_row(row: dict[str, Any], position: str = "") -> str:
    """One decision for the labeler. Arguments are the audit summary, which had
    secrets replaced before it was ever written."""
    when = str(row.get("ts") or "")[:19].replace("T", " ")
    lines = [
        f"{position}audit #{row['id']}  {when} UTC  source={row.get('source') or 'mcp'}  "
        f"detector={row.get('detector_version') or 'unversioned'}",
        f"  {row.get('tool') or '-'}  ->  {verdict_phrase(row)}  (score {row.get('score') or 0:.2f})",
        f"  signals  : {', '.join(signal_names(row)) or '(none)'}",
        f"  reason   : {(row.get('reason') or '')[:160]}",
        f"  arguments: {(row.get('args_digest') or '(none)')[:300]}",
        "             (secrets were replaced before logging)",
    ]
    return "\n".join(lines)


PROMPT = "  label?  [t] real problem (tp)  [f] false alarm (fp)  [u] unsure  [s] skip  [q] quit: "
_ANSWERS = {"t": LABEL_TP, "tp": LABEL_TP, "f": LABEL_FP, "fp": LABEL_FP,
            "u": LABEL_UNSURE, "unsure": LABEL_UNSURE, "s": "skip", "skip": "skip",
            "q": "quit", "quit": "quit", "": "skip"}


@dataclass
class ReviewSession:
    shown: int = 0
    labeled: dict[str, int] = field(default_factory=lambda: {l: 0 for l in LABELS})
    skipped: int = 0
    quit_early: bool = False


def review(since_iso: str | None = None, *, db_path: str | Path | None = None,
           input_fn: Callable[[str], str] | None = None,
           out: Callable[[str], None] | None = None, by: str = "human") -> ReviewSession:
    """Interactive labeler. Already-labeled rows never come back; skipped ones do.

    `input_fn` / `out` default to the builtins looked up at call time (not bound at
    definition time), so a replaced `input` - a test, a wrapper - is honoured.
    """
    import builtins

    input_fn = input_fn or (lambda prompt: builtins.input(prompt))
    out = out or (lambda text: builtins.print(text))
    todo = unlabeled(since_iso, db_path)
    session = ReviewSession()
    if not todo:
        out("  nothing to label - every REVIEW/BLOCK decision in this window is labeled")
        return session
    out(f"  {len(todo)} unlabeled REVIEW/BLOCK decision(s). Was each one a real problem?")
    for i, row in enumerate(todo, 1):
        out("")
        out(render_row(row, f"[{i}/{len(todo)}] "))
        session.shown += 1
        while True:
            try:
                raw = input_fn(PROMPT)
            except EOFError:
                raw = "q"
            # Windows PowerShell 5.1 prefixes piped input with a UTF-8 BOM, which
            # would turn the first answer into an invalid one.
            answer = _ANSWERS.get((raw or "").strip().lstrip("\ufeff").strip().lower())
            if answer is not None:
                break
            out("  please answer t, f, u, s or q")
        if answer == "quit":
            session.quit_early = True
            break
        if answer == "skip":
            session.skipped += 1
            continue
        set_label(row["id"], answer, by=by, db_path=db_path)
        session.labeled[answer] += 1
    return session


# --- precision -------------------------------------------------------------
@dataclass
class Split:
    tp: int = 0
    fp: int = 0
    unsure: int = 0

    @property
    def n(self) -> int:
        return self.tp + self.fp

    @property
    def precision(self) -> float | None:
        return self.tp / self.n if self.n else None

    @property
    def trusted(self) -> bool:
        return self.n >= MIN_TRUSTED_N

    def describe(self) -> str:
        """Never a bare percentage: always the n, and a warning when n is small."""
        if self.n == 0:
            text = "no tp/fp labels yet"
        else:
            text = f"precision {self.precision:.1%} (tp {self.tp} / n {self.n})"
            if not self.trusted:
                text += f"  - too few labels to trust (n < {MIN_TRUSTED_N})"
        if self.unsure:
            text += f"; unsure {self.unsure}"
        return text

    def to_dict(self) -> dict[str, Any]:
        return {"tp": self.tp, "fp": self.fp, "unsure": self.unsure, "n": self.n,
                "precision": None if self.precision is None else round(self.precision, 4),
                "trusted": self.trusted}


@dataclass
class Precision:
    interruptions: int = 0
    labeled: int = 0                      # tp + fp + unsure
    overall: Split = field(default_factory=Split)
    by_source: dict[str, Split] = field(default_factory=dict)
    by_signal: dict[str, Split] = field(default_factory=dict)

    @property
    def coverage(self) -> float:
        return self.labeled / self.interruptions if self.interruptions else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "interruptions": self.interruptions, "labeled": self.labeled,
            "coverage": round(self.coverage, 4), "min_trusted_n": MIN_TRUSTED_N,
            "overall": self.overall.to_dict(),
            "by_source": {k: v.to_dict() for k, v in sorted(self.by_source.items())},
            "by_signal": {k: v.to_dict() for k, v in sorted(self.by_signal.items())},
        }


def _add(split: Split, label: str) -> None:
    if label == LABEL_TP:
        split.tp += 1
    elif label == LABEL_FP:
        split.fp += 1
    elif label == LABEL_UNSURE:
        split.unsure += 1


def precision(since_iso: str | None = None,
              db_path: str | Path | None = None) -> Precision:
    rows = interruptions(since_iso, db_path)
    marks = labels_for([r["id"] for r in rows], db_path)
    result = Precision(interruptions=len(rows), labeled=len(marks))
    for row in rows:
        label = marks.get(row["id"])
        if label is None:
            continue
        _add(result.overall, label)
        _add(result.by_source.setdefault(row.get("source") or "mcp", Split()), label)
        for name in set(signal_names(row)):
            _add(result.by_signal.setdefault(name, Split()), label)
    return result


def render_precision(p: Precision, colorize: Any = None) -> str:
    def paint(text: str, key: str) -> str:
        return colorize(text, key) if colorize else text

    lines = [paint("  LABELED PRECISION", "bold"),
             "  (tp = the interruption was right, fp = false alarm; from "
             "`agentguard report --fp-review`)"]
    if p.interruptions == 0:
        lines.append("    no REVIEW/BLOCK decisions in this window")
        return "\n".join(lines)
    lines.append(f"    labeled {p.labeled} of {p.interruptions} REVIEW/BLOCK decisions "
                 f"({p.coverage:.0%})")
    if p.labeled == 0:
        lines.append("    run `agentguard report --fp-review` to label them")
        return "\n".join(lines)
    warn = (lambda s: paint(s.describe(), "REVIEW") if s.n and not s.trusted else s.describe())
    lines.append(f"    overall  : {warn(p.overall)}")
    for source, split in sorted(p.by_source.items()):
        lines.append(f"    {source:9s}: {warn(split)}")
    if p.by_signal:
        lines.append("    by signal (a decision counts toward every signal it carried):")
        ranked = sorted(p.by_signal.items(), key=lambda kv: (-(kv[1].n + kv[1].unsure), kv[0]))
        width = max(len(name) for name, _ in ranked[:15])
        for name, split in ranked[:15]:
            lines.append(f"      {name.ljust(width)}  {warn(split)}")
    return "\n".join(lines)
