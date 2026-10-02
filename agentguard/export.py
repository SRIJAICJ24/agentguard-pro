"""`agentguard report --export <file>` - an anonymized copy of the week's decisions.

For sharing the numbers (a review, a bug report, a write-up) without sharing what
the agent was working on. Each gated decision in the window becomes one row with:

  id, timestamp, source, tool, verdict, score, signal names, detector/policy
  version, mode, and your label.

What is removed, not just masked:
  * arguments - never exported at all
  * reason and signal *details* - they quote argument text (paths, hosts)
  * home-directory paths (C:\\Users\\<name>, /home/<name>, /Users/<name>) -> <HOME>
  * the current user's name, wherever it appears -> <USER>
  * anything the scanner recognises as a secret -> <redacted:TYPE>

The last three are applied to every string field that is exported, as a second
line of defence for the fields that are kept (a tool name can contain a path).

The first line of the file notes the window and the detector/policy version mix,
so a reader knows what the numbers cover.
"""

from __future__ import annotations

import csv
import getpass
import io
import json
import os
import re
from pathlib import Path
from typing import Any

from agentguard.db import connect
from agentguard.labels import labels_for, row_mode, signal_names
from agentguard.scanner import redact_text

FIELDS = ("id", "ts", "source", "workspace", "tool", "verdict", "score", "signals",
          "detector_version", "policy_version", "mode", "label")

_HOME_PATTERNS = (
    re.compile(r"(?i)\b[a-z]:[\\/]+(?:users|documents and settings)[\\/]+[^\\/\s\"',;:|]+"),
    re.compile(r"(?<![\w.])/(?:home|Users)/[^/\s\"',;:|]+"),
    re.compile(r"(?<![\w.])/root\b"),
)


def usernames() -> list[str]:
    """The names that identify the person running this: login name, the home
    directory's name, and the USERNAME/USER variables."""
    names = set()
    try:
        names.add(getpass.getuser())
    except Exception:                                   # noqa: BLE001
        pass
    for var in ("USERNAME", "USER", "LOGNAME"):
        if os.environ.get(var):
            names.add(os.environ[var])
    try:
        names.add(Path.home().name)
    except RuntimeError:
        pass
    # Very short names would redact ordinary words ("a", "me").
    return sorted({n for n in names if n and len(n) >= 3}, key=len, reverse=True)


def scrub(text: Any, names: list[str] | None = None) -> Any:
    if not isinstance(text, str) or not text:
        return text
    out = redact_text(text)
    for rx in _HOME_PATTERNS:
        out = rx.sub("<HOME>", out)
    for name in names if names is not None else usernames():
        out = re.sub(re.escape(name), "<USER>", out, flags=re.IGNORECASE)
    return out


def rows(since_iso: str, db_path: str | Path | None = None, *,
         exclude_workspaces: Any = ()) -> list[dict[str, Any]]:
    from agentguard.labels import workspace_clause

    conn = connect(db_path)
    ws_sql, ws_args = workspace_clause(exclude_workspaces)
    raw = [dict(r) for r in conn.execute(
        "SELECT * FROM audit WHERE stage = 'TOOL_PREPARE' AND ts >= ?" + ws_sql
        + " ORDER BY id ASC", (since_iso, *ws_args))]
    marks = labels_for([r["id"] for r in raw], db_path)
    names = usernames()
    out = []
    for r in raw:
        record = {
            "id": r["id"],
            "ts": r["ts"],
            "source": r.get("source") or "mcp",
            "workspace": r.get("workspace") or "",
            "tool": r.get("tool"),
            "verdict": r.get("verdict"),
            "score": r.get("score"),
            "signals": ";".join(signal_names(r)),
            "detector_version": r.get("detector_version") or "unversioned",
            "policy_version": r.get("policy_version") or "unversioned",
            "mode": row_mode(r) or "unknown",
            "label": marks.get(r["id"], ""),
        }
        out.append({k: scrub(v, names) for k, v in record.items()})
    return out


def header_line(report: Any) -> str:
    mix = "; ".join(f"detector {d} / policy {p} x{n}" for d, p, n in report.versions) \
        or "no gated calls"
    warn = " (MIXED VERSIONS - compare periods separately)" if report.mixed_versions else ""
    return (f"agentguard export - window last {report.window} "
            f"({report.since:%Y-%m-%d %H:%M} to {report.until:%Y-%m-%d %H:%M} UTC); "
            f"versions: {mix}{warn}; "
            + (f"excluded {report.excluded_dev} dev-workspace call(s) "
               f"[{', '.join(report.dev_workspaces_excluded)}]; "
               if getattr(report, "excluded_dev", 0) else "")
            + "arguments removed; home paths, usernames and secrets redacted")


def export(path: str | Path, report: Any, db_path: str | Path | None = None,
           fmt: str | None = None) -> tuple[Path, int]:
    """Write the export. Format from `fmt`, else the file extension (csv/json)."""
    target = Path(path)
    fmt = (fmt or target.suffix.lstrip(".") or "csv").lower()
    if fmt not in ("csv", "json"):
        raise ValueError(f"export format must be csv or json, got {fmt!r}")
    data = rows(report.since.isoformat(), db_path,
                exclude_workspaces=getattr(report, "dev_workspaces_excluded", ()))
    header = scrub(header_line(report))
    target.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        payload = {"meta": {"note": header, "window": report.window,
                            "since": report.since.isoformat(),
                            "until": report.until.isoformat(),
                            "versions": [{"detector_version": d, "policy_version": p,
                                          "calls": n} for d, p, n in report.versions],
                            "mixed_versions": report.mixed_versions},
                   "rows": data}
        target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    else:
        buf = io.StringIO()
        buf.write(f"# {header}\n")
        writer = csv.DictWriter(buf, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(data)
        target.write_text(buf.getvalue(), encoding="utf-8", newline="")
    return target, len(data)
