"""Local dashboard: one FastAPI app, server-rendered HTML, no frontend build.

Deliberately plain. It reads the same SQLite database the gateway writes to, so it
works whether or not a gateway process is currently running, and it never needs its
own copy of any state.
"""

from __future__ import annotations

import html
import json
from typing import Any

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, RedirectResponse

from agentguard import __version__, audit
from agentguard.db import connect
from agentguard.quarantine import QuarantinedMemoryLedger
from agentguard.review_queue import ReviewQueue

_CSS = """
:root{--bg:#0f1115;--panel:#171a21;--line:#252a34;--fg:#e6e8ec;--dim:#8b93a1;
--allow:#3fb950;--review:#d29922;--block:#f85149;--quar:#a371f7;--accent:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{padding:18px 24px;border-bottom:1px solid var(--line);display:flex;
gap:16px;align-items:baseline;flex-wrap:wrap}
h1{font-size:16px;margin:0;letter-spacing:.5px}
.mode{padding:2px 8px;border-radius:4px;font-size:12px}
.enforcing{background:#3d1418;color:var(--block)}
.observe{background:#3a2d0a;color:var(--review)}
main{padding:24px;max-width:1200px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:28px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}
.card .n{font-size:24px;font-weight:600}
.card .l{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.7px}
section{margin-bottom:32px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.8px;color:var(--dim);
border-bottom:1px solid var(--line);padding-bottom:8px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);
font-size:13px;vertical-align:top}
th{color:var(--dim);font-weight:500;font-size:11px;text-transform:uppercase}
.v{font-weight:600;font-size:12px}
.ALLOW{color:var(--allow)}.REVIEW{color:var(--review)}.BLOCK{color:var(--block)}
.QUARANTINE{color:var(--quar)}
.dim{color:var(--dim)}
.mono{white-space:pre-wrap;word-break:break-word;font-size:12px;color:var(--dim)}
button{background:var(--panel);color:var(--fg);border:1px solid var(--line);
border-radius:5px;padding:5px 12px;cursor:pointer;font:inherit;font-size:12px}
button.ok:hover{border-color:var(--allow);color:var(--allow)}
button.no:hover{border-color:var(--block);color:var(--block)}
form{display:inline}
a{color:var(--accent)}
.empty{color:var(--dim);padding:14px 0;font-style:italic}
.pill{font-size:11px;padding:1px 7px;border-radius:9px;background:var(--line);color:var(--dim)}
"""


def _esc(v: Any) -> str:
    return html.escape("" if v is None else str(v))


def create_app(db_path: str | None = None) -> FastAPI:
    app = FastAPI(title="AgentGuard", version=__version__)
    queue = ReviewQueue(db_path)
    ledger = QuarantinedMemoryLedger(db_path)

    def _agent_counts() -> list[dict[str, Any]]:
        conn = connect(db_path)
        rows = conn.execute(
            """SELECT agent, role, COUNT(*) AS calls,
                      SUM(verdict='BLOCK')  AS blocked,
                      SUM(verdict='REVIEW') AS review
               FROM audit WHERE agent IS NOT NULL
               GROUP BY agent, role ORDER BY calls DESC"""
        ).fetchall()
        return [dict(r) for r in rows]

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:                                   # noqa: PLR0915
        stats = audit.stats(db_path)
        intact, broken = audit.verify_chain(db_path)
        decisions = audit.last(25, db_path)
        pending = queue.list("pending")
        quarantined = ledger.list()

        parts: list[str] = [
            "<!doctype html><meta charset='utf-8'>",
            "<title>AgentGuard</title>",
            f"<style>{_CSS}</style>",
            "<header><h1>AGENTGUARD</h1>",
            f"<span class='dim'>v{__version__}</span>",
            f"<span class='pill'>audit chain: "
            f"{'intact' if intact else f'BROKEN at row {broken}'}</span>",
            "</header><main>",
        ]

        # --- counters ---
        cards = [
            ("agents protected", stats["agents"]),
            ("threats blocked", stats["blocked"]),
            ("calls today", stats["today"]),
            ("awaiting review", stats["pending_reviews"]),
            ("in quarantine", stats["quarantined"]),
            ("total decisions", stats["total"]),
        ]
        parts.append("<div class='cards'>")
        for label, n in cards:
            parts.append(f"<div class='card'><div class='n'>{n}</div>"
                         f"<div class='l'>{label}</div></div>")
        parts.append("</div>")

        # --- review queue ---
        parts.append("<section><h2>Review queue</h2>")
        if not pending:
            parts.append("<p class='empty'>Nothing awaiting review.</p>")
        else:
            parts.append("<table><tr><th>id</th><th>kind</th><th>tool</th>"
                         "<th>score</th><th>reason</th><th></th></tr>")
            for item in pending:
                parts.append(
                    f"<tr><td>#{item.id}</td><td>{_esc(item.kind)}</td>"
                    f"<td>{_esc(item.tool)}</td><td>{item.score or 0:.2f}</td>"
                    f"<td class='mono'>{_esc(item.reason)}</td><td>"
                    f"<form method='post' action='/review/{item.id}/approve'>"
                    f"<button class='ok'>approve</button></form> "
                    f"<form method='post' action='/review/{item.id}/deny'>"
                    f"<button class='no'>deny</button></form></td></tr>"
                )
            parts.append("</table>")
        parts.append("</section>")

        # --- quarantined memory ---
        parts.append("<section><h2>Quarantined memory "
                     "<span class='dim'>- promotion requires a human decision</span></h2>")
        if not quarantined:
            parts.append("<p class='empty'>Nothing in quarantine.</p>")
        else:
            parts.append("<table><tr><th>id</th><th>sources</th><th>sink</th>"
                         "<th>expires</th><th>content</th><th></th></tr>")
            for item in quarantined:
                parts.append(
                    f"<tr><td>#{item.id}</td>"
                    f"<td class='QUARANTINE v'>{_esc(', '.join(item.source_tools))}</td>"
                    f"<td>{_esc(item.tool)}</td>"
                    f"<td class='dim'>{_esc(item.expires_at or 'never (flagged)')}</td>"
                    f"<td class='mono'>{_esc(item.content[:220])}</td><td>"
                    f"<form method='post' action='/quarantine/{item.id}/promote'>"
                    f"<button class='ok'>promote</button></form> "
                    f"<form method='post' action='/quarantine/{item.id}/deny'>"
                    f"<button class='no'>deny</button></form></td></tr>"
                )
            parts.append("</table>")
        parts.append("</section>")

        # --- per-agent counts ---
        agents = _agent_counts()
        parts.append("<section><h2>Per-agent activity</h2>")
        if not agents:
            parts.append("<p class='empty'>No calls recorded yet.</p>")
        else:
            parts.append("<table><tr><th>agent</th><th>role</th><th>calls</th>"
                         "<th>blocked</th><th>review</th></tr>")
            for a in agents:
                parts.append(
                    f"<tr><td>{_esc(a['agent'])}</td><td>{_esc(a['role'])}</td>"
                    f"<td>{a['calls']}</td><td class='BLOCK'>{a['blocked'] or 0}</td>"
                    f"<td class='REVIEW'>{a['review'] or 0}</td></tr>"
                )
            parts.append("</table>")
        parts.append("</section>")

        # --- recent decisions ---
        parts.append("<section><h2>Recent decisions</h2>")
        if not decisions:
            parts.append("<p class='empty'>No decisions yet.</p>")
        else:
            parts.append("<table><tr><th>time</th><th>verdict</th><th>score</th>"
                         "<th>stage</th><th>tool</th><th>reason</th><th>session</th></tr>")
            for d in decisions:
                sid = d["session_id"] or ""
                parts.append(
                    f"<tr><td class='dim'>{_esc(d['ts'][11:19])}</td>"
                    f"<td class='v {_esc(d['verdict'])}'>{_esc(d['verdict'])}</td>"
                    f"<td>{d['score'] or 0:.2f}</td><td class='dim'>{_esc(d['stage'])}</td>"
                    f"<td>{_esc(d['tool'])}</td>"
                    f"<td class='mono'>{_esc(d['reason'])}</td>"
                    f"<td><a href='/timeline/{_esc(sid)}'>{_esc(sid[:8])}</a></td></tr>"
                )
            parts.append("</table>")
        parts.append("</section></main>")
        return "".join(parts)

    @app.get("/timeline/{session_id}", response_class=HTMLResponse)
    def timeline(session_id: str) -> str:
        """The attack-chain view: every event in one session, in order."""
        rows = audit.session_timeline(session_id, db_path)
        parts = ["<!doctype html><meta charset='utf-8'><title>AgentGuard timeline</title>",
                 f"<style>{_CSS}</style>",
                 f"<header><h1>ATTACK-CHAIN TIMELINE</h1>"
                 f"<span class='dim'>session {_esc(session_id)}</span>"
                 f"<a href='/'>&larr; back</a></header><main>"]
        if not rows:
            parts.append("<p class='empty'>No events for this session.</p></main>")
            return "".join(parts)
        parts.append("<table><tr><th>#</th><th>time</th><th>verdict</th><th>stage</th>"
                     "<th>tool</th><th>what happened</th></tr>")
        for i, r in enumerate(rows, 1):
            detail = f"<div class='mono'>{_esc(str(r['detail'])[:400])}</div>" \
                if r["detail"] else ""
            signals = ""
            try:
                sig = json.loads(r["signals"] or "[]")
                if sig:
                    signals = "<div class='mono'>" + "<br>".join(
                        f"- {_esc(s['name'])}: {_esc(s['detail'])}" for s in sig
                    ) + "</div>"
            except (ValueError, TypeError, KeyError):
                pass
            parts.append(
                f"<tr><td class='dim'>{i}</td><td class='dim'>{_esc(r['ts'][11:19])}</td>"
                f"<td class='v {_esc(r['verdict'])}'>{_esc(r['verdict'])}</td>"
                f"<td class='dim'>{_esc(r['stage'])}</td><td>{_esc(r['tool'])}</td>"
                f"<td>{_esc(r['reason'])}{signals}{detail}</td></tr>"
            )
        parts.append("</table></main>")
        return "".join(parts)

    # --- actions ---------------------------------------------------------
    @app.post("/review/{item_id}/approve")
    def approve(item_id: int) -> RedirectResponse:
        item = queue.approve(item_id)
        if item and item.kind == "memory_promotion":
            qid = item.payload.get("quarantine_id")
            if qid:
                ledger.promote(int(qid), approved_by="dashboard")
        return RedirectResponse("/", status_code=303)

    @app.post("/review/{item_id}/deny")
    def deny(item_id: int) -> RedirectResponse:
        queue.deny(item_id)
        return RedirectResponse("/", status_code=303)

    @app.post("/quarantine/{item_id}/promote")
    def promote(item_id: int) -> RedirectResponse:
        ledger.promote(item_id, approved_by="dashboard")
        return RedirectResponse("/", status_code=303)

    @app.post("/quarantine/{item_id}/deny")
    def quarantine_deny(item_id: int) -> RedirectResponse:
        ledger.deny(item_id)
        return RedirectResponse("/", status_code=303)

    @app.get("/api/stats")
    def api_stats() -> dict[str, Any]:
        return audit.stats(db_path)

    return app
