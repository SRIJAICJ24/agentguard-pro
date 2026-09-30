"""AgentGuard command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from agentguard import __version__


def load_policy(*args: Any, **kwargs: Any) -> Any:
    """Imported lazily: `agentguard hook` runs once per Claude Code tool call and
    must load only the standard library, and the policy module pulls in PyYAML."""
    from agentguard.policy import load

    return load(*args, **kwargs)

# --- small terminal helpers ------------------------------------------------
_COLORS = {"ALLOW": "\033[32m", "REVIEW": "\033[33m", "BLOCK": "\033[31m",
           "QUARANTINE": "\033[35m", "dim": "\033[2m", "bold": "\033[1m",
           "reset": "\033[0m"}


def _c(text: str, key: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{_COLORS.get(key, '')}{text}{_COLORS['reset']}"


def _table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    out = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)),
           "  ".join("-" * widths[i] for i in range(len(headers)))]
    for row in rows:
        out.append("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)))
    return "\n".join(out)


# --- commands --------------------------------------------------------------
def cmd_scan(args: argparse.Namespace) -> int:
    """One-off scan of a string, no server needed."""
    from agentguard.risk import RiskEngine
    from agentguard.scanner import scan_text

    policy = load_policy(args.policy)
    scan = scan_text(args.text, "input",
                     policy.path_denylist or scan_default_denylist())
    decision = RiskEngine(policy.allow_below, policy.block_above).evaluate(scan)

    print(f"{_c('verdict', 'bold')} : {_c(decision.verdict.value, decision.verdict.value)}")
    print(f"{_c('score', 'bold')}   : {decision.score:.2f}")
    if not scan.findings:
        print(_c("no findings", "dim"))
        return 0
    print(f"\n{_c('findings', 'bold')}:")
    for f in scan.findings:
        print(f"  - [{f.kind}] {f.label}")
        if f.excerpt:
            print(f"    {_c(f.excerpt, 'dim')}")
    return 0


def scan_default_denylist() -> Any:
    from agentguard.scanner import DEFAULT_PATH_DENYLIST
    return DEFAULT_PATH_DENYLIST


def cmd_audit(args: argparse.Namespace) -> int:
    from agentguard import audit

    if args.verify:
        intact, broken = audit.verify_chain()
        if intact:
            print(_c("audit chain intact", "ALLOW"))
            return 0
        print(_c(f"audit chain BROKEN at row {broken}", "BLOCK"))
        return 1

    if args.session:
        rows = audit.session_timeline(args.session)
        if not rows:
            print("no events for that session")
            return 0
        print(_c(f"attack-chain timeline for session {args.session}", "bold"))
        for r in rows:
            marker = {"ALLOW": "  ", "REVIEW": " !", "BLOCK": " X"}.get(r["verdict"], "  ")
            print(f"{marker} {r['ts'][11:19]}  {_c(r['verdict'].ljust(6), r['verdict'])} "
                  f"{r['stage']:14s} {r['tool'] or '-'}")
            if r["reason"]:
                print(f"      {_c(r['reason'], 'dim')}")
            if r["detail"]:
                print(f"      {_c(str(r['detail'])[:200], 'dim')}")
        return 0

    rows = audit.last(args.last)
    if not rows:
        print("no decisions recorded yet")
        return 0
    # Date included: time alone made old rows look like today's traffic.
    table = [[str(r["id"]), f"{r['ts'][:10]} {r['ts'][11:19]}", r.get("source") or "mcp",
              r["verdict"], f"{r['score'] or 0:.2f}", r["tool"] or "-",
              (r["reason"] or "")[:52]]
             for r in rows]
    print(_table(table, ["id", "when (UTC)", "source", "verdict", "score", "tool", "reason"]))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    from agentguard import audit
    from agentguard import config as cfg
    from agentguard.db import default_db_path

    policy = load_policy(args.policy)
    s = audit.stats()
    intact, broken = audit.verify_chain()
    print(_c(f"AgentGuard {__version__}", "bold"))

    # Installation config, when onboarding has been run.
    if cfg.exists():
        try:
            config = cfg.load()
            print(f"  config          : {cfg.config_path()}")
            print(f"  gateway port    : {config.port}"
                  + (f"   dashboard: {config.dashboard_port}" if config.dashboard
                     else "   dashboard: disabled"))
        except cfg.ConfigError as exc:
            print(f"  config          : {_c('UNUSABLE', 'BLOCK')} - {exc}")
            print(f"                    -> run `agentguard doctor` for detail")
    else:
        print(f"  config          : {_c('not set up', 'REVIEW')} "
              f"(run `agentguard onboard`)")

    print(f"  mode            : "
          f"{_c('ENFORCING', 'BLOCK') if policy.enforcement else _c('OBSERVE (log only)', 'REVIEW')}")
    print(f"  policy          : {policy.source_path or '<defaults>'}")
    print(f"  database        : {default_db_path()}")
    print(f"  audit chain     : "
          f"{_c('intact', 'ALLOW') if intact else _c(f'BROKEN at {broken}', 'BLOCK')}")
    print(f"  decisions       : {s['total']} total, {s['today']} today")
    print(f"  allowed/review/blocked : {s['allowed']}/{s['review']}/{s['blocked']}")
    print(f"  awaiting review : {s['pending_reviews']}")
    print(f"  quarantined     : {s['quarantined']}")
    print(f"  agents seen     : {s['agents']}")
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    from agentguard.review_queue import ReviewQueue

    q = ReviewQueue()
    if args.review_cmd == "list":
        items = q.list(None if args.all else "pending")
        if not items:
            print("review queue is empty")
            return 0
        table = [[str(i.id), i.ts[11:19], i.status, i.kind, i.tool or "-",
                  f"{i.score or 0:.2f}", (i.reason or "")[:44]] for i in items]
        print(_table(table, ["id", "time", "status", "kind", "tool", "score", "reason"]))
        return 0

    item_id = args.id
    item = q.approve(item_id) if args.review_cmd == "approve" else q.deny(item_id)
    if item is None:
        print(f"no review item #{item_id}", file=sys.stderr)
        return 1
    print(f"review #{item_id} -> {_c(item.status, 'ALLOW' if item.status == 'approved' else 'BLOCK')}")
    if item.kind == "memory_promotion" and item.status == "approved":
        from agentguard.quarantine import QuarantinedMemoryLedger
        qid = item.payload.get("quarantine_id")
        if qid:
            QuarantinedMemoryLedger().promote(int(qid))
            print(f"  promoted quarantined memory #{qid} to trusted memory")
    return 0


def cmd_memory(args: argparse.Namespace) -> int:
    from agentguard.quarantine import QuarantinedMemoryLedger

    ledger = QuarantinedMemoryLedger()
    if args.memory_cmd == "list-quarantine":
        items = ledger.list(status=None if args.all else "quarantined",
                            include_expired=args.all)
        if not items:
            print("nothing in quarantine")
            return 0
        for i in items:
            print(f"{_c('#' + str(i.id), 'bold')}  {_c(i.status, 'REVIEW')}  "
                  f"expires {i.expires_at or 'never (flagged)'}")
            print(f"   sources : {', '.join(i.source_tools) or 'unknown'}")
            print(f"   sink    : {i.tool}")
            print(f"   content : {i.content[:160]}")
            print()
        return 0

    if args.memory_cmd == "promote":
        item = ledger.get(args.id)
        if item is None:
            print(f"no quarantined item #{args.id}", file=sys.stderr)
            return 1
        # Promotion is a human decision, so show the provenance before doing it.
        print(_c("promoting quarantined memory - provenance:", "bold"))
        print(f"  captured : {item.ts}")
        print(f"  sources  : {', '.join(item.source_tools) or 'unknown'}")
        print(f"  session  : {item.session_id}")
        print(f"  content  : {item.content[:300]}")
        ledger.promote(args.id, approved_by=args.by)
        print(_c(f"\nitem #{args.id} promoted to trusted memory by {args.by}", "ALLOW"))
        return 0

    if args.memory_cmd == "deny":
        if ledger.deny(args.id) is None:
            print(f"no quarantined item #{args.id}", file=sys.stderr)
            return 1
        print(f"item #{args.id} denied and left out of trusted memory")
        return 0

    if args.memory_cmd == "trusted":
        rows = ledger.trusted_memory()
        if not rows:
            print("trusted memory is empty")
            return 0
        print(_table([[str(r["id"]), r["ts"][11:19], r["origin"],
                       (r["content"] or "")[:60]] for r in rows],
                     ["id", "time", "origin", "content"]))
        return 0
    return 1


def cmd_pins(args: argparse.Namespace) -> int:
    from agentguard.pinning import ToolPinStore

    store = ToolPinStore()
    if args.pins_cmd == "list":
        pins = store.all()
        if not pins:
            print("no tools pinned yet")
            return 0
        print(_table([[p["tool"], p["schema_hash"][:16], p["pinned_at"]] for p in pins],
                     ["tool", "hash", "pinned at"]))
        return 0
    store.unpin(args.tool)
    print(f"unpinned {args.tool} - it will be re-pinned on next sight")
    return 0


def resolve_enforcement(args: argparse.Namespace) -> tuple[bool | None, str]:
    """Decide enforcement and say where the decision came from.

    Precedence, most specific first:
      1. an explicit `--enforce` / `--observe` flag on this invocation
      2. `mode` in ~/.agentguard/agentguard.json (the installation default)
      3. `enforcement:` in agentguard.policy.yaml (returned as None so the policy
         loader keeps its own value)

    Two files can express enforcement, so the gateway prints which one won at
    startup rather than leaving the user to guess.
    """
    from agentguard import config as cfg

    if getattr(args, "enforce", False):
        return True, "--enforce flag"
    if getattr(args, "observe", False):
        return False, "--observe flag"
    try:
        if cfg.exists():
            config = cfg.load()
            return config.enforcement, f"mode: {config.mode} in {cfg.config_path()}"
    except cfg.ConfigError as exc:
        print(f"warning: ignoring unusable config ({exc})", file=sys.stderr)
    return None, "agentguard.policy.yaml"


def cmd_onboard(args: argparse.Namespace) -> int:
    from agentguard import config as cfg
    from agentguard.onboarding import onboard

    try:
        onboard(
            non_interactive=args.non_interactive,
            install_daemon_flag=args.install_daemon,
            activate=args.activate,
        )
    except cfg.ConfigError as exc:
        print(f"onboarding failed: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_configure(args: argparse.Namespace) -> int:
    from agentguard import config as cfg
    from agentguard.onboarding import configure

    try:
        configure(args.setting, args.value)
    except cfg.ConfigError as exc:
        print(f"configure failed: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    from agentguard import doctor

    report = doctor.run(args.policy)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0 if report.ok else 1

    print(_c("agentguard doctor", "bold"))
    print()
    status_colors = {"PASS": "ALLOW", "WARN": "REVIEW", "FAIL": "BLOCK"}
    print(doctor.render(report, lambda t, s: _c(t, status_colors.get(s, "dim"))))
    return 0 if report.ok else 1


def resolve_upstream(text: str) -> Any:
    """Turn `--upstream` into something FastMCP can connect to.

      path/to/server.py   run as a stdio server with this interpreter
      path/to/config.json an MCPConfig file ({"mcpServers": {...}}), e.g. the
                          upstream.mcp.json written by examples/safe_first_run.py
      {"mcpServers": ...} inline MCPConfig JSON
      anything else       passed through to FastMCP (http/https URLs)

    The .json-file form exists because inline JSON does not survive every shell:
    Windows PowerShell 5.1 strips the inner double quotes when passing it to a
    native program.
    """
    if text.endswith(".py"):
        return {"mcpServers": {"upstream": {"command": sys.executable, "args": [text]}}}
    if text.lower().endswith(".json"):
        config = json.loads(Path(text).read_text(encoding="utf-8"))
        if not isinstance(config, dict) or "mcpServers" not in config:
            raise ValueError("a .json upstream must be an MCPConfig with 'mcpServers'")
        return config
    if text.lstrip().startswith("{"):
        return json.loads(text)
    return text


def cmd_proxy(args: argparse.Namespace) -> int:
    from agentguard.gateway import run_gateway

    try:
        upstream = resolve_upstream(args.upstream) if args.upstream else None
    except (OSError, ValueError) as exc:
        print(f"proxy: cannot use --upstream {args.upstream!r}: {exc}", file=sys.stderr)
        return 1
    if upstream is None and args.transport == "stdio":
        print("proxy: --transport stdio needs --upstream", file=sys.stderr)
        return 1

    enforcement, source = resolve_enforcement(args)
    print(f"  enforcement decided by: {source}")
    try:
        run_gateway(upstream, port=args.port, transport=args.transport,
                    policy_path=args.policy, enforcement=enforcement,
                    agent=args.agent, role=args.role)
    except KeyboardInterrupt:
        # Ctrl+C is the normal way to stop the gateway, not an error.
        print("\nAgentGuard gateway stopped.")
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    import uvicorn

    from agentguard.dashboard import create_app

    print(f"AgentGuard dashboard -> http://127.0.0.1:{args.port}")
    try:
        uvicorn.run(create_app(), host="127.0.0.1", port=args.port, log_level="warning")
    except KeyboardInterrupt:
        print("\nAgentGuard dashboard stopped.")
    return 0


def cmd_simulate(args: argparse.Namespace) -> int:
    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples"))
    from mock_mcp_server import mcp as mock_upstream    # noqa: PLC0415

    from agentguard.gateway import build_gateway
    from agentguard.simulator import RedTeamSimulator

    policy = load_policy(args.policy)
    # The simulator measures the *enforcing* configuration - in observe mode
    # nothing is stopped, so every attack would trivially "pass" as allowed.
    policy.enforcement = True
    proxy, guard = build_gateway(mock_upstream, policy=policy, db_path=args.db)
    report = RedTeamSimulator(proxy, guard).run_sync()

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0

    print(_c("AgentGuard red-team simulation", "bold"))
    print()
    rows = []
    for r in report.results:
        mark = _c("PASS", "ALLOW") if r.passed else _c("FAIL", "BLOCK")
        rows.append([mark, r.scenario.category, r.scenario.name,
                     r.scenario.expect, r.observed])
    print(_table(rows, ["", "category", "scenario", "expected", "observed"]))

    print()
    print(f"  attacks detected     : {report.detection_rate:.0%} "
          f"({sum(r.passed for r in report.attacks)}/{len(report.attacks)})")
    print(f"  benign traffic clean : {report.clean_pass_rate:.0%} "
          f"({sum(r.passed for r in report.benign)}/{len(report.benign)})")
    print(f"  {_c('security score', 'bold')}       : "
          f"{_c(str(report.score) + '/100  grade ' + report.grade, 'bold')}")
    print(_c("\n  score = mean(detection, benign-clean), so blocking everything "
             "cannot inflate it.", "dim"))
    return 0 if report.score >= args.min_score else 1


def cmd_report(args: argparse.Namespace) -> int:
    from agentguard import report as report_mod

    try:
        report = report_mod.build(args.since)
    except ValueError as exc:
        print(f"report failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0

    print(_c("agentguard report", "bold"))
    print()
    print(report_mod.render(report, _c))
    if getattr(args, "by_source", False):
        print()
        print(report_mod.render_by_source(report, _c))
    return 0


def cmd_scope(args: argparse.Namespace) -> int:
    """Declared task scope. Human-only: there is no MCP path to this."""
    from agentguard.scope import ScopeStore, parse_tools

    store = ScopeStore(policy=load_policy(args.policy))
    if args.scope_cmd == "set":
        tools = parse_tools(args.tools)
        if not tools:
            print("scope set: --tools needs at least one pattern", file=sys.stderr)
            return 1
        scope = store.set(args.session, tools, goal=args.goal, set_by=args.by)
        print(f"scope for session {args.session}: {', '.join(scope.tools)}")
        if scope.goal:
            print(f"  goal: {scope.goal}")
        print(_c("  calls outside this scope will be held for REVIEW "
                 "(signal scope:outside)", "dim"))
        return 0

    if args.scope_cmd == "clear":
        if not store.clear(args.session):
            print(f"no scope set for session {args.session}", file=sys.stderr)
            return 1
        print(f"scope cleared for session {args.session}")
        return 0

    scopes = store.all()
    if args.session:
        one = store.get(args.session)
        scopes = {args.session: one} if one else {}
    if not scopes:
        print("no session scopes set (role defaults from the policy still apply)")
        return 0
    print(_table([[sid, ", ".join(s.tools), s.goal or "-", s.set_at or "-"]
                  for sid, s in scopes.items()],
                 ["session", "tools", "goal", "set at"]))
    return 0


def cmd_hook(args: argparse.Namespace) -> int:
    """Claude Code command hook: forward one event to the daemon (stdlib only)."""
    from agentguard.hookclient import main as hook_main

    return hook_main()


def _hook_scope(args: argparse.Namespace) -> str:
    from agentguard import hookinstall

    if getattr(args, "local", False):
        return hookinstall.SCOPE_LOCAL
    if getattr(args, "project", False):
        return hookinstall.SCOPE_PROJECT
    return hookinstall.SCOPE_USER


def cmd_install_hooks(args: argparse.Namespace) -> int:
    from agentguard import config as cfg
    from agentguard import hookinstall

    port = args.port
    if port is None:
        try:
            port = cfg.load().port
        except cfg.ConfigError:
            port = cfg.DEFAULT_PORT
    kind = args.type
    if args.fail_closed and kind == hookinstall.KIND_HTTP:
        print("note: HTTP hooks can't fail closed (Claude Code treats an unreachable "
              "HTTP hook as a non-blocking error); installing the command hook instead.")
        kind = hookinstall.KIND_COMMAND
    path = hookinstall.settings_path(_hook_scope(args))
    try:
        result = hookinstall.install(path, kind=kind, port=port, timeout=args.timeout)
    except hookinstall.HookInstallError as exc:
        print(f"install-hooks: {exc}", file=sys.stderr)
        return 1
    print(f"{result.path}: {result.message}")
    if result.backup:
        print(f"  backup: {result.backup}")
    if result.created:
        print("  (settings file did not exist; created it)")
    if args.fail_closed:
        try:
            config = cfg.load()
            config.hook_fail_mode = "closed"
            cfg.save(config)
            print("  hook_fail_mode set to closed in agentguard.json")
        except cfg.ConfigError as exc:
            print(f"  could not set hook_fail_mode: {exc}", file=sys.stderr)
    target = f"http://127.0.0.1:{port}/hooks/claude-code"
    print(f"  hooks send every PreToolUse/PostToolUse event to {target}")
    print("  start the daemon with `agentguard proxy` (or the background service),")
    print("  then check with `agentguard doctor`. New Claude Code sessions pick this up;")
    print("  running sessions normally do too, via Claude Code's settings file watcher.")
    return 0


def cmd_uninstall_hooks(args: argparse.Namespace) -> int:
    from agentguard import hookinstall

    path = hookinstall.settings_path(_hook_scope(args))
    try:
        result = hookinstall.uninstall(path)
    except hookinstall.HookInstallError as exc:
        print(f"uninstall-hooks: {exc}", file=sys.stderr)
        return 1
    print(f"{result.path}: {result.message}")
    if result.backup:
        print(f"  backup: {result.backup}")
    return 0


def cmd_daemon(args: argparse.Namespace) -> int:
    from agentguard import daemonctl

    if args.daemon_cmd == "status":
        status = daemonctl.status()
        print(daemonctl.render_status(status))
        return 0 if status.running else 1
    ok, message = daemonctl.stop()
    print(message)
    return 0 if ok else 1


_LOCK_LIMIT_NOTE = ("note: a lock stops traffic through the gateway. It does not revoke "
                    "credentials held by upstream servers - rotate those if they may be "
                    "compromised.")


def cmd_lock(args: argparse.Namespace) -> int:
    from agentguard.locks import LockStore

    store = LockStore()
    if args.status:
        active = store.active()
        if not active:
            print("no active locks")
            return 0
        print(_table([[str(lk.id), "ALL SESSIONS" if lk.is_global else lk.scope,
                       lk.locked_by or "-", lk.locked_at, lk.reason or "-"]
                      for lk in active],
                     ["id", "scope", "by", "since", "reason"]))
        return 0
    if args.all:
        store.lock_all(args.reason, args.by)
        print(_c("every session is locked", "BLOCK")
              + " - all tool calls through the gateway are refused, in observe mode too")
    else:
        store.lock_session(args.session, args.reason, args.by)
        print(_c(f"session {args.session} is locked", "BLOCK"))
    print(_c(_LOCK_LIMIT_NOTE, "dim"))
    print("release with `agentguard unlock " + ("--all`" if args.all
                                                 else f"--session {args.session}`"))
    return 0


def cmd_unlock(args: argparse.Namespace) -> int:
    from agentguard.locks import ALL, LockStore

    released = LockStore().release(ALL if args.all else args.session, args.by)
    if not released:
        print("nothing to unlock", file=sys.stderr)
        return 1
    print(f"released {released} lock(s)")
    return 0


def cmd_kill(args: argparse.Namespace) -> int:
    print("To stop every agent immediately, lock all sessions:")
    print()
    print("  agentguard lock --all [--reason ...]")
    print()
    print("Every running gateway on this machine checks for locks before each call,")
    print("and a lock blocks even in observe mode. `agentguard lock --session <id>`")
    print("locks one session; `agentguard unlock` releases.")
    print(_LOCK_LIMIT_NOTE)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agentguard",
        description="Local-first runtime security gateway for MCP-based AI agents.",
    )
    p.add_argument("--version", action="version", version=f"agentguard {__version__}")
    p.add_argument("--policy", default=None, help="path to agentguard.policy.yaml")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a string without starting a server")
    s.add_argument("text")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("status", help="show gateway and policy status")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("audit", help="show recent decisions")
    s.add_argument("--last", type=int, default=20)
    s.add_argument("--session", help="show the full attack-chain timeline for a session")
    s.add_argument("--verify", action="store_true", help="verify the hash chain")
    s.set_defaults(func=cmd_audit)

    s = sub.add_parser("review", help="human review queue")
    rs = s.add_subparsers(dest="review_cmd", required=True)
    ls = rs.add_parser("list"); ls.add_argument("--all", action="store_true")
    ap = rs.add_parser("approve"); ap.add_argument("id", type=int)
    dn = rs.add_parser("deny"); dn.add_argument("id", type=int)
    s.set_defaults(func=cmd_review)

    s = sub.add_parser("memory", help="quarantined memory ledger")
    ms = s.add_subparsers(dest="memory_cmd", required=True)
    lq = ms.add_parser("list-quarantine"); lq.add_argument("--all", action="store_true")
    pr = ms.add_parser("promote"); pr.add_argument("id", type=int)
    pr.add_argument("--by", default="human")
    dq = ms.add_parser("deny"); dq.add_argument("id", type=int)
    ms.add_parser("trusted")
    s.set_defaults(func=cmd_memory)

    s = sub.add_parser("pins", help="tool pins (rug-pull detection)")
    ps = s.add_subparsers(dest="pins_cmd", required=True)
    ps.add_parser("list")
    up = ps.add_parser("unpin"); up.add_argument("tool")
    s.set_defaults(func=cmd_pins)

    s = sub.add_parser("proxy",
                       help="run the daemon: Claude Code hook endpoint, plus the MCP "
                            "gateway when --upstream is given")
    s.add_argument("--port", type=int, default=9000)
    s.add_argument("--upstream", default=None,
                   help="upstream MCP server: a .py path, an http URL, an MCPConfig "
                        ".json file, or inline MCPConfig JSON. Omit it to serve only "
                        "the Claude Code hook endpoint")
    s.add_argument("--transport", default="http", choices=["http", "stdio"])
    s.add_argument("--enforce", action="store_true",
                   help="block/hold calls instead of only logging them")
    s.add_argument("--observe", action="store_true",
                   help="force observe/log-only mode, overriding the saved config")
    s.add_argument("--agent", default=None)
    s.add_argument("--role", default=None)
    s.set_defaults(func=cmd_proxy)

    s = sub.add_parser("dashboard", help="serve the local dashboard")
    s.add_argument("--port", type=int, default=9001)
    s.set_defaults(func=cmd_dashboard)

    s = sub.add_parser("simulate", help="run the red-team simulator and score coverage")
    s.add_argument("--json", action="store_true")
    s.add_argument("--db", default=None)
    s.add_argument("--min-score", type=int, default=0,
                   help="exit non-zero if the score is below this (for CI)")
    s.set_defaults(func=cmd_simulate)

    s = sub.add_parser(
        "report",
        help="summarise the audit log and list false-positive candidates",
    )
    s.add_argument("--since", default="7d",
                   help="window to report over: 7d, 24h, 90m, 2w (default: 7d)")
    s.add_argument("--json", action="store_true")
    s.add_argument("--by-source", action="store_true",
                   help="also break the numbers down by source (mcp gateway / hook)")
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("scope", help="declare which tools a session's task needs")
    ss = s.add_subparsers(dest="scope_cmd", required=True)
    st = ss.add_parser("set", help="set the scope for one session")
    st.add_argument("--session", required=True,
                    help="session id, as shown by `agentguard audit`")
    st.add_argument("--tools", required=True,
                    help='comma-separated tool globs, e.g. "filesystem.read*,web.search"')
    st.add_argument("--goal", default=None,
                    help="the task in plain words (used by the optional alignment auditor)")
    st.add_argument("--by", default="human")
    sh = ss.add_parser("show"); sh.add_argument("--session", default=None)
    sc = ss.add_parser("clear"); sc.add_argument("--session", required=True)
    s.set_defaults(func=cmd_scope)

    s = sub.add_parser("lock", help="refuse every tool call, now (all sessions or one)")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--all", action="store_true", help="lock every session")
    g.add_argument("--session", help="lock one session id")
    g.add_argument("--status", action="store_true", help="list active locks")
    s.add_argument("--reason", default="manual lock")
    s.add_argument("--by", default="human")
    s.set_defaults(func=cmd_lock)

    s = sub.add_parser("unlock", help="release a lock")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--all", action="store_true", help="release the global lock")
    g.add_argument("--session", help="release one session's lock")
    s.add_argument("--by", default="human")
    s.set_defaults(func=cmd_unlock)

    # --- Claude Code hooks -------------------------------------------------
    s = sub.add_parser("hook", help="Claude Code command hook: forward stdin to the daemon")
    s.set_defaults(func=cmd_hook)

    for name, func, text in (
        ("install-hooks", cmd_install_hooks,
         "register AgentGuard's hooks in Claude Code settings (backup + merge)"),
        ("uninstall-hooks", cmd_uninstall_hooks,
         "remove AgentGuard's hooks from Claude Code settings, keeping all others"),
    ):
        s = sub.add_parser(name, help=text)
        g = s.add_mutually_exclusive_group()
        g.add_argument("--project", action="store_true",
                       help="this project's .claude/settings.json instead of user settings")
        g.add_argument("--local", action="store_true",
                       help="this project's .claude/settings.local.json")
        if name == "install-hooks":
            s.add_argument("--type", choices=("http", "command"), default="http",
                           help="http (default, native) or command (stdlib fallback)")
            s.add_argument("--port", type=int, default=None,
                           help="daemon port (default: from agentguard.json)")
            s.add_argument("--timeout", type=int, default=None,
                           help="seconds Claude Code waits for the hook (default 5 http, "
                                "10 command)")
            s.add_argument("--fail-closed", action="store_true",
                           help="block tool calls when the daemon is unreachable "
                                "(forces the command hook)")
        s.set_defaults(func=func)

    s = sub.add_parser("daemon", help="status or stop of the background daemon")
    ds = s.add_subparsers(dest="daemon_cmd", required=True)
    ds.add_parser("status")
    ds.add_parser("stop")
    s.set_defaults(func=cmd_daemon)

    s = sub.add_parser("kill", help="how to revoke access immediately")
    s.set_defaults(func=cmd_kill)

    # --- distribution layer ------------------------------------------------
    s = sub.add_parser("onboard", help="first-time interactive setup")
    s.add_argument("--non-interactive", action="store_true",
                   help="accept every default without prompting")
    s.add_argument("--install-daemon", action="store_true",
                   help="write a background-service definition for this OS")
    s.add_argument("--activate", action="store_true",
                   help="with --install-daemon, also enable the service now")
    s.set_defaults(func=cmd_onboard)

    s = sub.add_parser("doctor", help="check the install for config and port problems")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_doctor)

    s = sub.add_parser("configure", help="change one setting without redoing onboarding")
    s.add_argument("setting", nargs="?", default=None,
                   help="port, mode, dashboard, dashboard_port or upstream")
    s.add_argument("value", nargs="?", default=None)
    s.set_defaults(func=cmd_configure)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
