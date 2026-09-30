"""Gateway entrypoint: a FastMCP proxy with AgentGuard middleware attached.

Built on FastMCP's proxy primitive rather than hand-rolled JSON-RPC. FastMCP
already handles MCP protocol correctness, so AgentGuard is a middleware layer on
top of it - less code to get wrong, and it stays current as MCP evolves.

The upstream can be an in-process FastMCP server (tests), a stdio command, an HTTP
URL, or an MCPConfig dict describing several servers at once.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastmcp import Client, FastMCP
from fastmcp.server import create_proxy
from fastmcp.server.providers.proxy import ProxyClient

from agentguard.identity import AgentIdentity
from agentguard.middleware import AgentGuardMiddleware
from agentguard.policy import Policy, load as load_policy


def build_gateway(
    upstream: Any,
    *,
    policy: Policy | None = None,
    policy_path: str | Path | None = None,
    identity: AgentIdentity | None = None,
    db_path: str | None = None,
    enforcement: bool | None = None,
    name: str = "agentguard",
) -> tuple[FastMCP, AgentGuardMiddleware]:
    """Wrap `upstream` in a guarded proxy.

    Returns the proxy and the middleware instance, since tests and the dashboard
    both need to inspect live gateway state (taint maps, counters, kill switch).
    """
    pol = policy or load_policy(policy_path)
    guard = AgentGuardMiddleware(
        pol, identity=identity, db_path=db_path, enforcement=enforcement
    )
    proxy = create_proxy(_client_for(upstream), name=name)
    proxy.add_middleware(guard)
    return proxy, guard


def _client_for(upstream: Any) -> Any:
    """Wrap `upstream` so the proxy never forwards `roots/list` upstream.

    FastMCP's default proxy client answers a downstream server's `roots/list`
    request by forwarding it to whatever client is connected to the proxy
    itself. Over the gateway's HTTP transport that forwarded request has
    nowhere reliable to go before the triggering tool call has finished, so
    the whole call hangs forever (confirmed against a real
    `@modelcontextprotocol/server-filesystem`; see tests/test_stage0_proxy.py).
    Declaring an empty roots list up front makes the client answer locally
    instead, matching AgentGuard's model that scoping is the upstream
    server's job (its own CLI args / config), not something the gateway
    hands it via MCP roots.
    """
    if isinstance(upstream, Client):
        return upstream
    return ProxyClient(upstream, roots=[])


HOOK_PATH = "/hooks/claude-code"
HOOK_HEALTH_PATH = "/hooks/health"
DAEMON_HOST = "127.0.0.1"


def build_daemon(
    upstream: Any = None,
    *,
    policy: Policy | None = None,
    policy_path: str | Path | None = None,
    identity: AgentIdentity | None = None,
    db_path: str | None = None,
    enforcement: bool | None = None,
    name: str = "agentguard",
) -> tuple[FastMCP, AgentGuardMiddleware | None, Any]:
    """The long-running AgentGuard process: hook endpoint, plus the MCP gateway
    when an upstream is given.

    One process on one port, so the gateway and the hook engine share state: the
    hook's correlation index lets the gateway see the taint of the Claude Code
    session that made an MCP call. Without an upstream (someone who uses no MCP
    servers) the daemon serves the hook endpoint alone.
    """
    from agentguard.hooks import HookBridge, HookEngine

    pol = policy or load_policy(policy_path)
    if enforcement is not None:
        pol.enforcement = enforcement
    engine = HookEngine(pol, db_path=db_path, identity=identity)

    guard: AgentGuardMiddleware | None = None
    if upstream is not None:
        server, guard = build_gateway(upstream, policy=pol, identity=identity,
                                      db_path=db_path, name=name)
        guard.hook_bridge = HookBridge(engine.correlation, engine.taints)
    else:
        server = FastMCP(name)
    attach_hook_routes(server, engine)
    return server, guard, engine


def attach_hook_routes(server: FastMCP, engine: Any) -> None:
    """POST /hooks/claude-code (the hook) and GET /hooks/health (for doctor)."""
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response

    @server.custom_route(HOOK_PATH, methods=["POST"])
    async def claude_code_hook(request: Request) -> Response:
        try:
            payload = await request.json()
        except ValueError:
            # Non-2xx is a non-blocking error to Claude Code: the call proceeds.
            return JSONResponse({"error": "body is not JSON"}, status_code=400)
        try:
            reply = engine.handle(payload)
        except Exception as exc:                                # noqa: BLE001
            # Never take the agent down with the gateway: an internal error
            # renders no decision (fail-open) and is reported, not raised.
            print(f"AgentGuard hook error: {type(exc).__name__}: {exc}")
            return Response(status_code=200)
        # 2xx with an empty body = "no decision", the normal permission flow.
        return JSONResponse(reply) if reply else Response(status_code=200)

    @server.custom_route(HOOK_HEALTH_PATH, methods=["GET"])
    async def hook_health(request: Request) -> Response:
        return JSONResponse({"ok": True, "service": "agentguard",
                             "mode": "enforce" if engine.enforcing else "observe"})


def run_gateway(
    upstream: Any = None,
    *,
    port: int = 9000,
    transport: str = "http",
    policy_path: str | Path | None = None,
    db_path: str | None = None,
    enforcement: bool | None = None,
    agent: str | None = None,
    role: str | None = None,
) -> None:
    """Start the daemon and serve until interrupted."""
    identity = AgentIdentity.from_env()
    if agent:
        identity.name = agent
    if role:
        identity.role = role

    if upstream is None and transport == "stdio":
        raise ValueError("stdio transport needs --upstream (there is nothing to proxy)")

    server, guard, engine = build_daemon(
        upstream, policy_path=policy_path, identity=identity,
        db_path=db_path, enforcement=enforcement,
    )
    mode = "ENFORCING" if engine.enforcing else "OBSERVE (log only)"
    if upstream is not None:
        print(f"AgentGuard gateway -> upstream {upstream!r}")
    else:
        print("AgentGuard daemon (Claude Code hooks only - no MCP upstream)")
    print(f"  mode      : {mode}")
    print(f"  identity  : {identity.name} (role: {identity.role})")
    print(f"  policy    : {engine.policy.source_path or '<defaults>'}")
    if transport == "stdio":
        server.run()
        return
    if upstream is not None:
        print(f"  mcp       : http://{DAEMON_HOST}:{port}/mcp")
    print(f"  hooks     : http://{DAEMON_HOST}:{port}{HOOK_PATH}")
    with _PidFile():
        server.run(transport="http", host=DAEMON_HOST, port=port)


class _PidFile:
    """Write the daemon's pid to AGENTGUARD_HOME/daemon.pid while it runs, so
    `agentguard daemon stop` can find it."""

    def __enter__(self) -> None:
        import os

        from agentguard.config import agentguard_home

        self.path = agentguard_home() / "daemon.pid"
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(str(os.getpid()), encoding="utf-8")
        except OSError:
            self.path = None

    def __exit__(self, *exc: Any) -> None:
        if self.path is not None:
            try:
                self.path.unlink()
            except OSError:
                pass
