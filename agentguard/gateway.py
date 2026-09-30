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


def run_gateway(
    upstream: Any,
    *,
    port: int = 9000,
    transport: str = "http",
    policy_path: str | Path | None = None,
    db_path: str | None = None,
    enforcement: bool | None = None,
    agent: str | None = None,
    role: str | None = None,
) -> None:
    """Start the gateway and serve until interrupted."""
    identity = AgentIdentity.from_env()
    if agent:
        identity.name = agent
    if role:
        identity.role = role

    proxy, guard = build_gateway(
        upstream, policy_path=policy_path, identity=identity,
        db_path=db_path, enforcement=enforcement,
    )
    mode = "ENFORCING" if guard.policy.enforcement else "OBSERVE (log only)"
    print(f"AgentGuard gateway -> upstream {upstream!r}")
    print(f"  mode      : {mode}")
    print(f"  identity  : {identity.name} (role: {identity.role})")
    print(f"  policy    : {guard.policy.source_path or '<defaults>'}")
    if transport == "stdio":
        proxy.run()
    else:
        print(f"  listening : http://127.0.0.1:{port}/mcp")
        proxy.run(transport="http", port=port)
