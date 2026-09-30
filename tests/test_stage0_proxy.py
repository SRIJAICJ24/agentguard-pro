"""Stage 0 - proxy topology.

The only claim here: a real MCP client talking through the gateway gets exactly
what the upstream server would have returned directly.
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
import socket
import sys
import tempfile
from pathlib import Path

import pytest
from fastmcp import Client

from conftest import text_of

FAKE_ROOTS_SERVER = Path(__file__).resolve().parent / "fake_roots_server.py"
NPX_AVAILABLE = shutil.which("npx") is not None


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def test_proxy_forwards_call_unchanged(upstream, gateway):
    """A call through the proxy matches a call straight to the upstream."""
    proxy, _guard = gateway

    async with Client(upstream) as direct:
        expected = text_of(await direct.call_tool("filesystem.read", {"path": "notes.txt"}))

    async with Client(proxy) as through:
        actual = text_of(await through.call_tool("filesystem.read", {"path": "notes.txt"}))

    assert actual == expected
    assert "notes.txt" in actual


async def test_proxy_exposes_upstream_tools(gateway):
    """Tool discovery passes through, descriptions included."""
    proxy, _guard = gateway
    async with Client(proxy) as client:
        tools = {t.name: t for t in await client.list_tools()}

    assert {"filesystem.read", "web.search", "memory.save", "email.send"} <= set(tools)
    assert tools["filesystem.read"].description


async def test_second_tool_also_forwards(gateway):
    proxy, _guard = gateway
    async with Client(proxy) as client:
        out = text_of(await client.call_tool("web.search", {"query": "asyncio tutorial"}))
    assert "asyncio tutorial" in out


async def test_gateway_records_decisions(gateway, db_path):
    """Every forwarded call leaves an audit entry - the proxy is never silent."""
    from agentguard import audit

    proxy, _guard = gateway
    async with Client(proxy) as client:
        await client.call_tool("filesystem.read", {"path": "notes.txt"})

    rows = audit.last(10, db_path)
    assert any(r["tool"] == "filesystem.read" for r in rows)
    intact, broken = audit.verify_chain(db_path)
    assert intact, f"audit chain broken at {broken}"


async def test_client_for_declares_no_roots():
    """The fix, isolated: the gateway must never let FastMCP's default proxy
    roots handler forward `roots/list` upstream to the connected caller.

    FastMCP's `ProxyClient` defaults to forwarding a downstream server's
    `roots/list` request to whoever is connected to the gateway itself. Over
    the gateway's HTTP transport that forwarded request can be sent before
    the caller's SSE listener is attached and is never delivered - the
    triggering tool call then hangs forever waiting on a reply nobody sends
    (confirmed against a real `@modelcontextprotocol/server-filesystem`; see
    `test_proxy_does_not_hang_with_real_filesystem_server` below). Declaring
    an empty roots list up front makes the client answer `roots/list`
    locally instead, so the request never leaves the proxy. This test checks
    that wiring directly, since the end-to-end hang is a timing-sensitive
    race that isn't reliably forced by a lightweight fake server.
    """
    from fastmcp.server.providers.proxy import ProxyClient

    from agentguard.gateway import _client_for

    client = _client_for({"mcpServers": {"f": {"command": sys.executable, "args": ["-c", "pass"]}}})

    assert isinstance(client, ProxyClient)
    # The roots handler is wrapped into a session kwarg at construction time,
    # so exercise it rather than reach for private state.
    callback = client._session_kwargs["list_roots_callback"]
    result = await callback(None)
    assert result.roots == []


@pytest.mark.skipif(not NPX_AVAILABLE, reason="requires npx/node to run a real MCP server")
async def test_proxy_does_not_hang_with_real_filesystem_server(db_path):
    """End-to-end regression test for the `roots/list` hang, against the real
    `@modelcontextprotocol/server-filesystem` - the server this was first
    found against. Without the fix in `agentguard.gateway._client_for`, this
    call hangs indefinitely and the `wait_for` below raises `TimeoutError`.
    """
    from agentguard.gateway import build_gateway

    sandbox = tempfile.mkdtemp(prefix="agentguard-roots-test-")
    try:
        (Path(sandbox) / "notes.md").write_text("hello from sandbox", encoding="utf-8")

        port = _free_port()
        upstream = {"mcpServers": {"files": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", sandbox],
        }}}
        proxy, _guard = build_gateway(upstream, db_path=db_path, enforcement=False)

        server_task = asyncio.create_task(
            proxy.run_async(transport="http", port=port, host="127.0.0.1", show_banner=False)
        )
        try:
            await asyncio.sleep(1.5)  # let uvicorn bind before connecting
            async with Client(f"http://127.0.0.1:{port}/mcp") as client:
                result = await asyncio.wait_for(
                    client.call_tool("read_file", {"path": "notes.md"}), timeout=30
                )
            assert "hello from sandbox" in text_of(result)
        finally:
            server_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await server_task
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


async def test_proxy_forwards_calls_with_fake_roots_requesting_server(db_path):
    """Sanity check that a fake stdio server which requests roots (no
    npx/node dependency) still gets a fast, correct answer through the fixed
    gateway. Doesn't reproduce the historical hang on its own (the hang is a
    timing-sensitive race that only reproduces reliably against a real,
    variable-latency server - see the npx-based test above), but guards the
    general mechanism for any roots-requesting stdio server.
    """
    from agentguard.gateway import build_gateway

    port = _free_port()
    upstream = {"mcpServers": {"roots": {
        "command": sys.executable, "args": [str(FAKE_ROOTS_SERVER)],
    }}}
    proxy, _guard = build_gateway(upstream, db_path=db_path, enforcement=False)

    server_task = asyncio.create_task(
        proxy.run_async(transport="http", port=port, host="127.0.0.1", show_banner=False)
    )
    try:
        await asyncio.sleep(1.0)
        async with Client(f"http://127.0.0.1:{port}/mcp") as client:
            result = await asyncio.wait_for(
                client.call_tool("echo", {"text": "hello"}), timeout=15
            )
        assert "hello" in text_of(result)
    finally:
        server_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await server_task
