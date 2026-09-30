"""A minimal stdio MCP server that requests `roots/list` as soon as its
session finishes initializing - mimicking `@modelcontextprotocol/server-
filesystem`, which asks the connected client for its roots right after the
handshake and falls back gracefully if the client can't answer.

Written against the low-level `mcp` server API (rather than FastMCP's
high-level one) because that's the only way to get a handle on the
`ServerSession` early enough to fire `list_roots()` at that exact point in
the lifecycle - the same point at which AgentGuard's proxy forwards the
request upstream. Used by test_stage0_proxy.py to reproduce, without
depending on npx/node, the hang fixed in agentguard/gateway.py's
`_client_for`.
"""

from __future__ import annotations

import sys

import anyio
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.session import InitializationState, ServerSession
from mcp.server.stdio import stdio_server

server: Server = Server("fake-roots-server")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="echo",
            description="Echo the given text back.",
            inputSchema={
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    return [types.TextContent(type="text", text=f"echo: {arguments.get('text')}")]


async def _request_roots_once_ready(session: ServerSession) -> None:
    while session._initialization_state != InitializationState.Initialized:
        await anyio.sleep(0.01)
    try:
        await session.list_roots()
    except Exception as e:  # the real filesystem server does the same
        print(f"Failed to request initial roots from client: {e}", file=sys.stderr)


async def main() -> None:
    init_options = server.create_initialization_options()
    async with stdio_server() as (read_stream, write_stream):
        async with ServerSession(read_stream, write_stream, init_options) as session:
            async with anyio.create_task_group() as tg:
                tg.start_soon(_request_roots_once_ready, session)
                async for message in session.incoming_messages:
                    tg.start_soon(server._handle_message, message, session, None, False)


if __name__ == "__main__":
    anyio.run(main)
