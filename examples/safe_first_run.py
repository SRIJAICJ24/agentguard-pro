"""Build a disposable sandbox for AgentGuard's first run against a REAL MCP server.

Up to now the gateway has only ever been pointed at `examples/mock_mcp_server.py`,
where nothing it does can matter. The first run against a real server is the risky
one, and it is risky in both directions:

  * under-blocking - a missed detection touches something that actually matters
  * over-blocking  - a false positive interrupts real work and erodes trust in the
                     tool before it has earned any

So the first real upstream should be one server, scoped to a directory that is
worthless. This script creates that directory, fills it with harmless files plus a
decoy credential file, and prints the exact commands to run.

    python examples/safe_first_run.py

Nothing here touches your real project tree.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

SANDBOX_FILES: dict[str, str] = {
    "notes.md": (
        "# Sandbox notes\n\n"
        "This directory exists only to give AgentGuard a real MCP server to sit in\n"
        "front of. Nothing in here matters. Delete it whenever you like.\n"
    ),
    "report.txt": (
        "Quarterly summary, revision q3-2026-final-v2.\n"
        "Ordinary prose with version-looking tokens, which is exactly the shape of\n"
        "text a naive entropy scanner flags. This file should always be ALLOWED.\n"
    ),
    "src/app.py": (
        "def main():\n"
        '    """Ordinary source file - reading this should always be allowed."""\n'
        "    print('hello from the sandbox')\n"
    ),
    "src/config.yaml": "service: demo\nreplicas: 2\ntimeout_seconds: 30\n",
    # A decoy. Fake values, but shaped like the real thing, so the first BLOCK you
    # ever see happens somewhere it cannot hurt.
    ".env": (
        "# FAKE credentials for testing AgentGuard. Not real. Not valid anywhere.\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "DATABASE_PASSWORD=not-a-real-password-just-a-decoy\n"
    ),
}


def build_sandbox(directory: Path, force: bool = False) -> Path:
    if directory.exists():
        if not force:
            print(f"{directory} already exists; re-run with --force to recreate it.")
            return directory
        shutil.rmtree(directory)

    for relative, content in SANDBOX_FILES.items():
        target = directory / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return directory


def upstream_config(directory: Path) -> dict:
    """MCPConfig for a filesystem MCP server scoped to the sandbox.

    The scoping is the safety property, and it is enforced twice over: the
    filesystem server itself refuses paths outside the roots it was started with,
    and AgentGuard's own denylist sits in front of that. Neither is trusted alone.
    """
    return {
        "mcpServers": {
            "files": {
                "command": "npx",
                "args": [
                    "-y",
                    "@modelcontextprotocol/server-filesystem",
                    str(directory.resolve()),
                ],
            }
        }
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a disposable sandbox for AgentGuard's first real run."
    )
    parser.add_argument("--dir", default="agentguard-sandbox",
                        help="where to build the sandbox (default: ./agentguard-sandbox)")
    parser.add_argument("--force", action="store_true",
                        help="delete and recreate the sandbox if it already exists")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()

    directory = Path(args.dir).resolve()
    build_sandbox(directory, force=args.force)

    config = upstream_config(directory)
    config_file = directory / "upstream.mcp.json"
    config_file.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    print(f"sandbox ready: {directory}")
    print(f"  {len(SANDBOX_FILES)} files, including a FAKE .env decoy")
    print(f"  upstream config written to {config_file}")
    print()
    print("1. Start the gateway in OBSERVE mode (nothing will be blocked):")
    print()
    # The config-file form works in every shell; inline JSON does not survive
    # Windows PowerShell 5.1, which strips the inner double quotes.
    print(f"   python -m agentguard.cli proxy --observe --port {args.port} "
          f"--upstream \"{config_file}\"")
    print()
    print("2. Point Claude Code at AgentGuard rather than the filesystem server:")
    print()
    print(f"   claude mcp add --transport http agentguard "
          f"http://localhost:{args.port}/mcp")
    print()
    print("3. Ask your agent to do ordinary things in the sandbox - read notes.md,")
    print("   summarise report.txt, list src/. Then ask it to read .env, which is")
    print("   the decoy.")
    print()
    print("4. See what the gateway would have done:")
    print()
    print("   agentguard audit --last 30")
    print("   agentguard report --since 1d")
    print()
    print("Nothing outside this directory is reachable: the filesystem server is")
    print("started with the sandbox as its only root. Delete it when you are done:")
    print(f"   rm -rf {directory}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
