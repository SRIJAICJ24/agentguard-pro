"""The mock upstream MCP server, at the path the docs and tests use.

The server itself lives in the package (agentguard/mock_upstream.py) so that
`agentguard simulate` works from a pip install, where examples/ isn't shipped.
Importing this module gives the very same module object, so its state
(`_MEMORY`) is shared; running it as a script starts the server.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from agentguard import mock_upstream as _server
except ImportError:                       # run from a checkout without installing
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from agentguard import mock_upstream as _server

if __name__ == "__main__":
    _server.main()
else:
    sys.modules[__name__] = _server
