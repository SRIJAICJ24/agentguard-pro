"""What a pip install gets: the `agentguard` package and nothing else.

Regression: `agentguard simulate` imported examples/mock_mcp_server.py from the
source tree, so it crashed with ModuleNotFoundError from any installed wheel
(found on the week 1 frozen install).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def child_pythonpath(*first: str | os.PathLike[str], drop: Path | None = None) -> str:
    """PYTHONPATH for a child process: `first`, then the parent's own import path
    (minus `drop`), so dependencies stay importable however they were installed -
    a venv, the user site under a temporary HOME, or PYTHONPATH itself."""
    keep = []
    for p in sys.path:
        if not p or not os.path.isdir(p):
            continue
        if drop is not None and Path(p).resolve() == drop.resolve():
            continue
        keep.append(p)
    return os.pathsep.join([*(str(f) for f in first), *keep])


def test_simulate_runs_with_only_the_package_installed():
    work = Path(tempfile.mkdtemp(prefix="ag-pkg-"))
    try:
        site = work / "site"
        shutil.copytree(ROOT / "agentguard", site / "agentguard",
                        ignore=shutil.ignore_patterns("__pycache__"))
        home = work / "home"
        home.mkdir()
        env = {**os.environ, "PYTHONPATH": child_pythonpath(site, drop=ROOT), "AGENTGUARD_HOME": str(home),
               "HOME": str(home), "CLAUDE_CONFIG_DIR": str(home / "claude")}
        out = subprocess.run(
            [sys.executable, "-m", "agentguard.cli", "simulate", "--db", str(home / "sim.db"),
             "--min-score", "100"],
            cwd=work, env=env, capture_output=True, text=True, timeout=300)
        assert out.returncode == 0, out.stdout[-2000:] + out.stderr[-2000:]
        assert "100/100" in out.stdout
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_the_examples_path_still_works_for_docs_and_tests():
    import mock_mcp_server

    from agentguard import mock_upstream

    assert mock_mcp_server is mock_upstream, "one module, so _MEMORY is shared"
    assert mock_mcp_server.WORM_PAYLOAD


def test_the_examples_script_still_starts_a_server():
    out = subprocess.run([sys.executable, str(ROOT / "examples" / "mock_mcp_server.py"), "--help"],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0 and "--transport" in out.stdout, out.stderr
