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


def test_mcp_dependencies_are_capped_at_the_tested_major():
    """Regression (first GitHub CI run, 2026-10-10): `fastmcp>=3.0` let a fresh
    install resolve fastmcp 4.1 / mcp 2.3, under which the MCP gateway silently
    stopped enforcing (32 failures; the demo printed NOT BLOCKED). Each MCP
    dependency must have an upper bound until a new major is tested."""
    import tomllib

    from packaging.requirements import Requirement

    deps = {Requirement(d).name: Requirement(d)
            for d in tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
            ["project"]["dependencies"]}
    for name, untested in (("fastmcp", "4.0"), ("mcp", "2.0")):
        assert name in deps, f"{name} must be declared directly, with a cap"
        assert untested not in deps[name].specifier, f"{name} {untested} is not tested"
        assert any(s.operator == "<" for s in deps[name].specifier), name
