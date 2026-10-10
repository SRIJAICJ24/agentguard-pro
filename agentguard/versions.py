"""Which detector and which policy produced a decision.

A week of measurement only means something if every decision in it was made by
the same detection logic under the same rules. Each audit row therefore records:

  detector_version  DETECTOR_VERSION below. It must be bumped whenever detection
                    logic changes. That rule is enforced, not just stated: the
                    test suite fingerprints the detection code and fails when the
                    fingerprint no longer matches DETECTOR_FINGERPRINT, telling you
                    to bump the version and record the new fingerprint.
  policy_version    a short hash of the loaded policy's contents, so editing
                    agentguard.policy.yaml mid-week is visible too.

`agentguard report` shows the mix of versions in its window and warns when there
is more than one, so a mid-week change can't silently blend into one number.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Any

#: Bump on any change to detection logic (see module docstring). Format:
#: YYYY.MM.N - the date of the change plus a counter.
DETECTOR_VERSION = "2026.10.5"

#: The fingerprint of the detection code DETECTOR_VERSION describes. When the
#: fingerprint test fails, bump DETECTOR_VERSION and paste the new value here.
DETECTOR_FINGERPRINT = "1d80675375f3"

#: Modules whose code decides verdicts. Comments, docstrings and formatting
#: don't count (the fingerprint is taken over the syntax tree); code does.
DETECTION_MODULES: tuple[str, ...] = (
    "scanner", "risk", "taint", "sinks", "propagation", "classify", "hooks",
    "middleware", "policy", "scope", "financial", "behavior", "quarantine",
    "pinning", "identity", "locks", "decision", "shellcmd",
)


def _strip_docstrings(tree: ast.AST) -> ast.AST:
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and \
                    isinstance(getattr(body[0], "value", None), ast.Constant) and \
                    isinstance(body[0].value.value, str):
                node.body = body[1:] or [ast.Pass()]
    return tree


def _canonical(node: Any) -> str:
    """A syntax-tree dump that is the same on every supported Python version.

    `ast.dump` is not: Python 3.13 leaves out fields that are None or empty lists,
    and 3.12 added `type_params`, so the same code fingerprinted differently on
    3.12 and 3.13 (found on the first Linux run). Empty fields are skipped here
    on every version.
    """
    if isinstance(node, ast.AST):
        fields = []
        for name in node._fields:
            value = getattr(node, name, None)
            if value is None or (isinstance(value, list) and not value):
                continue
            fields.append(f"{name}={_canonical(value)}")
        return f"{type(node).__name__}({','.join(fields)})"
    if isinstance(node, list):
        return "[" + ",".join(_canonical(item) for item in node) + "]"
    return repr(node)


def detector_fingerprint(package_dir: Path | None = None) -> str:
    """Hash of the detection modules' syntax trees (comments/docstrings ignored)."""
    base = package_dir or Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for name in DETECTION_MODULES:
        source = (base / f"{name}.py").read_text(encoding="utf-8")
        tree = _strip_docstrings(ast.parse(source))
        digest.update(name.encode())
        digest.update(_canonical(tree).encode())
    return digest.hexdigest()[:12]


def policy_version(policy: Any) -> str:
    """Short hash of everything in a policy that affects verdicts.

    Excludes `enforcement` (recorded separately as the row's mode) and
    `source_path` (moving the file doesn't change the rules).
    """
    if policy is None:
        return "none"
    try:
        data = dataclasses.asdict(policy)
    except TypeError:
        return "unknown"
    data.pop("enforcement", None)
    data.pop("source_path", None)
    canonical = json.dumps(data, sort_keys=True, default=str, separators=(",", ":"))
    return "p-" + hashlib.sha256(canonical.encode()).hexdigest()[:10]
