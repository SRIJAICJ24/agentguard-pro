"""Things that must not depend on the OS or the Python version.

Found on the first Linux run (WSL Ubuntu, Python 3.12): the detector fingerprint
was computed with `ast.dump`, whose output changed in Python 3.13 (empty fields
omitted), so identical code had a different fingerprint on 3.12 and 3.13 and the
version guard failed on every Python but the author's.
"""

from __future__ import annotations

import ast


def test_canonical_dump_is_pinned():
    from agentguard.versions import _canonical

    assert _canonical(ast.parse("x = 1")) == \
        "Module(body=[Assign(targets=[Name(id='x',ctx=Store())],value=Constant(value=1))])"


def test_canonical_dump_ignores_empty_fields_however_a_version_spells_them():
    from agentguard.versions import _canonical

    a = ast.parse("def f(x):\n    return x\n")
    b = ast.parse("def f(x):\n    return x\n")
    fn = b.body[0]
    fn.type_params = []                      # 3.12+ spelling of "no type params"
    fn.returns = None
    fn.type_comment = None
    if hasattr(a.body[0], "type_params"):
        del a.body[0].type_params            # pre-3.12 shape
    assert _canonical(a) == _canonical(b)


def test_fingerprint_does_not_use_ast_dump(monkeypatch):
    """ast.dump is the version-dependent part; the fingerprint must not call it."""
    from agentguard import versions

    def boom(*_a, **_k):
        raise AssertionError("ast.dump is Python-version dependent")

    monkeypatch.setattr(versions.ast, "dump", boom)
    assert len(versions.detector_fingerprint()) == 12
