# Contributing

Thanks for helping. AgentGuard is judged on two numbers: how many real attacks it stops,
and how often it interrupts real work for nothing. A change should move one of them
without hurting the other, and should show evidence for both.

## Setup

```bash
python -m pip install -e ".[dev]"
```

**Never run tests or `simulate` against your real home.** Point AgentGuard and Claude Code at
throwaway folders in the same shell:

```bash
export AGENTGUARD_HOME="$(mktemp -d)" CLAUDE_CONFIG_DIR="$(mktemp -d)"
python -m pytest tests -q
python -m agentguard.cli simulate --min-score 100
```

On Windows PowerShell, set `$env:AGENTGUARD_HOME` and `$env:CLAUDE_CONFIG_DIR` to new folders
under `$env:TEMP` first.

## Rules for changes

1. **Every bug fix comes with a regression test, and the test has to fail without the fix.**
   Say in the pull request how you checked that. For example, run the new test file
   against `git archive HEAD` in a temp folder.
2. **Detection changes bump `DETECTOR_VERSION`.** `tests/test_readiness_e.py` fingerprints
   the detection modules and fails until you bump the version in `agentguard/versions.py`
   and paste in the new fingerprint. Every audit row records the version, so numbers from
   different versions are never mixed silently.
3. **False-positive fixes need a measurement.** Run `agentguard replay` on your own
   transcripts before and after the change (it is read-only), and put the before/after
   counts in the pull request. Include the attack cases that must still fire. Each
   "quiet" case in `tests/test_week2_accuracy.py` sits next to a "still caught" case.
4. **No secret-shaped literals in new code or tests.** Build fake keys at run time (see
   `_token()` in `tests/test_week2_accuracy.py`) so secret scanners and push protection
   don't trip on the repository.
5. **Extend, don't rewrite.** Keep public behaviour, signal names and the audit hash chain
   compatible. If a test's expectation has to change, explain why in the pull request.
6. **Claims need evidence.** In docs, a number must be one you measured, with how you
   measured it. "Not measured" is a fine thing to write.

## Where things are

`README.md` has the project layout. Detection logic lives in the modules listed in
`agentguard/versions.py` (`DETECTION_MODULES`). `docs/week-log.md` records each frozen
measurement install.
