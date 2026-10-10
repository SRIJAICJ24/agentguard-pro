## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Evidence

- [ ] **Bug fix:** a regression test that fails without the fix. How I checked:
      <!-- e.g. ran the new test against `git archive HEAD` in a temp folder: N failed -->
- [ ] **Detection change:** `DETECTOR_VERSION` and `DETECTOR_FINGERPRINT` bumped in
      `agentguard/versions.py`
- [ ] **False-positive change:** `agentguard replay` totals before / after:
      <!-- calls, flagged, hard-blocked, taint events -->
- [ ] The attack cases this area must still catch still pass (name them)
- [ ] No secret-shaped literals; fake keys are built at run time

## Checks

- [ ] `python -m pytest tests -q` with `AGENTGUARD_HOME` and `CLAUDE_CONFIG_DIR` pointed at temp folders
- [ ] `python -m agentguard.cli simulate --min-score 100`
- [ ] Docs: any number I added is one I measured, and says how
