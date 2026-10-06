# Security policy

AgentGuard is a security tool, so a flaw in it can leave someone thinking they are protected
when they aren't. Reports are welcome, including ones that "only" show a bypass.

## Reporting a vulnerability

Please don't open a public issue for a vulnerability. Use GitHub's private
vulnerability reporting ("Report a vulnerability" under the repository's Security tab).
Include:

- what you did: the exact tool call, command or transcript line, with secrets replaced;
- what AgentGuard decided (`agentguard audit --last 5` shows the signals);
- what you expected it to decide, and why it matters.

A small, self-contained reproduction helps most. A test that fails in the style of
`tests/test_week2_accuracy.py` is the best kind.

There's no bug bounty. This is a volunteer project, and response times are best-effort.

## What counts as a vulnerability

- A **bypass of a hard-enforced rule** (`credential_files`, `secret_exfiltration`,
  `self_protection`) that a typical agent could stumble into or be talked into.
- A **secret reaching the audit log, an export or the review queue** unredacted.
- Anything that lets a tool call **modify AgentGuard's own state** (policy, audit chain,
  locks, scope) through the MCP gateway or a hook.
- A **crash or hang that makes the hook fail open** on ordinary input.

## What doesn't (documented limits)

These are described under "Known limitations" in the README. Reports that move one of them
forward are still welcome as ordinary issues:

- Paraphrased content evading shingle-based taint tracking.
- A program doing the damage internally (`python do_it.py`) rather than in the command line.
- A determined process running as the same user disabling AgentGuard. Self-protection
  raises the bar; it is not a sandbox.
- Observe mode not blocking. That is its purpose.

## Supported versions

Only the latest commit on the default branch. There are no releases yet.
