# Safe first run against a real MCP server

Every run so far has been against `examples/mock_mcp_server.py`, where nothing
AgentGuard does can matter. The first run against a *real* server is the one worth
being careful about, and it is risky in both directions:

- **under-blocking** — a missed detection touches something that actually matters
- **over-blocking** — a false positive interrupts real work, and the tool loses your
  trust before it has earned any

Both failures are cheap if the only thing on the other side of the gateway is a
directory you'd be happy to delete. So: **one** real server, scoped to a disposable
directory, in observe mode.

---

## 1. Build the sandbox

```bash
python examples/safe_first_run.py
```

This creates `./agentguard-sandbox/` containing:

| File | Why it's there |
|---|---|
| `notes.md`, `report.txt` | ordinary prose — should always be ALLOWED |
| `src/app.py`, `src/config.yaml` | ordinary source — should always be ALLOWED |
| `.env` | a **decoy** with fake credentials — this is the one that should trip |
| `upstream.mcp.json` | the upstream config, written for you |

The `.env` values are fake and valid nowhere. It exists so that the first BLOCK you
ever see happens somewhere it cannot hurt.

---

## 2. Start the gateway in observe mode

The script prints the exact command. It looks like this:

```bash
python -m agentguard.cli proxy --observe --port 9000 --upstream "agentguard-sandbox/upstream.mcp.json"
```

`--upstream` accepts the `upstream.mcp.json` file the script wrote. Inline JSON also
works in bash, but not in Windows PowerShell 5.1, which strips the inner double quotes.

Two things make this safe:

1. **The upstream is scoped.** The filesystem MCP server is started with the sandbox
   as its only root and refuses paths outside it. That containment comes from the
   server, not from AgentGuard — so it holds even if AgentGuard misses something.
2. **`--observe` means nothing is blocked.** Every control still runs and every
   decision is still written to the audit log; the call goes through regardless.
   Over-blocking cannot cost you anything yet, because there is no blocking.

Two independent layers, neither trusted on its own.

---

## 3. Point your agent at AgentGuard

```bash
claude mcp add --transport http agentguard http://localhost:9000/mcp
```

Then use the agent normally against the sandbox. Ask it to read `notes.md`,
summarise `report.txt`, list `src/`. Then ask it to read `.env`.

---

## 4. Read what happened

```bash
agentguard audit --last 30
agentguard report --since 1d
```

What you're checking:

- The ordinary reads show `ALLOW`. If any of them show `REVIEW` or `BLOCK`, that is a
  false positive, and it is the whole reason for running this before enforcing.
- The `.env` read shows `BLOCK` (score 0.80, signal `path:**/.env`). If it doesn't,
  that's a miss — check your policy's `paths.deny` list.

---

## 5. Then leave it running

Point the gateway at the MCP servers you actually use day to day, still with
`--observe`, and leave it for about a week of normal work. Then:

```bash
agentguard report --since 7d
```

That gives a false-positive candidate count and rate from **your** traffic, which is
the number that decides what happens next:

- **Low, and the candidates look like genuine misfires** → tune those specific
  signals, then turn enforcement on with `agentguard configure mode enforce`.
- **High** → fix the scanner before enforcing anything. Turning on blocking with a
  noisy detector is how a security tool gets uninstalled.

The report calls them *candidates*, not confirmed false positives, because it can
only see that a human overruled the gateway — not whether the human was right. Read
the list; don't just read the percentage.

---

## Cleaning up

```bash
rm -rf agentguard-sandbox
claude mcp remove agentguard
```

---

## A note on scoping

Do not skip the sandbox and point the first run at your real project tree, even in
observe mode. Observe mode protects you from AgentGuard over-blocking; it does
nothing about a filesystem server that can read your whole home directory. The
scoping is the part that makes the first run safe — the observe flag only makes it
non-disruptive.
