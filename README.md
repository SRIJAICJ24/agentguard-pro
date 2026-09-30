# AgentGuard

A local-first runtime security gateway for AI agents using MCP.

AgentGuard sits between your AI agent (Claude Code, or any other MCP-based agent) and
the tools it can use — files, the web, email, databases, other MCP servers. It watches
every action live, blocks the dangerous ones, and remembers nothing you didn't approve.
Nothing leaves your machine.

**Status:** Stages 0 through 7 are implemented and tested. That's the full pipeline,
behaviour monitoring, the red-team simulator, the distribution layer, the validation
tooling, and the September 2026 threat update (worm detection, volume-aware DLP,
declared task scope, a financial tier with a global lock, and a
[standards mapping](docs/standards-mapping.md)). 290 tests pass. Every Stage 7 detector
ships observe-only like everything else. See
[What's built so far](#whats-built-so-far) for the honest breakdown.

**The open question is the false-positive rate on real traffic.** Every FP number
quoted here so far is synthetic. `agentguard report` exists to replace it with a
measured one — see [Measuring it on your own traffic](#measuring-it-on-your-own-traffic).

Built on [FastMCP](https://github.com/jlowin/fastmcp) (v3) rather than hand-rolled
JSON-RPC, and [`detect-secrets`](https://github.com/Yelp/detect-secrets) rather than
hand-written credential regexes.

---

## What it actually does

Think of it as antivirus for your AI agent, not a tool you have to operate:

- **Blocks obvious attacks automatically.** A credential path (`~/.ssh/id_rsa`, `.env`)
  or a live-looking API key in a tool argument is stopped before the call executes.
- **Notices when a tool changes behind your back.** Every tool's description and schema
  is hashed on first sight. A later change forces human review — this is the "rug pull"
  attack, and name-based allowlists miss it completely.
- **Protects your agent's memory, not just its actions.** If your agent tries to
  permanently remember something derived from an untrusted source, that memory is
  quarantined with an expiry instead of becoming trusted knowledge. **And the taint
  survives recall** — so it can't come back clean weeks later.
- **Stops prompt-injection worms from spreading.** When a web page tells your agent to
  "copy this into every file you write", and the agent does, the write is held. This
  applies to email, files, commits, comments, chat, and injections hidden inside code
  comments.
- **Notices bulk data leaving, not single addresses.** One email address in a message is
  correspondence. Two hundred in a CSV body is an export. Card numbers are Luhn-checked
  and Aadhaar numbers Verhoeff-checked, so random digit runs don't count.
- **Keeps the agent on task, and money under a human's control.** You can declare which
  tools a session's task needs. Every payment waits for a human, with a receipt in the
  audit chain. `agentguard lock --all` stops every session at once.
- **Catches your agent misbehaving, not just attackers.** A runaway loop hammering file
  deletes trips a velocity check against the learned baseline.
- **Keeps a real record.** Every decision is logged in a hash-chained audit table with a
  readable attack-chain timeline.
- **Lets you test yourself.** A red-team simulator throws known attack patterns at your
  own setup and scores your actual coverage.

---

## Quick start

```bash
pip install -e .
```

Run the red-team simulator against the bundled mock server — this needs no
configuration and proves the whole pipeline works end to end:

```bash
python -m agentguard.cli simulate
```

```
      category              scenario                          expected    observed
----  --------------------  --------------------------------  ----------  ----------
PASS  prompt_injection      injection_instruction_override    REVIEW      REVIEW
PASS  credential_access     cred_ssh_private_key              BLOCK       BLOCK
PASS  memory_poisoning      memory_poisoning_via_web          QUARANTINE  QUARANTINE
PASS  exfiltration          exfil_untrusted_content           REVIEW      REVIEW
PASS  benign                benign_reading_poisoned_page      ALLOW       ALLOW
...
  attacks detected     : 100% (10/10)
  benign traffic clean : 100% (6/6)
  security score       : 100/100  grade A
```

Scan a single string without starting anything:

```bash
python -m agentguard.cli scan "aws_secret_access_key=AKIAIOSFODNN7EXAMPLE"
```

Generate demo incidents and look at the dashboard:

```bash
AGENTGUARD_HOME=/tmp/ag-demo python examples/seed_demo.py
AGENTGUARD_HOME=/tmp/ag-demo agentguard dashboard
```

---

## Setting it up for real

Run the wizard once. Every question has a safe default, so you can hold Enter through
it — the default is observe-only, which never blocks anything.

```bash
agentguard onboard
```

It writes `~/.agentguard/agentguard.json` (how this installation runs) and a starter
`agentguard.policy.yaml` in the current directory (what the gateway allows). An
existing policy file is never overwritten.

Check the install before trusting it:

```bash
agentguard doctor
```

```
  PASS  dependencies    fastmcp 3.4.7, detect-secrets present
  PASS  config file     ~/.agentguard/agentguard.json (mode: observe, port: 9000)
  PASS  gateway port    port 9000 is free
  PASS  policy file     agentguard.policy.yaml parses (3 roles, observe (log only))
  PASS  audit database  ~/.agentguard/agentguard.db is reachable
  PASS  audit chain     hash chain verifies cleanly
```

Start the gateway in front of your real MCP server:

```bash
agentguard proxy --upstream https://your-real-mcp-server/mcp --port 9000
```

Then point Claude Code at AgentGuard instead of the server it used to talk to:

```bash
claude mcp add --transport http agentguard http://localhost:9000/mcp
```

**Start with enforcement off.** That is the default, and it is deliberate: in observe
mode every control still runs and every decision is still written to the audit log, but
nothing is blocked. Run your normal work through it for a few days, read
`agentguard audit --last 50`, and confirm the false-positive rate on *your* traffic is
acceptable. Only then turn blocking on:

```bash
agentguard configure mode enforce
```

To change one setting later without redoing the wizard:

```bash
agentguard configure port 9500
agentguard configure dashboard n
```

### Running it in the background

```bash
agentguard onboard --install-daemon
```

This writes the right service definition for your OS — a systemd user unit on Linux, a
launchd plist on macOS, a Task Scheduler launcher on Windows — and then prints the one
command to enable it. It does **not** start the service for you. Registering a
background process that intercepts your agent's tool calls is not something an install
wizard should do silently; add `--activate` if you want it enabled in the same step.

On Windows, `--activate` registers a logon task and starts it immediately. The task
runs the daemon with no console window, restarts it if it exits, and logs to
`~/.agentguard/daemon.log`. `agentguard daemon status` shows whether it's answering, and
`agentguard daemon stop` stops it without the launcher restarting it.

With no MCP upstream configured, the daemon serves only the Claude Code hook endpoint.
That is the setup for someone who uses Claude Code but no MCP servers.

---

## Claude Code hooks: seeing Claude Code's own tools

The MCP gateway only sees MCP traffic. Claude Code's built-in tools (`Bash`, `PowerShell`,
`Read`, `Write`, `Edit`, `WebFetch`, `WebSearch`, …) never go through MCP, and for most
people that's where the risk is. Claude Code's `PreToolUse` / `PostToolUse` hooks send those
calls to the AgentGuard daemon, which runs them through the same scanner, taint, sink,
propagation and DLP checks as the gateway.

```bash
agentguard proxy                 # the daemon: hook endpoint (+ MCP gateway with --upstream)
agentguard install-hooks         # register the hooks in your Claude Code user settings
agentguard doctor                # checks the hooks are installed AND the daemon answers
```

`install-hooks` merges into `~/.claude/settings.json` (or `CLAUDE_CONFIG_DIR`). It writes a
timestamped backup first, refuses a file that isn't valid JSON, keeps every other hook, and
is idempotent. `uninstall-hooks` removes only AgentGuard's entries. `--project` / `--local`
target this project's `.claude/settings.json` / `settings.local.json` instead.

| Tool | What AgentGuard checks |
|---|---|
| `Bash` / `PowerShell` | secrets and credential paths anywhere in the command. Network commands (`curl`, `wget`, `nc`, `scp`, `Invoke-WebRequest`, …) to hosts outside `hooks.allow_hosts` join the **exfiltration** tier. `git commit`/`push` and output redirected into files join the **propagation** tier. Recursive deletes and disk-level commands → **REVIEW**. All patterns live in `agentguard.policy.yaml` under `hooks.bash` |
| `Read` / `Write` / `Edit` | path denylist; secret scan on written content; writes join the propagation tier (worm detection, DLP) |
| `WebFetch` / `WebSearch` | results are **untrusted** and fingerprinted into the session's taint map, so a later `Write` or `curl` of that text is caught |
| MCP tools | gated by the hook, unless the server is routed through the AgentGuard gateway (`hooks.gateway_servers`), in which case only the gateway counts it |

**Observe mode never interferes.** Every call is logged (`source = hook` in the audit log),
and Claude Code's normal permission flow decides. In **enforce mode**, BLOCK → deny and
REVIEW → ask: Claude Code's own permission prompt is the review step, and an ask you
approve is counted in `report` as a false-positive candidate. AgentGuard never answers
"allow", because that would skip Claude Code's own prompts.

**If the daemon is down**, the HTTP hook fails open (Claude Code treats it as a non-blocking
error, and that can't be changed). If you need fail-closed, install the stdlib-only command
hook: `agentguard install-hooks --fail-closed`.

**Self-protection.** Writes, edits and shell commands that touch AgentGuard's config, policy
file, audit database, the Claude Code settings files that register the hooks, or that stop
the daemon go to REVIEW, and are denied in enforce mode. **This raises the bar; it does not
stop a determined process running as the same user.** Anything with your file permissions
can edit those files or kill the daemon by a route the patterns don't recognise, or while
the daemon isn't running.

Details, the verified hook schema, and what differed from expectations:
[docs/claude-code-hooks-notes.md](docs/claude-code-hooks-notes.md).

---

## How it works

```
Agent (Claude Code, or anything else)
          │
          ▼
     AgentGuard  ── FastMCP proxy + middleware, local only
          │
   ┌──────┴──────┐
   │  ALLOW      │ → forwarded to the real MCP server, response returned normally
   │  REVIEW     │ → held, queued for your decision
   │  BLOCK      │ → stopped, logged, agent gets an error
   └─────────────┘
          │
          ▼
   Real MCP servers
```

FastMCP's `on_call_tool` hook straddles the call, which maps onto the design's
lifecycle without any protocol code of our own:

| Lifecycle stage | Where | What runs |
|---|---|---|
| `TOOL_PREPARE` | before forwarding | kill switch / locks → policy deny → RBAC → control-plane guard → pin check → scanner → velocity → sink/taint → propagation → DLP → scope → financial → (optional) alignment auditor |
| `TOOL_EXECUTE` | forwarding | only if permitted |
| `TOOL_RESULT` | after forwarding | source classification, fingerprinting, quarantine recall hook |

Ordering is deliberate: cheap absolute checks (kill switch, explicit deny, RBAC) run
before anything expensive and before any score is computed. **A rule is not evidence to
be weighed against other evidence.** Scoring runs next; taint and sink analysis can then
only *raise* a verdict, never lower it.

---

## The Quarantined Memory Ledger

This is the part most security tools miss, and the reason this project exists.

An agent reads a poisoned web page, decides the content is worth remembering, and writes
it to durable memory. Every later session then treats attacker-authored text as its own
trusted knowledge. Blocking the write outright breaks legitimate memory; allowing it is
worse.

So a persistence-tier write carrying untrusted taint is neither blocked nor trusted — it
is **quarantined**:

- stored separately from trusted memory, never returned as trusted knowledge
- kept with full provenance: source tool, fingerprints, session, timestamp
- given a TTL, so unreviewed attacker text expires instead of accumulating
- **on recall, its taint labels are re-attached to the returned content**

That last property is what makes the ledger work rather than just being another
quarantine folder. Without it, an attacker only needs to wait one session: write in
session A, recall in session B, exfiltrate as "trusted" content. Because recall
re-taints, the session-B exfiltration attempt is still caught. There is a test for
exactly that chain
([`test_b_taint_survives_recall_and_blocks_later_exfiltration`](tests/test_stage25_taint_quarantine.py)).

Promotion to trusted memory requires an explicit human action and logs the full
provenance alongside the decision.

### Sink tiers

Every outgoing call lands in exactly one tier:

| Tier | Examples | Untrusted taint in the arguments means |
|---|---|---|
| `ordinary` | file read, search | logged only — **reading is never punished** |
| `exfiltration` | email send, web POST, webhook | REVIEW or BLOCK per policy |
| `persistence` | `memory.save`, vector writes, RAG updates | route to the quarantine ledger |

Persistence is checked before exfiltration, so a memory tool whose name also matches an
egress glob still reaches the ledger.

Stage 7 adds two more tiers. They are *additional* memberships: a call keeps its tier
above and can also be in these. `email.send` is both exfiltration and propagation, and
the stricter verdict wins.

| Tier | Examples | What it adds |
|---|---|---|
| `propagation` | file writes, git commits, PR/issue comments, document edits, chat posts, email | worm detection and DLP |
| `financial` | payments, purchases, checkout, refunds, transfers | always REVIEW; optional per-session cap; receipts |

---

## Stage 7: September 2026 threat update

Every feature here computes and logs by default. It stops calls only when `enforcement`
is on, and each can be switched off with `enabled: false` in the policy. Each one shows
up in `agentguard report` under its own signal name.

### Propagation (worm) detection: `propagation:replication`

A self-replicating injection doesn't need to steal anything. It only needs the agent to
copy it somewhere the *next* agent will read. The replication signature requires all
three of these:

1. The outgoing content overlaps untrusted content, from this session's taint map or
   rehydrated from the Quarantined Memory Ledger.
2. The **overlapping region itself** contains instruction-like text aimed at an AI
   reader: the scanner's injection patterns plus self-propagation phrasing ("when an
   agent reads this", "copy this into every file").
3. The destination is a propagation-tier sink.

All three give REVIEW. Overlap alone is normal (quoting a page into notes) and is logged
as `propagation:taint_overlap`. Instruction text with no untrusted overlap is left to the
existing scanner, unchanged. Comments in source code (`#`, `//`, `/* */`, `<!-- -->`,
docstrings) are extracted and checked as whole blocks, so a payload split across comment
lines inside a large file is still seen.

### Volume-aware DLP: `dlp:over_limit:<LABEL>`, `dlp:redacted`, `dlp:unscanned_attachment`

This runs on exfiltration and propagation sinks. It counts emails, phone numbers, cards
(Luhn-checked), PAN and Aadhaar numbers (Verhoeff-checked), then assigns a label:
PUBLIC < INTERNAL < CONFIDENTIAL < PII < SECRET. Each role has a maximum label per sink
tier. Anything above it triggers the configured action: `log`, `review`, `block` or
`redact`. `redact` swaps values for typed placeholders (`<EMAIL_1>`), and only the
redacted form reaches the upstream server. In observe mode it logs what it *would* have
redacted and rewrites nothing.

**Scope limit:** the gateway scans only content present in the arguments. An attachment
passed as a file path is not read. It's logged as `dlp:unscanned_attachment` so the gap
is visible.

### Declared task scope: `scope:outside`, `scope:tamper_attempt`

```bash
agentguard scope set --session <id> --tools "filesystem.read*,web.search" --goal "..."
```

A human sets the scope per session. You can also set a default per role with
`roles.<role>.scope`. Calls outside it are held for REVIEW. The scope lives in the
gateway's local database, and nothing on the MCP channel can change it. A call to any
tool in the reserved `agentguard*` namespace is refused and logged. An upstream
advertising such a tool is itself a red flag.

An optional `AlignmentAuditor` can also judge (declared goal, last N calls, proposed
call) on the deep path, using a **local** OpenAI-compatible endpoint such as Ollama. It's
off by default and refuses non-loopback endpoints unless `alignment.allow_remote: true`.
It adds `alignment:misaligned`, and failures fail open as `alignment:unavailable`.

### Financial tier and global lock: `financial:action`, `financial:cap_exceeded`, `lock:global`

Every financial call goes to the review queue regardless of score. An optional session
cap blocks a payment that would push the session's approved total over the limit; the
total is read from receipts, so it survives restarts. When an approved payment goes
through, a receipt joins the hash-chained audit log. It records agent, action, amount,
currency, payee, approver, policy rule and argument hash.

```bash
agentguard lock --all --reason "incident 42"   # every session, every gateway on this machine
agentguard unlock --all
```

A lock is a human command, not a detector, so it blocks **even in observe mode**. The
in-process kill switch follows the same rule. **A lock stops traffic through the
gateway. It cannot revoke credentials held by upstream servers.** Rotate those if they
may be compromised.

### Standards mapping

[`docs/standards-mapping.md`](docs/standards-mapping.md) maps each feature to the OWASP
Top 10 for LLM Applications 2026, the OWASP Top 10 for Agentic Applications (including
ASI06), and the OWASP Agent Control Standard v0.1.0. It has an explicit Gaps column.

---

## Two engineering decisions worth explaining

### `detect-secrets` is used in two tiers

`detect-secrets` ships 26 structural detectors (AWS, GitHub, JWT, private keys…) plus
two entropy detectors. The entropy detectors are built for scanning source *files*,
where surrounding filters suppress noise. Applied naively to a tool argument, they fire
constantly on ordinary prose — measured during this build, the string
`"the weather is nice in paris today"` produced **ten** entropy findings. Since a secret
finding pushes the risk score toward BLOCK, wiring the library in as-is would have made
the gateway unusable on real traffic long before it ever missed an attack.

So structural detectors always run at full weight, while the two entropy detectors run
only against text that already looks credential-bearing (`key=`, `token:`,
`password …`) and carry a lower weight. Real base64/hex secrets are still caught;
English sentences are not blocked. `test_scanner_is_quiet_on_ordinary_prose` guards this.

### Risk weights are calibrated so each signal decides its own verdict

The signal weights are set so a *conclusive* signal reaches BLOCK on its own, and a
*suggestive* one lands in REVIEW:

| Signal | Weight | Alone |
|---|---|---|
| structural secret (`AWS Access Key`) | 0.80 | BLOCK |
| denylisted credential path | 0.80 | BLOCK |
| gated entropy hit | 0.30 | REVIEW |
| injection phrasing | 0.35 | REVIEW |
| untrusted taint → exfiltration sink | 0.40 | REVIEW |
| tool pin mismatch | 0.50 | forces REVIEW regardless of score |
| propagation replication (7A) | 0.45 | REVIEW (floor) |
| alignment auditor: misaligned (7C, optional) | 0.35 | REVIEW |
| DLP over limit, out of scope, financial action (7B–7D) | 0 | verdict set by a floor (policy action), not by score |

Thresholds: `< 0.25` ALLOW, `> 0.75` BLOCK, between → REVIEW. All of it lives in named
constants in [`risk.py`](agentguard/risk.py), and
`test_structural_secret_alone_blocks_but_injection_alone_only_reviews` pins the
calibration so it can't drift silently.

---

## Measuring it on your own traffic

Enforcement is **off by default**. In observe mode every control still runs and every
decision is still logged — nothing is stopped. That is how you measure the
false-positive rate on your own traffic before the gateway is allowed to interrupt your
work.

**Start in a sandbox.** The first run against a real (non-mock) MCP server should point
at one low-risk server scoped to a disposable directory, so a mistake in either
direction costs nothing:

```bash
python examples/safe_first_run.py
```

See [examples/safe_first_run.md](examples/safe_first_run.md) for the full walkthrough.

Then leave it running against the servers you actually use, still in observe mode, for
about a week of normal work. Then ask for the number:

```bash
agentguard report --since 7d
```

```
  calls gated     : 412

  ALLOW      380   92.2%  #####################################
  REVIEW      24    5.8%  ##
  BLOCK        8    1.9%  #

  top signals by how many decisions they appeared in:
    path:**/.env                     9  (2.2% of calls)
    taint:exfiltration               6  (1.5% of calls)
    injection:instruction_override   4  (1.0% of calls)

  FALSE-POSITIVE CANDIDATES
  (interruptions a human cleared, with no block in the same session within 15m after)
    ...
    candidates            : 5
    as share of all calls : 1.21%
    as share of interrupts: 15.6%  (5/32)
```

A false-positive candidate is an interruption a human then cleared through the review
queue — the gateway was overruled. The check is deliberately bounded: a clearance is
only disqualified if a BLOCK follows it in the same session **within 15 minutes**. An
MCP session is a whole client connection and can stay open for hours, so an unbounded
"any later block" test would disqualify nearly every genuine false positive and bias
the number toward zero.

They are **candidates, not confirmed errors**. The report can see that a human
disagreed with the gateway; it cannot see whether the human was right. Read the list,
not just the percentage.

**Stage 7 signals to watch.** Run the validation week with these detectors on, in
observe mode, so their false-positive surface gets measured too:

| Signal | Detector | Effect when enforcing |
|---|---|---|
| `propagation:replication` | worm detection | REVIEW |
| `propagation:taint_overlap` | worm detection | none (logged only) |
| `dlp:over_limit:<LABEL>` | DLP | per `classification.actions` |
| `dlp:redacted` / `dlp:unscanned_attachment` | DLP | rewrite / none |
| `scope:outside` / `scope:tamper_attempt` | task scope | REVIEW / BLOCK |
| `alignment:misaligned` / `alignment:unavailable` | optional auditor | REVIEW / none |
| `financial:action` / `financial:cap_exceeded` | financial tier | REVIEW / BLOCK |
| `financial:currency_mismatch` / `financial:amount_unknown` | financial tier | none beyond the REVIEW |
| `lock:global` / `lock:session` | locks | BLOCK, in every mode |

That number decides what happens next:

- **Low, and the candidates look like genuine misfires** → tune those specific signals,
  then `agentguard configure mode enforce`.
- **High** → fix the scanner before enforcing anything. Turning on blocking with a noisy
  detector is how a security tool gets uninstalled.

---

## Everyday commands

```bash
agentguard onboard                   # first-time setup wizard
agentguard onboard --install-daemon  # also write a background-service definition
agentguard doctor                    # check config, ports, policy, audit chain
agentguard configure <setting> <val> # change one setting (port/mode/dashboard/upstream)
agentguard report --since 7d         # FP candidates + verdict mix over a window
agentguard status                    # mode, policy, counters, audit-chain integrity
agentguard scan "<text>"             # one-off check, no server
agentguard audit --last 20           # recent decisions
agentguard audit --session <id>      # full attack-chain timeline for one session
agentguard audit --verify            # verify the hash chain
agentguard review list               # what's awaiting your approval
agentguard review approve <id>       # approve a queued call (single-use)
agentguard memory list-quarantine    # memories held in quarantine
agentguard memory promote <id>       # promote to trusted memory, with provenance
agentguard memory trusted            # what's in trusted memory
agentguard pins list                 # pinned tool hashes
agentguard scope set --session <id> --tools "a*,b" [--goal "..."]   # declare a task scope
agentguard scope show | clear --session <id>
agentguard lock --all | --session <id> | --status   # refuse every call, now
agentguard unlock --all | --session <id>
agentguard dashboard                 # local web UI
agentguard simulate                  # red-team run + security score
agentguard proxy --upstream <target> # run the gateway (+ hook endpoint)
agentguard proxy                     # hook endpoint only (no MCP servers)
agentguard install-hooks [--project|--local] [--type command] [--fail-closed]
agentguard uninstall-hooks [--project|--local]
agentguard daemon status | stop      # the background daemon
agentguard report --since 7d --by-source   # mcp gateway vs Claude Code hooks
```

The audit-chain timeline is genuinely readable:

```
attack-chain timeline for session ec102491
   ALLOW  TOOL_PREPARE   web.search      no signals
   ALLOW  TOOL_RESULT    web.search      untrusted result from 'web.search' fingerprinted
 ! REVIEW TOOL_PREPARE   memory.save     persistence-tier write quarantined as #1 (sources: web.search)
 ! REVIEW TOOL_PREPARE   email.send      taint:exfiltration | sink tier: exfiltration
```

---

## Configuration

There are two files, and they answer different questions:

| File | Scope | Holds |
|---|---|---|
| `~/.agentguard/agentguard.json` | this machine | port, mode, dashboard on/off — written by `agentguard onboard` |
| `agentguard.policy.yaml` | this project | what the gateway allows: rules, roles, tiers, thresholds |

The policy file is project-local (searched upward from the working directory) and
belongs in version control next to the code it protects. The JSON config is machine-local
and does not. `AGENTGUARD_HOME` overrides where the config and database live.

Both can express enforcement, so precedence is explicit and the gateway prints which
source it used at startup:

1. `--enforce` / `--observe` on the command line
2. `mode` in `agentguard.json`
3. `enforcement:` in `agentguard.policy.yaml`

The policy file holds every security tunable: enforcement, thresholds, tool allow/deny, per-role
permissions, path denylists, which tools count as untrusted sources, sink tiers, and
quarantine TTLs. See the shipped [`agentguard.policy.yaml`](agentguard.policy.yaml) —
it is commented throughout.

A note on RBAC semantics: **deny is evaluated first and always wins.** A non-empty
`allow` list is already deny-by-default, so adding `deny: ["*"]` alongside one cancels
the allow list entirely rather than acting as a backstop.

---

## The security score

`agentguard simulate` runs known attack patterns through a real MCP client against the
live gateway, then scores what actually happened.

The score is deliberately hard to game:

- An attack scenario passes only if the gateway reached **at least** the expected
  verdict. Detecting-but-allowing is a failure.
- A **benign** scenario passes only if it was ALLOWED.
- The score is `mean(detection_rate, benign_pass_rate)`.

So a gateway configured to deny every tool detects 100% of attacks, destroys 100% of
legitimate traffic, and scores **50** — not 100. There are tests for both degenerate
configurations (`test_score_punishes_a_block_everything_gateway`,
`test_score_punishes_a_disabled_gateway`). A security score that rewarded blocking
everything would be worse than no score at all.

---

## Testing

```bash
python -m pytest tests/ -q
```

290 tests, one file per stage. The ones that matter most are the four attack
reproductions in
[`tests/test_stage25_taint_quarantine.py`](tests/test_stage25_taint_quarantine.py):

| Test | Asserts |
|---|---|
| (a) `test_a_poisoned_web_result_save_is_quarantined` | a poisoned page's "routing rule" is quarantined, **not** written to trusted memory |
| (b) `test_b_taint_survives_recall_and_blocks_later_exfiltration` | a *new* session recalls it, taint is re-attached, the exfiltration is stopped |
| (c) `test_c_user_stated_preference_goes_to_trusted_memory` | a legitimate preference reaches trusted memory, unaffected |
| (d) `test_d_merely_reading_untrusted_content_is_not_blocked` | reading a poisoned page is **not** punished — only unsafe *use* |

The Stage 7A worm reproductions in
[`tests/test_stage7a_propagation.py`](tests/test_stage7a_propagation.py) assert the
`propagation:replication` signal itself, not just a REVIEW verdict:

| Test | Channel |
|---|---|
| `test_a_worm_forwarded_by_email_is_flagged` | email |
| `test_b_worm_written_to_a_file_is_flagged` | file write |
| `test_c_worm_hidden_in_a_code_comment_is_flagged` | code comment, split across lines of a ~300-line file |
| `test_d_worm_saved_to_memory_then_recalled_and_written_is_flagged` | memory, across sessions |
| `test_e_quoting_a_web_snippet_into_notes_is_logged_not_reviewed` | benign control |
| `test_f_ordinary_code_with_ordinary_comments_is_not_flagged` | benign control |

Run the suite with `AGENTGUARD_HOME` pointed at a temporary directory. Some tests and
`simulate` write to the default database.

---

## What's built so far

- [x] **Stage 0** — FastMCP proxy scaffold, passthrough verified against a real MCP client
- [x] **Stage 1** — two-tier `detect-secrets` scanner, path denylist, injection patterns, risk engine, YAML policy, hash-chained audit log, CLI
- [x] **Stage 2** — tool pinning with description diffs, RBAC per agent identity, single-use approval queue, dashboard
- [x] **Stage 2.5** — taint engine (n-gram shingles), sink classifier, Quarantined Memory Ledger with taint-surviving recall
- [x] **Stage 3** — velocity baselines with per-window training, kill switch
- [x] **Stage 4** — red-team simulator, anti-gameable security score
- [x] **Stage 5** — onboarding wizard, `doctor`, `configure`, daemon definitions for systemd/launchd/Task Scheduler
- [x] **Stage 6** — safe first-run sandbox, `agentguard report` with false-positive candidates
- [x] **Stage 7A** — propagation tier, replication signature, code-comment extraction, 4 worm scenarios in the simulator (22 scenarios, 100/100)
- [x] **Stage 7B** — volume-aware DLP: Luhn/Verhoeff-validated entities, labels, per-role limits, `redact`, unscanned-attachment signal
- [x] **Stage 7C** — declared task scope (CLI and per-role), control-plane tamper guard, optional local AlignmentAuditor (off by default)
- [x] **Stage 7D** — financial tier, session cap, hash-chained payment receipts, `lock --all` / `unlock`
- [x] **Stage 7E** — [standards mapping](docs/standards-mapping.md) with a Gaps column
- [x] **Readiness A** — Claude Code hooks (HTTP endpoint + stdlib command fallback), tool mapping for Bash/PowerShell/Read/Write/Edit/WebFetch/WebSearch/MCP, gateway↔hook taint bridge, observe/enforce mapping, self-protection, `install-hooks`/`uninstall-hooks`, `source` column with a chain-preserving migration, `report --by-source`, hooks-only daemon that restarts on Windows
- [ ] **The validation week itself** — not yet run. This is the gate on everything below. Stage 7 detectors and the hooks should be measured in the same week.
- [ ] Packaged install (`pipx install agentguard` once published to PyPI)

### Known limitations, stated plainly

- **Taint matching is shingle-based.** It catches verbatim and near-verbatim
  copy-through, which is how the documented memory-poisoning and exfiltration chains
  actually behave. An agent that heavily *paraphrases* untrusted content before using it
  can fall below the overlap threshold. Lowering `SHINGLE_SIZE` raises recall and false
  positives together.
- **Tool pinning is trust-on-first-use.** AgentGuard cannot know whether a description
  was already malicious before it was first seen; it establishes a baseline and detects
  *change* from it.
- **The security score measures coverage of known patterns**, not of novel attacks. It
  tells you whether your configuration holds against the scenarios in the library — no
  more than that.
- **Behaviour baselines are in-process** and reset when the gateway restarts.
- **Not yet run for a sustained period against live traffic.** The design's own bar for
  "a v1 worth showing" includes a week in observe mode on real sessions, and Stage 5's
  own precondition was a few days of real traffic before polishing the install
  experience. Neither has happened yet. The only false-positive evidence so far is the
  simulator's eight benign controls and the scanner's prose tests — that is a floor, not a
  measurement of your traffic. This is exactly why enforcement ships off by default.
- **Daemon definitions are generated but only smoke-tested cross-platform.** They are
  written and asserted on for Linux, macOS and Windows, but have only been executed on
  Windows.
- **Worm detection inherits the shingle limit.** A payload the agent rewrites in its own
  words won't overlap the untrusted source. The phrasing patterns are English-only, and
  requiring a spreading quantifier ("into *every* file") trades recall for fewer false
  positives on tutorials.
- **DLP reads arguments only.** Attachments passed by path aren't opened. Phone-number
  patterns cover Indian, E.164 (`+`-prefixed) and North American formats, not every
  national format.
- **Scope needs a session id.** It comes from `agentguard audit` after the session
  starts. Per-role defaults avoid that step.
- **Observe mode really is observe mode for payments.** A financial call is logged and
  queued, but it still executes. Receipts exist only for approvals made while enforcing.
- **Locks don't revoke upstream credentials.** They stop traffic through the gateway,
  nothing more.
- **The fast path has a known hot spot that predates Stage 7.** detect-secrets scans
  every line, so a 200-line file write costs about 30 ms in the Stage 1 scanner, well
  over the 5 ms target. Typical calls stay around 1.5–3 ms depending on machine load.
  Stage 7 adds about 0.2–0.8 ms to typical calls (roughly 15–20% of the fast path, part
  of it two small SQLite reads for locks and scope) and about 3–5 ms to that large write.
- **`*email*` in the default exfiltration globs also matches `email.read*`.** A mail
  *read* whose arguments carry tainted text is therefore treated as egress. This dates
  from Stage 2.5 and is left unchanged.
- **Hooks see tool calls, not intent.** A Bash command is judged by its text. A script
  that does the damage internally (`python do_it.py`) looks harmless to the command
  patterns. Self-protection is pattern-based and raises the bar only; it does not stop a
  determined process running as your user.
- **Hook latency is real.** Measured on this Windows machine, the HTTP hook costs about
  7–8 ms p50 per call when the connection is reused and about 22–31 ms when each call opens
  a new one (whether Claude Code reuses connections isn't documented). A 200-line `Write`
  costs about 48–63 ms, mostly the Stage 1 detect-secrets pass. The command-hook fallback
  costs about 290 ms per call, most of it starting Python.
- **The gateway↔hook taint bridge is correlation, not identity.** It links an MCP call to a
  Claude Code session only when the hook saw the identical call in the previous 30 s, and
  links nothing when that's ambiguous.
- **In observe mode a lock doesn't stop Claude Code's own tools.** Observe mode never answers
  "deny", by design. The MCP gateway still honours locks in every mode.

---

## Project layout

```
agentguard/
  decision.py    Verdict / Signal / Decision vocabulary
  db.py          SQLite schema and per-thread connections
  audit.py       hash-chained audit log + timeline queries
  scanner.py     two-tier secrets, path denylist, injection patterns, redaction
  risk.py        weighted signals -> score -> verdict
  policy.py      YAML policy, RBAC rules, sink tiers
  identity.py    AgentIdentity + RBACPolicy
  pinning.py     tool hash pinning + description diffs
  review_queue.py human-in-the-loop queue, single-use approvals
  taint.py       shingle fingerprints, session-scoped TaintMap
  sinks.py       ordinary / exfiltration / persistence classification
  quarantine.py  the Quarantined Memory Ledger
  behavior.py    velocity baselines + kill switch
  middleware.py  the whole pipeline, in order
  gateway.py     FastMCP proxy entrypoint
  dashboard.py   FastAPI + server-rendered HTML
  simulator.py   red-team scenarios + scoring
  config.py      ~/.agentguard/agentguard.json load/save/validate
  doctor.py      preflight checks with actionable hints
  onboarding.py  onboard/configure wizards + daemon definitions
  report.py      audit-log summary + false-positive candidates
  propagation.py worm detection: replication signature, comment extraction   (7A)
  classify.py    volume-aware DLP, Luhn/Verhoeff, labels, redaction          (7B)
  scope.py       declared task scope + control-plane namespace               (7C)
  alignment.py   AlignmentAuditor interface, no-op default, local adapter    (7C)
  financial.py   financial tier, amount/payee extraction, receipts           (7D)
  locks.py       CLI-set locks honoured by every running gateway             (7D)
  hooks.py       Claude Code hook engine: tool mapping, taint bridge          (A)
  hookclient.py  `agentguard hook`: stdlib-only command hook                  (A)
  hookinstall.py install/uninstall hooks in Claude Code settings              (A)
  daemonctl.py   `agentguard daemon status|stop`                              (A)
  cli.py         command line interface
docs/BUILD_PROMPTS.md       the staged build specification
docs/standards-mapping.md   OWASP LLM 2026 / Agentic Top 10 / ACS mapping
docs/claude-code-hooks-notes.md   verified hook schema + design notes
examples/mock_mcp_server.py
examples/safe_first_run.py + .md   disposable sandbox for the first real run
tests/           290 tests, one file per stage
```

This is v2 of an earlier hackathon project ("Agent-Guard").
