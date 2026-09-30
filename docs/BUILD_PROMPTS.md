# AgentGuard — Master Build Prompts for Claude Code
*Consolidates: System Design v1 + Research Analysis & Novel Architecture into an executable build sequence*
August 2026

---

## 0. Two things this research pass changes about implementation

**Use FastMCP, not raw FastAPI/JSON-RPC, as the gateway base.** FastMCP (PrefectHQ) is the de facto standard Python framework for MCP — it is very widely used and powers a large share of MCP servers — and, critically, it natively supports proxying and composing existing MCP servers. This means AgentGuard doesn't hand-roll JSON-RPC/MCP protocol handling — it builds a middleware layer on top of FastMCP's proxy primitive. Less code, spec-correct by construction, easier to keep current as MCP evolves.

**Use `detect-secrets` (Yelp, open source), not hand-rolled regex, for the secret/PII detector.** It detects secrets using regex and entropy heuristics, has a plugin API for custom detectors, and scans current content rather than full git history, which keeps it fast enough for a live request path. Wire it in as a library dependency in the fast-path scanner instead of writing your own credential-pattern regexes from scratch.

Everything else from the two prior docs (threat model, phased plan, distribution model, Quarantined Memory Ledger) stands as designed.

---

## 1. Consolidated architecture (one page, for Claude Code's context)

```
Agent (Claude Code, or anything else) ──▶ AgentGuard (FastMCP proxy) ──▶ Real MCP servers

Inside AgentGuard, every tool call passes through:

  FAST PATH (deterministic, <5ms target)
     ├─ detect-secrets scan of arguments
     ├─ denylist path/pattern check
     └─ risk_score < threshold? → ALLOW
                                 → else → DEEP PATH / REVIEW

  TAINT ENGINE (runs on every TOOL RESULT, not just calls)
     ├─ classify source: TRUSTED (user, pinned local files)
     │                   UNTRUSTED (web, email, external MCP, RAG)
     ├─ fingerprint content (n-gram shingles, no model call)
     └─ store in session-scoped taint map

  SINK CLASSIFIER (runs on every TOOL CALL argument)
     ├─ ordinary sink       → log only
     ├─ exfiltration sink   → untrusted taint present? → REVIEW/BLOCK
     └─ PERSISTENCE sink (memory_save, vector writes)
            └─ untrusted taint present?
                   yes → QUARANTINE TIER (TTL, tagged, not trusted memory)
                   no  → trusted memory, normal write

  POLICY / RBAC — per-agent-identity allow/deny rules, least privilege
  AUDIT LOG — every decision, hash-chained, attack-chain timeline for dashboard
```

Five-stage lifecycle from the original design (INPUT → TOOL_PREPARE → TOOL_EXECUTE → TOOL_RESULT → OUTPUT) still holds — the taint engine hooks in at TOOL_RESULT, the sink classifier at TOOL_PREPARE.

---

## 2. Build sequence

| Stage | Deliverable | Depends on |
|---|---|---|
| 0 | Scaffold + FastMCP proxy passthrough, no logic yet | — |
| 1 | Fast-path scanner + policy engine + audit log + CLI | 0 |
| 2 | Tool pinning + RBAC + approval queue + minimal dashboard | 1 |
| **2.5** | **Taint engine + sink classifier + Quarantined Memory Ledger** | 2 |
| 3 | Behavior baseline + anomaly + kill switch | 2.5 |
| 4 | Red-team simulator + benchmark scoring | 3 |

**How to actually use the prompts below:** paste one stage at a time into Claude Code. Wait for its tests to pass before pasting the next. Don't paste Stage 2 while Stage 1 is still failing — each stage's prompt assumes the previous one's code exists and works.

---

## 3. Stage 0 — Scaffold

> Initialize a Python project called `agentguard` using FastMCP (PrefectHQ's `fastmcp` package, not the raw `mcp` SDK) as the base for a proxy server. Structure: `agentguard/` package with `gateway.py` (the FastMCP proxy entrypoint), `cli.py`; `examples/mock_mcp_server.py` — a minimal real FastMCP server exposing two tools, `filesystem.read(path: str)` and `web.search(query: str)`, both returning fake data; `tests/`.
>
> Use FastMCP's proxying support so that `agentguard/gateway.py` sits in front of `examples/mock_mcp_server.py` and currently just passes every call through unmodified — no security logic yet, this stage only proves the proxy topology works end to end with a real MCP client making real calls through it.
>
> Add a CLI command `agentguard proxy --port 9000 --upstream <mock server address>`.
>
> Write a test that starts the mock server, starts the proxy pointed at it, calls `filesystem.read` through the proxy using an MCP client, and asserts the response matches what the mock server would have returned directly.
>
> Write a README stating this is v2 of an earlier hackathon project ("Agent-Guard") and that Stage 0 is proxy plumbing only — no security logic yet.

---

## 4. Stage 1 — Fast-path scanner, policy engine, audit log, CLI

> Building on the Stage 0 scaffold, add:
>
> 1. `agentguard/scanner.py` — a fast-path scanner run on every tool call's arguments before forwarding. Integrate the `detect-secrets` library as a dependency for credential/PII detection (don't hand-write secret regexes — call detect-secrets' scanning API against the argument text). Add a separate denylist check for filesystem paths (`~/.ssh/**`, `~/.aws/**`, `**/.env`, `**/credentials/**`) using simple glob matching, kept independent of the secrets library since it's a different signal.
> 2. `agentguard/risk.py` — combine scanner findings into a single risk score using explicit weighted signals (e.g. secret detected +0.4, denylisted path +0.3, unknown destination +0.15), and map score ranges to a decision: ALLOW below 0.25, REVIEW 0.25–0.75, BLOCK above 0.75. Keep the weights as named constants, not magic numbers, so they're easy to tune later.
> 3. `agentguard/policy.py` — load a YAML policy file (`agentguard.policy.yaml`) with per-tool allow/deny rules, checked before the risk score is even computed (an explicit deny always wins regardless of score).
> 4. `agentguard/audit.py` — every decision (tool, args summary, score, decision, timestamp) appended to a local SQLite table. Add a `agentguard/audit.py` query helper to fetch the last N decisions for CLI display.
> 5. Extend `cli.py` with `agentguard scan "<text>"` for a one-off scan without starting a server, and `agentguard audit --last 20` to print recent decisions.
>
> Write tests: a secret-bearing argument gets BLOCKed, a denylisted path gets BLOCKed, an ordinary call gets ALLOWed and actually reaches the mock server, and a policy-file explicit deny overrides a low risk score.

---

## 5. Stage 2 — Tool pinning, RBAC, approval queue, dashboard

> Building on Stage 1, add:
>
> 1. `agentguard/pinning.py` — on first approval of a tool, SHA-256 hash its full description/schema and store it (SQLite table `tool_pins`). On every subsequent call to that tool, re-hash and compare; a mismatch forces REVIEW regardless of risk score, and the audit log entry includes a text diff of old vs. new description.
> 2. `agentguard/identity.py` — an `AgentIdentity` model (name, role) attached to each session; a `RBACPolicy` mapping roles to allowed/denied tool patterns, loaded from the same policy YAML under a new `roles:` section.
> 3. `agentguard/review_queue.py` — REVIEW decisions go into a queue (SQLite-backed) instead of blocking silently; add CLI commands `agentguard review list` and `agentguard review approve <id>` / `agentguard review deny <id>`.
> 4. A minimal dashboard — a single FastAPI + server-rendered HTML page (no separate frontend build step yet) showing: recent decisions, the review queue with approve/deny buttons, and per-agent-identity call counts. Keep this deliberately plain for now; visual theming comes later.
>
> Write tests covering: a tool whose pinned hash no longer matches forces REVIEW even with a low risk score; an RBAC-denied role gets BLOCKed even if the tool itself would otherwise be ALLOWed; approving a queued review actually lets the original call proceed.

---

## 6. Stage 2.5 — Taint engine, sink classifier, Quarantined Memory Ledger

**This is the differentiator — take the most care here, and don't let it collapse into "just another content filter."**

> Building on Stage 2, add:
>
> 1. `agentguard/taint.py` — a `TaintMap` class, scoped per session, storing content fingerprints. On every TOOL_RESULT (not just calls — this runs on responses coming back from upstream MCP servers), classify the result's source as `TRUSTED` (the original user query, or reads from a pinned local-file allowlist) or `UNTRUSTED` (anything from a web tool, email tool, external/unpinned MCP server, or RAG retrieval). For untrusted results, compute content fingerprints using n-gram shingles (e.g. 5-word shingles, hashed) — not embeddings, this stays deterministic and needs no model call — and store them against the session's taint map with the source tool name and timestamp.
> 2. `agentguard/sinks.py` — a `SinkClassifier` that categorizes every outgoing tool call by name/pattern into one of three tiers, configurable in the policy YAML under a new `sinks:` section:
>    - `ordinary` (default) — read-only/local/reversible, taint overlap is logged only
>    - `exfiltration` — network egress, email send, external POST; if the call's arguments overlap with any untrusted fingerprint in the taint map, force REVIEW/BLOCK per policy
>    - `persistence` — anything writing to durable memory (`memory_save`, vector-store writes, RAG corpus updates) — routes to the Quarantined Memory Ledger below instead of the exfiltration path
> 3. `agentguard/quarantine.py` — the `QuarantinedMemoryLedger`. When a `persistence`-tier call's content overlaps untrusted taint, don't forward it to the real memory tool at all yet — write it instead to a separate quarantine table with: content, source tool, taint fingerprint set, session ID, timestamp, and a TTL (default: configurable in policy, e.g. 24h for web-sourced content, indefinite-but-flagged for anything already reviewed). Add a `recall` hook: if an agent later reads back a quarantined item, re-attach its taint labels to the returned content before it goes back to the agent — taint must survive the memory boundary, this is the core property that makes the ledger effective. Add `agentguard memory list-quarantine` and `agentguard memory promote <id>` CLI commands, where promotion requires an explicit human action and logs the full provenance (source, original content, timestamp) alongside the promotion decision.
> 4. Wire the dashboard's review queue to also show quarantined memory items awaiting promotion, with the same approve/deny pattern as tool-call reviews.
>
> Write tests specifically reproducing the documented attack pattern: (a) a mock web-search result contains embedded text instructing the agent to save a "routing rule" to memory — assert the save gets quarantined, not written to trusted memory; (b) simulate a later session recalling that quarantined item and then attempting to use it in an exfiltration-tier call — assert the taint label survived recall and the exfiltration call gets blocked; (c) a legitimate user-stated preference saved to memory goes straight to trusted memory, unaffected. Also write a test confirming an untrusted result that's merely *displayed* to the user (never used as a tool-call argument) is not blocked — the system should not punish reading, only unsafe use.
>
> Keep this stage in observe/log-only mode by default (`enforcement: false` in policy), with an explicit flag to turn on blocking — consistent with shipping detection features quiet-by-default until false-positive rate is actually measured on real traffic.

---

## 7. What "done" looks like for a v1 worth showing people

Not the full roadmap — just: Stage 0 through 2.5 working, with the three Stage 2.5 tests passing, run against your own Claude Code sessions for a week in observe mode, and one real incident (even a synthetic one you construct on purpose) captured end-to-end in the audit log with the attack-chain timeline. That's a legitimate demo and a legitimate portfolio entry — Stages 3 and 4 (behavior analytics, red-team benchmark) are what turn it into something publishable, not what make it real.

---

## 8. Stage 5 — Distribution layer (onboarding, doctor, configure, daemon)

Stages 0–4 are built and passing (66 tests). This is the layer explicitly deferred in the README — do this only after you've run at least a few days of real observe-mode traffic through Stages 0–4, since there's no point polishing the install experience for a detector whose real-world false-positive rate you haven't checked yet.

> Building on the completed Stages 0–4, add:
>
> 1. `agentguard/onboarding.py` — an interactive `agentguard onboard` command: ask whether to start in observe-only or enforce mode (default observe), ask for a port, ask whether to enable the dashboard, then write `~/.agentguard/agentguard.json` with these choices and generate a starter `agentguard.policy.yaml` in the current directory if none exists yet.
> 2. A `--install-daemon` flag on `agentguard onboard` that registers AgentGuard as a background service — detect the OS and write the right service definition: a systemd user unit on Linux, a launchd plist on macOS, a Windows Task Scheduler entry on Windows — pointing at the already-installed console script.
> 3. `agentguard doctor` — checks: does `~/.agentguard/agentguard.json` exist and parse, is the configured port free or already held by AgentGuard itself, does the policy YAML parse, is the audit database reachable, and does its hash chain verify cleanly (reuse the Stage 1 chain-verification logic). Print a clear pass/fail list per check, not a raw exception.
> 4. `agentguard configure` — a shorter interactive flow to change one setting (port, enforce mode, dashboard on/off) without redoing the full onboarding wizard.
> 5. Update the README with the exact command for wiring AgentGuard in front of a real Claude Code session: `claude mcp add --transport http agentguard http://localhost:<port>` — current Claude Code CLI syntax for adding a remote HTTP MCP server — plus a short note to start with enforcement off.
>
> Write tests: `doctor` correctly reports failure on a malformed config file and on a tampered audit chain (reuse the existing tamper test fixture), and `onboard` produces a config file that `agentguard status` can then read successfully.

---

## 9. Stage 6 — Validation tooling (before any more features)

Stages 0–5 are complete (107 tests). The precondition on Stage 5 — real observe-mode traffic — still hasn't happened; every FP number so far is synthetic. Don't build anything past this stage until it has.

> Building on the completed Stages 0–5, add two things only:
>
> 1. **A safe first-connection example.** Add `examples/safe_first_run.md` (or a short script) showing how to point the gateway's `--upstream` at exactly **one** real, low-risk MCP server first — e.g. a filesystem MCP server whose root is scoped via config to a disposable test directory, not the real project tree. The goal is that the first time this runs against a real (non-mock) upstream, a mistake in either direction — over-blocking or under-blocking — can't do anything that matters.
> 2. **`agentguard report [--since <duration>]`** — reads the audit log and prints: total calls, ALLOW/REVIEW/BLOCK counts and percentages, the top triggered rules/signals by frequency, and a specific list of REVIEW/BLOCK decisions that were later manually cleared through the review queue without any follow-up incident — these are your actual false-positive candidates, the number this whole project has been waiting on. Default `--since` to 7 days.
>
> Write a test with a synthetic audit log containing a known mix of ALLOW/REVIEW/BLOCK/cleared entries, asserting `report` computes the right counts and correctly identifies the cleared-without-incident entries.
>
> Do not add anything else in this stage — no new detection logic, no dashboard changes. This stage exists purely so the validation week produces a number instead of an impression.

Once you've run this against real sessions for a week and have an actual FP rate from `agentguard report`, come back with it — that number decides whether Stage 7 is "turn enforcement on" or "go fix the scanner first."

---

## 10. Stage 7 — September 2026 threat update

**Why now:** OpenAI published "Self-replicating prompt injections exist" (25 Sep 2026), showing injections propagating between agents via email, file writes, and code comments. OWASP released the 2026 LLM Top 10 and the Agent Control Standard (ACS) on 2 Sep 2026. Both land directly on AgentGuard's architecture.

**Relationship to the observe-week gate:** every feature below ships **observe-only / off by default**, exactly like Stage 2.5. The real-traffic week is not replaced — run it concurrently, so its data measures these new detectors too. More detectors = more false-positive surface, so each one must show up in `agentguard report` as its own signal name.

Paste one sub-stage at a time. 7A is the priority; 7B–7E can follow in any order.

### 7A — Propagation (worm) detection  ← do this first

> Working in the existing AgentGuard codebase (Stages 0–6 complete, 143 tests passing). Read `taint.py`, `sinks.py`, and `scanner.py` first and report how file writes, git commits, chat/message posts, and email sends are currently classified before changing anything — do not duplicate existing sink logic.
>
> Add a **propagation** sink tier for any tool call that writes to a surface other agents or people will later read: file writes, git commits, PR/issue comments, document edits, chat/message posts, and outgoing email. Patterns configurable under `sinks.propagation` in the policy YAML. Email may already be an exfiltration sink — a call can belong to both tiers; take the stricter verdict.
>
> The **replication signature** is the combination of all three: (1) the outgoing content overlaps untrusted fingerprints in the session's taint map or in taint rehydrated from the quarantine ledger; (2) the overlapping region contains instruction-like text aimed at an AI reader — reuse the scanner's existing injection patterns, and add patterns for self-propagation phrasing ("include this in", "copy this into", "when an agent reads"); (3) the destination is a propagation sink. All three → REVIEW with signal `propagation:replication`. Overlap alone → log only (quoting a web page into notes is normal). Instruction text alone without untrusted overlap → existing scanner behavior, unchanged.
>
> Code comments are a documented vector: when the written content is source code, extract comment text (`#`, `//`, `/* */`, `<!-- -->`, docstrings) and run the check on comments separately, so an injection hidden in a comment isn't diluted by surrounding code.
>
> Tests, reproducing the three documented channels: (a) web result containing a self-propagation instruction → agent sends an email containing it → flagged; (b) same content written to a file → flagged; (c) same content hidden in a code comment inside an otherwise normal `.py` file → flagged; (d) the injected content saved to memory, recalled in a new session, then written to a file → flagged (taint must survive the ledger here too); (e) benign: agent quotes a web snippet with no instruction text into a notes file → logged, not reviewed; (f) benign: agent writes code with ordinary comments → not flagged. Add four worm scenarios to the red-team simulator and confirm the benign controls still pass. Report the fast-path latency after the change.

### 7B — Volume-aware DLP and data classification

> Add `agentguard/classify.py`. For every outgoing call to an exfiltration or propagation sink, count PII entities in the arguments: email addresses, phone numbers, card numbers (Luhn-validated, so random digit runs don't count), and Indian identifiers (PAN format; Aadhaar format with Verhoeff checksum). Assign a label: PUBLIC, INTERNAL, CONFIDENTIAL, PII, SECRET (SECRET = existing detect-secrets findings).
>
> Counts matter more than presence: one email address in a message is normal, fifty in a body is a bulk export. Thresholds in the policy YAML under `classification:`, plus a per-role maximum label allowed to leave through each sink tier. Actions per rule: `log`, `review`, `block`, or `redact` (replace matches with typed placeholders like `<EMAIL_1>`; placeholders are never reversed by the gateway).
>
> Scope limit, stated in the README: the gateway scans content present in arguments. An attachment passed only as a file path is not read — log it as an unscanned attachment signal.
>
> Tests: one email in a message → allow; a CSV body with 200 emails to an external sink → block under the default policy; a random 16-digit number → not a card; a Luhn-valid test card number → detected; `redact` produces placeholders and the redacted version is what reaches the upstream. Confirm the fast path stays within its latency budget.

### 7C — Declared task scope (deterministic alignment)

> The gateway sees tool calls, not the agent's reasoning, so alignment checking here works on the tool trace. Add a per-session task scope set by the human, never by the agent: `agentguard scope set --session <id> --tools "filesystem.read*,web.search"`, or a default scope per role in the policy YAML. Once set, the scope cannot be changed through the MCP channel. Calls outside scope → REVIEW with signal `scope:outside`.
>
> Add an `AlignmentAuditor` interface on the deep path with a default no-op. Provide one optional adapter that sends (declared goal, last N tool calls, proposed call) to a local OpenAI-compatible endpoint (e.g. Ollama) for a few-shot aligned/misaligned judgment, modeled on LlamaFirewall's AlignmentCheck. Off by default; never calls a remote API unless explicitly configured.
>
> Tests: in-scope call → allow; out-of-scope call → review; an attempt to change scope via a tool call → rejected and logged; the no-op auditor adds no latency.

### 7D — Financial sink tier and global lock

> Add a `financial` sink tier (payment, transfer, purchase, refund, invoice-pay patterns). Every call in this tier → REVIEW regardless of risk score, even in observe mode's reporting. Extract amount, currency, and payee where present; enforce an optional per-session spending cap. On approval, write a structured receipt into the existing hash-chained audit log (agent identity, action, amount, payee, approver, policy rule, argument hash).
>
> Add `agentguard lock --all` to lock every active session at once. Document plainly that locking stops traffic through the gateway but cannot revoke credentials held by upstream servers.
>
> Tests: a purchase call always reaches the review queue; exceeding the cap blocks; an approved payment produces a receipt that passes chain verification; `lock --all` denies subsequent calls in every session.

### 7E — Standards mapping (documentation only)

> Create `docs/standards-mapping.md` mapping each AgentGuard feature to the OWASP Top 10 for LLM Applications 2026, the OWASP Top 10 for Agentic Applications (including ASI06, memory and context poisoning), and the OWASP Agent Control Standard. Fetch and read the actual published documents first; cite real section or control identifiers only. Where AgentGuard does not cover a control, say so in a Gaps column — do not stretch a feature to claim coverage it doesn't provide. No code changes in this sub-stage.
---

## 11. Stage 7 — Verify and continue (single prompt)

Use this instead of pasting 7A–7E one by one, because part of Stage 7 is already built. First copy this file into the repo as `docs/BUILD_PROMPTS.md`, so Claude Code can read the Section 10 acceptance criteria directly.

> You're continuing AgentGuard. Stages 0–6 are complete and must stay working: FastMCP proxy, two-tier scanner, risk engine, policy/RBAC, hash-chained audit log, tool pinning, review queue, dashboard, taint engine, sink classifier, Quarantined Memory Ledger, behavior monitor, red-team simulator, onboarding/doctor/configure/daemon, the `report` command, the safe-first-run sandbox, and the roots-hang fix. Part of Stage 7 may already exist. The Stage 7 specification is Section 10 of `docs/BUILD_PROMPTS.md` — read it first.
>
> **Ground rules**
> - Don't rewrite or delete working code or tests.
> - Never touch my real `~/.agentguard`. Set `AGENTGUARD_HOME` to a temp dir in the same shell call as any command that writes state.
> - Use `python -m agentguard.cli` (the console script isn't on PATH on this machine).
> - Every new detector ships off or observe-only by default, and appears in `agentguard report` under its own signal name.
>
> **Phase 1 — Audit (no code changes).**
> 1. Run the full suite, `simulate`, and `audit --verify`. Record the test count, simulator score, and fast-path latency as the baseline.
> 2. For every acceptance criterion in 7A–7E, mark it DONE, PARTIAL, or MISSING. Evidence must be a passing test name or a command you actually ran; reading the code alone doesn't count.
> 3. Also confirm Stages 0–6 still behave as specified. In particular: taint survives the ledger across sessions, the roots-hang regression test passes, and the sandbox still gives ALLOW on the ordinary files and BLOCK on the `.env` decoy.
> 4. Print the full audit table before changing anything.
>
> **Phase 2 — Fix.** Resolve every PARTIAL item first. Each bug fix gets a regression test that you've confirmed fails without the fix.
>
> **Phase 3 — Continue.** Build the MISSING sub-stages in order: 7A → 7B → 7C → 7D → 7E. After each one, run the full suite and the simulator. Don't start the next sub-stage while anything is failing.
>
> **Final report**
> - The audit table, updated to its final state.
> - What was fixed and what was added.
> - Test count, simulator score, and latency, before vs after.
> - The new signal names to watch in `report --since 7d`.
> - Honest limitations.
> - The README checklist updated to match reality.
