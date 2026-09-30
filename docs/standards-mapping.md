# AgentGuard — standards mapping

Maps what AgentGuard actually does to three OWASP GenAI Security Project documents. Where a
feature covers only part of an entry, the row says **partial**. Controls AgentGuard doesn't
provide are listed under Gaps rather than stretched to fit.

Compiled 27 September 2026 against these sources:

| Document | Version read | Source |
|---|---|---|
| OWASP Top 10 for LLM Applications 2026 | published 3–4 Aug 2026; entry list from the canonical repo `2026/final/` | [genai.owasp.org resource page](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/), [GenAI-Security-Project/GenAI-LLM-Top10](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10) |
| OWASP Top 10 for Agentic Applications (the "2026" agentic list) | released 9 Dec 2025 | [OWASP GenAI announcement](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) |
| OWASP Agent Control Standard (ACS) | specification v0.1.0 | [ACS resource page](https://genai.owasp.org/resource/agent-control-standard-acs/), [GenAI-Security-Project/agent-control-standard](https://github.com/GenAI-Security-Project/agent-control-standard) (`specification/v0.1.0/`) |

**What was and wasn't read.** For the two Top 10 lists, identifiers and titles were taken from the
official sources above. The per-entry prose (the PDFs) wasn't read line by line, so this mapping
works at the entry level and doesn't cite sub-sections. For ACS, the hook names are the schema
file names under `specification/v0.1.0/hooks/`, and the dispositions are the `decision` enum in
`specification/v0.1.0/response-envelope.json`. Identifiers that couldn't be confirmed from these
sources aren't used.

---

## 1. OWASP Top 10 for LLM Applications 2026

The 2026 edition scopes itself to the model as a component; risks from tools, memory and actions
move to the Agentic Top 10. AgentGuard sits on the tool-call path, so its coverage here is
naturally uneven.

| ID | Title | AgentGuard feature | Coverage | Gaps |
|---|---|---|---|---|
| LLM01:2026 | Prompt Injection | Scanner injection patterns on tool arguments (`scanner.py`). Taint engine fingerprints untrusted results and tracks where they flow (`taint.py`, `sinks.py`). Propagation detection for self-replicating injections (`propagation.py`, Stage 7A). | **partial** | The model's own input isn't inspected: the gateway sees tool calls and results, not prompts. Injection is only caught when it shows up as a tool argument or flows from a tainted result into a sink. Paraphrased injections can evade shingle matching. Patterns are English-only. |
| LLM02:2026 | Sensitive Information Disclosure | detect-secrets two-tier scan and redaction in logs. Volume-aware DLP with Luhn, Verhoeff, PAN and email/phone counts, per-role label limits and `redact` (`classify.py`, Stage 7B). Credential-path denylist. | **partial** | Covers only data leaving through tool arguments. Model responses to the user aren't seen. Attachments passed by path aren't read (logged as `dlp:unscanned_attachment`). |
| LLM03:2026 | Excessive Agency | Policy allow/deny, RBAC per agent role, declared task scope (`scope:outside`, Stage 7C), financial tier always held for a human (Stage 7D), review queue, locks. | **partial** | Least privilege is enforced only for tools reached through the gateway. The agent's identity is declared by config/env and isn't authenticated. |
| LLM04:2026 | Supply Chain | Tool pinning: a changed tool description or schema forces REVIEW (`pinning.py`). | **partial** | Trust-on-first-use only. No package, model or dataset provenance, signature checks or SBOM. |
| LLM05:2026 | Data and Model Poisoning | Quarantined Memory Ledger holds memory and vector writes derived from untrusted content (persistence tier). | **partial** | Covers memory/RAG writes made as MCP tool calls. No training, fine-tuning or model-weight poisoning coverage. |
| LLM06:2026 | Unbounded Consumption | Velocity baseline with a hard rate ceiling (`behavior.py`), plus locks. | **partial** | No token, cost or compute accounting. Baselines are in-process and reset on restart. |
| LLM07:2026 | Misinformation | — | **none** | AgentGuard makes no judgment about whether content is true. |
| LLM08:2026 | Hidden Context Exposure | Scanner `system_prompt_probe` pattern flags probing phrasing in tool arguments. | **minimal** | The gateway never sees the system prompt or hidden context, so it can't detect that context being exposed. |
| LLM09:2026 | Vector and Embedding Weaknesses | Vector-store writes (`*vector*`, `*upsert*`, `*embed*store*`) are in the persistence tier, so tainted writes are quarantined. | **partial** | No embedding-level analysis (inversion, cross-tenant leakage, similarity manipulation). |
| LLM10:2026 | Improper Output Handling | Taint labels on results. Propagation detection when output is written onward. | **minimal** | Results aren't sanitised or encoded before downstream use. Only flows into sinks are assessed. |

## 2. OWASP Top 10 for Agentic Applications

| ID | Title | AgentGuard feature | Coverage | Gaps |
|---|---|---|---|---|
| ASI01 | Agent Goal Hijack | Declared task scope (`scope:outside`). Optional AlignmentAuditor on the deep path (`alignment:misaligned`, off by default). Taint to exfiltration sink. | **partial** | The deterministic check is tool-level only. Goal-level judgment needs the optional local model, and the gateway can't see the agent's reasoning. |
| ASI02 | Tool Misuse | Policy/RBAC, argument scanning, sink tiers, financial tier, review queue, velocity. | **partial** | Tools reached outside the gateway aren't covered. |
| ASI03 | Identity & Privilege Abuse | `AgentIdentity` + RBAC per role. Credential-path denylist. Secret detection. | **partial** | Identity comes from config/env and isn't cryptographically bound. No delegation chains or token-scope management. Locks don't revoke upstream credentials. |
| ASI04 | Agentic Supply Chain Vulnerabilities | Tool pinning with description diffs (rug-pull detection). A reserved control-plane namespace rejects upstream tools named `agentguard*`. | **partial** | Trust-on-first-use. Upstream server code and dependencies aren't verified. |
| ASI05 | Unexpected Code Execution | The policy can deny execution tools (e.g. `system.exec`). | **minimal** | No sandboxing and no analysis of generated code. |
| ASI06 | Memory & Context Poisoning | **Quarantined Memory Ledger**: untrusted-derived writes are held with TTL and provenance, taint is re-attached on recall across sessions, and promotion needs a human. Stage 7A extends this so recalled payloads written onward are flagged. | **substantial** for memory written through MCP tools | Memory the client or agent framework writes directly, without an MCP tool, isn't seen. Shingle matching misses heavy paraphrase. |
| ASI07 | Insecure Inter-Agent Communication | Propagation tier: content bound for surfaces other agents read (files, commits, comments, chat, email) is checked for replicating instructions (Stage 7A). | **partial** | No authentication or integrity of agent-to-agent messages. Direct A2A protocols aren't proxied. |
| ASI08 | Cascading Failures | Propagation detection breaks worm chains at the write. Velocity ceiling. `lock --all` across every session. | **partial** | No cross-gateway or fleet-wide correlation. |
| ASI09 | Human-Agent Trust Exploitation | The review queue shows the redacted call, its signals and provenance. Financial receipts record approver and argument hash. | **partial** | Nothing checks whether the agent's explanation to the human is truthful. |
| ASI10 | Rogue Agents | Kill switch and CLI locks (absolute, even in observe mode). Velocity anomalies. Scope. Hash-chained audit trail. | **partial** | Detection is per call. No long-horizon behavioural model of concealment. |

## 3. OWASP Agent Control Standard (ACS) v0.1.0

ACS defines lifecycle hooks, a request/response envelope, and three pillars: Instrument, Trace
and Inspect. AgentGuard is an MCP proxy, not an ACS-conformant implementation: it doesn't speak
the ACS envelope. The table maps concepts, not wire compatibility.

### Hooks (`specification/v0.1.0/hooks/`)

| ACS hook | AgentGuard equivalent | Coverage |
|---|---|---|
| `tool-call-request` | `on_call_tool` before `call_next` (TOOL_PREPARE): the whole policy/scan/sink/scope/DLP/financial pipeline | **yes** (concept) |
| `tool-call-result` | `on_call_tool` after `call_next` (TOOL_RESULT): taint classification, quarantine recall hook | **yes** (concept) |
| `memory-store` | persistence-tier tool calls → Quarantined Memory Ledger | **partial** (only when memory is an MCP tool) |
| `memory-context-retrieval` | recall hook re-attaches taint when a result matches a quarantined item | **partial** (same condition) |
| `knowledge-retrieval` | results from `rag.*` tools are classified as untrusted and fingerprinted | **partial** |
| `session-start`, `session-end` | an implicit MCP session is created per connection; no hook | **no** |
| `user-message`, `agent-response`, `agent-trigger`, `turn-start`, `turn-end` | not visible to an MCP proxy | **no** |
| `subagent-start`, `subagent-stop` | not visible | **no** |
| `skill-load`, `skill-register`, `skill-unload` | not visible | **no** |
| `pre-compact`, `post-compact` | not visible | **no** |
| `agbom-snapshot`, `agbom-changed` | tool pinning stores tool descriptions/schemas and detects changes, but produces no AgBOM | **partial** (change detection only) |
| `system-ping` | — | **no** |

### Dispositions (`response-envelope.json`, `decision`)

| ACS decision | AgentGuard | Notes |
|---|---|---|
| `allow` | ALLOW | |
| `deny` | BLOCK | locks and kill switch are absolute; other denials are enforced only when `enforcement: true` |
| `modify` | DLP `redact` (Stage 7B) rewrites arguments before forwarding | the only modifying control |
| `ask` | REVIEW → review queue, single-use approval, retry | asynchronous (hold then retry), not an inline prompt |
| `defer` | — | **gap**: no defer-to-another-authority disposition |

Envelope fields, conceptually: `reasoning` ≈ decision `reason`; `reason_codes` ≈ signal names
(e.g. `propagation:replication`); `policy_references` is covered **partially**, only by
`policy_rule` in financial receipts; `cited_provenance_ids` ≈ taint sources and quarantine
provenance. None of this is emitted in ACS format.

### Pillars

| Pillar | AgentGuard | Gaps |
|---|---|---|
| Instrument | middleware on the MCP proxy path | only MCP tool traffic; not the ACS hook protocol |
| Trace | hash-chained SQLite audit log, per-session attack-chain timeline, payment receipts in the chain | no OpenTelemetry spans or OCSF events |
| Inspect | tool pins (description/schema hashes and diffs) | no AgBOM in CycloneDX / SPDX / SWID |

---

## Summary of the largest gaps

1. **Outside the tool path**: prompts, model responses, hidden context and truthfulness (LLM07, LLM08, LLM10, ASI09) are mostly out of reach for a gateway that only sees tool traffic.
2. **Identity** is declared, not authenticated (LLM03, ASI03).
3. **Supply chain** is trust-on-first-use pinning only (LLM04, ASI04).
4. **Execution sandboxing** is absent (ASI05).
5. **ACS conformance**: no ACS envelope, no OpenTelemetry/OCSF trace export, no AgBOM, no `defer` disposition.
