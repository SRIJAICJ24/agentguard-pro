# Claude Code hooks — verified notes for AgentGuard

Read from the official reference, [code.claude.com/docs/en/hooks](https://code.claude.com/docs/en/hooks)
(fetched 30 Sep 2026, raw markdown at `/docs/en/hooks.md`), plus the `env-vars` and
`settings` pages for configuration paths.

**Claude Code version tested against: 2.1.284** (Claude desktop app 2.9939.4, Agent SDK
0.3.284 — taken from `CLAUDE_CODE_EXECPATH`, `CLAUDE_CODE_DESKTOP_APP_VERSION` and
`CLAUDE_AGENT_SDK_VERSION` in the session environment). That is new enough for every field
below; `mcp_server` needs v2.1.274 or later.

Real payloads: see [Captured fixtures](#captured-fixtures) at the end.

---

## What I was told vs what the docs say

| Claim to verify | Verdict | What the docs actually say |
|---|---|---|
| PreToolUse replies via `hookSpecificOutput.permissionDecision` (`allow`/`deny`/`ask`/`defer`) | **Confirmed**, with caveats | All four values exist. `"allow"` **skips Claude Code's permission prompt**, so a security hook must not return it casually; AgentGuard never does. `"defer"` is honoured **only in non-interactive `-p` mode**; interactive sessions log a warning and ignore it. With several hooks, precedence is `deny > defer > ask > allow`. The old top-level `decision`/`reason` (`approve`/`block`) is deprecated for PreToolUse. |
| Exit code 2 blocks and overrides any JSON | **Confirmed** | "Exit 2's block is the one outcome JSON can't override" — even `permissionDecision: "allow"`. Since v2.1.214, exit 2 with schema-invalid JSON still blocks. |
| PostToolUse uses different fields | **Confirmed** | Top-level `decision: "block"` + `reason` (adds the reason next to the result; it can't undo the call), and `hookSpecificOutput.additionalContext`, `updatedToolOutput`, `updatedMCPToolOutput`, `classifierContext`. |
| Hooks can be `type: "command"` or `type: "http"` | **Confirmed, and more** | Five types: `command`, `http`, `mcp_tool`, `prompt`, `agent`. |
| Hooks also fire inside subagents | **Confirmed** | Settings, managed and plugin hooks run in subagents; tool events then carry `agent_id` and `agent_type`. |

### What the notes didn't mention, and changed the design

1. **An HTTP hook can never fail closed.** Connection failure, non-2xx and timeout are all
   "non-blocking errors, execution continues". Status codes alone can't block, only a 2xx
   JSON body with a decision can. So `install-hooks --fail-closed` installs the **command**
   hook, which can exit 2.
2. **A timed-out command hook doesn't block either.** "A timed-out `command`, `http`, or
   `mcp_tool` hook doesn't block the tool call." Fail-closed only works if the hook exits 2
   *before* Claude Code's timeout, so the client's own daemon timeout (default 2 s) is well
   under the hook `timeout` it's installed with (10 s).
3. **The default hook timeout is 600 s.** Every AgentGuard entry sets its own: 5 s for HTTP,
   10 s for command.
4. **File paths arrive absolute, with native separators** (backslashes on Windows), and `~`
   is expanded before hooks run. Everything is normalised to forward slashes before matching.
5. **Windows has a `PowerShell` tool.** Where it's enabled it is the primary shell, and
   without Git Bash the `Bash` tool doesn't exist at all. AgentGuard maps `PowerShell`
   exactly like `Bash`.
6. **MCP calls carry `mcp_server: {name, source}`** (v2.1.274+). The docs say to base trust
   on `source`, not the `mcp__<server>__` prefix. AgentGuard uses `name` only to decide which
   surface counts a call (dedupe), never to grant trust.
7. **Edits to settings files are picked up mid-session** by a file watcher, so installing
   hooks doesn't strictly need a restart.
8. **Things that can silently disable the hooks:** `disableAllHooks: true` in any settings
   level (a project's `.claude/settings.json` can override the user file), an
   `allowedHttpHookUrls` allowlist that doesn't include the daemon's URL, and
   `allowManagedHooksOnly` in managed settings. `doctor` checks the first; self-protection
   flags writes to the settings files that could set it.
9. **Hooks don't see `@`-referenced files** (no tool call is made), or `EndConversation`.

---

## Input schema (stdin for command hooks, POST body for HTTP hooks)

Common fields: `session_id`, `prompt_id` (v2.1.196+, absent until the first prompt),
`transcript_path`, `cwd`, `scratchpad_dir` (v2.1.257+), `permission_mode` (`default`, `plan`,
`acceptEdits`, `auto`, `dontAsk`, `bypassPermissions`), `effort: {level}`, `hook_event_name`.
Inside a subagent, also `agent_id` and `agent_type`.

### PreToolUse

Adds `tool_name`, `tool_input`, `tool_use_id`, and `mcp_server` for MCP tools.
`tool_input` per tool, as AgentGuard reads it:

| Tool | `tool_input` fields |
|---|---|
| `Bash`, `PowerShell` | `command`, `description`, `timeout` (ms), `run_in_background` |
| `Write` | `file_path` (absolute), `content` |
| `Edit` | `file_path`, `old_string`, `new_string`, `replace_all` |
| `Read` | `file_path`, `offset`, `limit` |
| `Glob` | `pattern`, `path` |
| `Grep` | `pattern`, `path`, `glob`, `output_mode`, `-i`, `multiline` |
| `WebFetch` | `url`, `prompt` |
| `WebSearch` | `query`, `allowed_domains`, `blocked_domains` |
| `Agent` | subagent prompt and settings |
| `mcp__<server>__<tool>` | the MCP tool's own arguments |

`MultiEdit` is not in the current tool list. AgentGuard still maps it (`edits[].new_string`)
in case an older version sends it.

### PostToolUse

Adds `tool_input`, `tool_response` (shape depends on the tool: `Write` returns
`{filePath, type}`, `Bash` returns `{stdout, stderr, interrupted, isImage}`, …), `tool_use_id`,
optional `duration_ms`, and `mcp_server` for MCP tools. `Bash` may also carry
`tool_response.bashEditDiff` (public beta; not used).

## Output formats

**PreToolUse** (the only form AgentGuard emits, and only in enforce mode):

```json
{"hookSpecificOutput": {"hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": "AgentGuard: path:**/.ssh/** (score 0.80)"}}
```

`permissionDecisionReason` is shown to **Claude** for `deny` and to the **user** for `ask`.
`updatedInput` (used with `ask` when DLP redacts) replaces the whole input object.

**PostToolUse:** `{"decision": "block", "reason": "...", "hookSpecificOutput":
{"hookEventName": "PostToolUse", "additionalContext": "...", "updatedToolOutput": {...}}}`.
AgentGuard returns nothing from PostToolUse; it only observes the result.

**No decision:** exit 0 with empty stdout, or HTTP 2xx with an empty body. This is
AgentGuard's answer in observe mode and for ALLOW, and it leaves Claude Code's normal
permission flow in charge.

---

## How AgentGuard uses this

| | Observe mode (default) | Enforce mode |
|---|---|---|
| ALLOW | no decision | no decision (never `"allow"`) |
| REVIEW | no decision, logged as would-ask | `"ask"`: Claude Code's own prompt is the review step |
| BLOCK | no decision, logged as would-deny | `"deny"` |
| self-protection | no decision, logged | `"deny"` |
| lock active | no decision, logged | `"deny"` |

**Approvals as false-positive candidates.** An `ask` is queued as a `hook_ask` review item
carrying the `tool_use_id`. If a `PostToolUse` with that id arrives, the tool ran, so the
user approved it at the prompt. The item is marked approved by `claude-code-prompt`, which
`report` counts as a false-positive candidate. A denied prompt produces no PostToolUse, and
the item stays pending.

**Counting a call once.** Calls to an MCP server routed through the AgentGuard gateway (the
`hooks.gateway_servers` list, default `["agentguard"]`, matched on the tool-name prefix or
`mcp_server.name`) are gated and logged **by the gateway only**. The hook just notes the
call for correlation and, afterwards, records the result's taint into the Claude Code
session. Every other MCP server is gated by the hook. Audit rows say which surface wrote
them (`source`: `mcp` or `hook`).

**Sharing taint between the gateway and hooks.** Claude Code doesn't tell an MCP server which
Claude Code session is calling it, so the gateway's MCP session can't be tied to a
`session_id` by identity. Instead:

* The hook's PreToolUse fires before Claude Code sends the MCP request, and notes
  (tool, argument hash) → Claude Code session.
* When the gateway receives the same call within 30 s, it merges that session's taint into
  its own check (sources appear as `claude-code:WebFetch` and so on).

This is **correlation, not identity**. It needs hooks installed and the gateway running in the
same daemon process. It links nothing when two sessions make the identical call inside the
window, since it won't guess. It links nothing for calls a hook never saw.
`test_bridge_control_without_the_hook_note_the_gateway_sees_nothing` pins that last point.
I didn't build a per-workspace fallback scope: `cwd` exists only on the hook side, so the
gateway has nothing to match it against.

**When the daemon is down:**

| Hook type | Daemon down / slow | Configurable? |
|---|---|---|
| `http` (default install) | Claude Code: non-blocking error, the call proceeds (fail-open) | No; Claude Code's behaviour |
| `command` (`agentguard hook`) | fail-open by default: exit 0 within `hook_timeout` (2 s) | `hook_fail_mode: closed` makes PreToolUse exit 2 (block) |

---

## Captured fixtures

_Pending: the capture session in the throwaway project `D:\agentguard-hook-capture` has not
been run yet. Until it is, the tests use `tests/fixtures/claude_code/doc_*.json`, built
field-for-field from the documented schema above._
