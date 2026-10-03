# AgentGuard measurement log

One line per frozen install. The week's numbers only mean something if every decision
in them came from the same code and the same rules, so:

> **Rule: any change after a line is written — code, detection patterns, or the policy
> file the daemon loads — means a new git tag, a new `DETECTOR_VERSION` (when detection
> code changed; the test suite enforces this), a fresh wheel install, and a new line here.**
> `agentguard report` warns when its window mixes detector or policy versions; compare
> those periods separately.

| Tag | Detector version | Policy hash | Live policy file | Install | Start date (UTC) | End date |
|---|---|---|---|---|---|---|
| `week1` | `2026.10.3` | `p-78e342c112` | `D:/agentguard-week/agentguard.policy.yaml` | wheel from `week1`, non-editable, venv `D:/agentguard-week` | **2026-10-03** (frozen 2026-10-02; the daemon first answered from the venv at about 04:40 UTC, first hook row is audit #14 at 04:41 UTC) | — |

Install notes for this line:

- The daemon starts from `~/.agentguard/agentguard-daemon.vbs` (hidden window, restarts
  itself within about 5 seconds if it exits). Auto-start at login is a copy of that file in
  the Windows Startup folder, **not** a scheduled task: `onboard --activate` could not
  create the task without Administrator rights.
- Audit rows #1-#13 predate this install (older code, no workspace label); a report
  window that includes them shows a version-mix warning. Count from #14 onward.
- Audit rows from `D:\agentgaurd` (the dev workspace) are excluded from reports by default.
- Self-protection is live: during this session AgentGuard blocked a read-only command of
  Claude's that named the live audit database, because command-text matching cannot tell
  reading from editing. Changes to the live policy or home must be made by the user.

How to check what's actually running against this line:

```bash
D:/agentguard-week/Scripts/python.exe -c "import agentguard, agentguard.versions as v; print(agentguard.__file__, v.DETECTOR_VERSION)"
D:/agentguard-week/Scripts/python.exe -c "from agentguard.policy import load; from agentguard.versions import policy_version; print(policy_version(load('D:/agentguard-week/agentguard.policy.yaml')))"
```

The first must print a path under `D:\agentguard-week\Lib\site-packages` and `2026.10.3`;
the second `p-78e342c112`. Every audit row also records `detector_version` and
`policy_version`, so `agentguard report` shows any drift on its own.

## Key formats added in week1 (F1), and where each was verified

| Provider | Prefixes | Source | Notes |
|---|---|---|---|
| OpenAI | `sk-admin-` | OpenAI Admin API reference, example value `sk-admin-1234abcd` ([developers.openai.com](https://developers.openai.com/api/reference/resources/organization/subresources/admin_api_keys/methods/create)) | first-party |
| OpenAI | `sk-proj-`, `sk-svcacct-` | OpenAI developer community forum ([community.openai.com](https://community.openai.com/t/incorrect-api-is-generated-in-the-openai-account/879912)) | **not** in OpenAI's own reference text, which uses a generic `sk-abc...` example for service-account keys; weaker verification |
| Anthropic | `sk-ant-api…` (`sk-ant-api03-` example), `sk-ant-admin…` | Claude API docs: [Authentication](https://platform.claude.com/docs/en/manage-claude/authentication), [Admin API](https://platform.claude.com/docs/en/api/administration-api) | first-party |
| Google | `AIza` + 35 | Google Cloud [Manage API keys](https://docs.cloud.google.com/docs/authentication/api-keys): example `AIzaSy…` (39 chars) | example only, no stated rule; Google's newer `AQ.` keys are not in Google's own docs and are **not** detected |
| GitHub | `github_pat_` (plus `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` already covered) | [About authentication to GitHub](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github) | first-party |
| Slack | `xapp-`, `xoxe.xapp-`, `xwfp-` (plus `xoxb-`, `xoxp-` already covered) | [Slack token types](https://docs.slack.dev/authentication/tokens) | first-party |
| Stripe | `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_`, `sk_org_` | [Stripe API keys](https://docs.stripe.com/keys) | first-party; publishable `pk_` keys are documented as safe to expose and not flagged |

None of the providers documents a body length, so bodies are matched by character class
with a minimum length; redaction always removes the whole token.
