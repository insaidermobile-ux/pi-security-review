# Proposal

## Why

A full run on a real project, with the session model served through the `pi-claude-bridge` provider, failed in every agent. The provider rejected each request with the same error, which is about 900 characters long. Two problems on our side made this worse:

- **No early stop.** The profile agent failed first, and six hunt agents were still started on the same model. Each failed with the same error, so the run took longer and gave nothing new. With a provider that bills rejected requests, it would also have cost money.
- **Unreadable output.** The session summary repeated the full error seven times, once per agent, followed by subtree labels that list a dozen directories each. The useful part, which agent failed and why, was buried.

## What Changes

- **Stop after a rejected profile request.** When the profile agent's model request is rejected with an error that retrying cannot fix, and the hunt role uses the same model, hunting does not start. The run ends incomplete with one reason naming the model and the error, and the report and store are written as usual. Transient errors such as rate limits, context overflow, timeouts, cancellations, and agents that finish without submitting do not stop the run, because other agents may still succeed.
- **Report agent failures compactly.** Agents of the same stage that fail with the same error are reported as one incomplete reason, such as `6 hunt agents failed (hunt:app, hunt:mobile, hunt:eval and 3 more): <error>`. Errors and agent labels in incomplete reasons are shortened. The run log keeps each agent's full error.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `security-audit-pipeline`: new requirements for stopping after a rejected profile request and for compact failure reporting.

## Impact

- **Code** in `extensions/security-review/`: `agent-runtime.ts` (classifying a model rejection on the agent outcome), `pipeline.ts` (early stop and grouped failure reasons).
- **Output:** incomplete reasons in the session summary, report, and stored run records become shorter. Their full text moves to the run log only.
- **No new dependencies.** Classification uses `isRetryableAssistantError` and `isContextOverflow` from `@earendil-works/pi-ai`, already a peer dependency.
