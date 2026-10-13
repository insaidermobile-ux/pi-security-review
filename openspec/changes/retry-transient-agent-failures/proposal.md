# Proposal

## Why

In two of four real-model runs on the seeded fixture, the provider answered one hunt agent with `429 Rate limit reached for requests`. pi's session-level retry gave up after three attempts spread over about 14 seconds (2, 4, and 8 s), which is shorter than the provider's limit window. The agent failed, and with it the only hunter for its vulnerability class:

- One run had no SQL injection hypothesis at all, so the secret disclosure it enables could not be grouped under it and became a separate finding.
- That finding stays `open` in the store until a complete `full` run, because default runs never mark findings stale.

The run was correctly marked incomplete, but a transient provider condition should not cost a whole vulnerability class.

## What Changes

- **Longer retry budget for audit agents.** Each audit agent retries a provider request that fails with a transient error (rate limit, overload, server or network error, as classified by pi) up to 6 times with exponential backoff starting at 5 seconds and capped at 60 seconds per wait, about 3 minutes in total. Today it is 3 retries starting at 2 seconds.
- **One re-run of a hunt agent after a transient failure.** A hunt agent that still fails with a transient error is run once more, after the other hunt agents of the run have finished, when the provider is less loaded. If the re-run succeeds, its hypotheses replace the partial ones from the failed attempt, and the run is not incomplete because of that agent. If it fails, hypotheses from both attempts proceed and the run is incomplete, as today. Timeouts, cancellations, and agents that finish without submitting are not re-run.
- The run log keeps both attempts, and the report's Errors section notes the re-run.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `security-audit-pipeline`: new requirements for retrying transient model request failures and re-running a transiently failed hunt agent; the stage failure scenario now applies to failures that remain after the retry.

## Impact

- **Code** in `extensions/security-review/`: `agent-runtime.ts` (retry budget, transient classification on the agent outcome), `pipeline.ts` (hunt re-run).
- **Cost and time:** a re-run costs one more hunt agent, only when a hunter failed transiently. Retry waits count toward `agentTimeoutSeconds` (default 600 s), which leaves room for the full retry budget.
- **Docs:** README security model and limitations section.
- **No new dependencies.** The transient classification uses `isRetryableAssistantError` from `@earendil-works/pi-ai`, already a peer dependency.
