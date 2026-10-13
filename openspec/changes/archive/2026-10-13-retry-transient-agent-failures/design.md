# Design

## Context

- `createAuditSession` in `agent-runtime.ts` creates each audit agent's session with `SettingsManager.inMemory({ retry: { enabled: true, maxRetries: 3 } })`. pi retries an assistant turn whose error `isRetryableAssistantError` classifies as transient, waiting `baseDelayMs * 2^(attempt-1)` capped at `maxAgentDelayMs`. Defaults are 2000 ms and 60000 ms, so three retries wait 2 + 4 + 8 = 14 s.
- The zai provider's `429 … Rate limit reached for requests` (code 1302) matches pi's transient patterns. It was retried and still failed.
- `huntStage` runs all hunt assignments through `mapBounded` with `maxConcurrentAgents` and records a failure for every outcome that is not `ok`. Hypotheses submitted before a failure are kept.

## Goals / Non-Goals

**Goals:** survive provider throttling that lasts minutes, not seconds, without losing a vulnerability class; keep the run log truthful about what happened.

**Non-Goals:**

- Re-running affirmer, challenger, profile, triage, or report agents. Their failures already degrade gracefully (unverified hypothesis, missing profile, ungrouped hypotheses, fallback summary), and they get the longer in-session retry budget too.
- A user setting for the retry budget. The constants can become settings later if needed.
- Adaptive concurrency based on observed rate limits.

## Decisions

### D1. Retry budget as constants in `agent-runtime.ts`

`AGENT_RETRY = { enabled: true, maxRetries: 6, baseDelayMs: 5000, maxAgentDelayMs: 60000 }`: waits of 5, 10, 20, 40, 60, 60 s, 195 s in total. That fits inside the default 600 s agent timeout with time left for the work itself. `SdkRunnerOptions` gains an optional `retry` override so tests can use millisecond delays.

### D2. Transient classification on the outcome

`AgentOutcome` gains `transient?: true`, set only when the agent failed because its last assistant message is an error that `isRetryableAssistantError` accepts, meaning pi's own retries were exhausted. It is not set for timeouts, cancellations, missing submissions, or exceptions. Using pi's classifier keeps one definition of "transient" and follows pi's updates, including its exclusion of quota and billing errors, which retrying cannot fix.

### D3. Hunt re-run after the batch

After all hunt assignments finish, `huntStage` re-runs each assignment whose outcome is `transient`, once, through `mapBounded` with the same concurrency, using a fresh collector and the label `hunt:<assignment> (re-run)`.

- Re-run succeeds: its hypotheses replace that assignment's partial hypotheses; no failure is recorded; `errors` gets "hunt:<assignment> was re-run after a transient error (<first error>)".
- Re-run fails: both attempts' hypotheses are kept (same-type merging removes exact repeats) and the re-run's failure is recorded as today, so the run is incomplete.
- Both outcomes are appended to the run log's `agents`.
- Progress: the hunt total grows by the number of re-runs, for example `hunt 6/7`.

Running re-runs after the batch rather than immediately lowers concurrent load on the provider, which is the usual cause of the error.

## Risks / Trade-offs

- **Longer runs under sustained throttling:** a hunter can take about 3 minutes of waits, plus as much again on re-run. → Bounded by `agentTimeoutSeconds` per attempt; at most one re-run per assignment.
- **Replacing partial hypotheses** discards submissions from the failed attempt even if the re-run missed one of them. → Accepted: the re-run is a complete attempt, and keeping both would produce near-duplicates with different wording.
